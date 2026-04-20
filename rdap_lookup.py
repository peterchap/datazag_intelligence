import httpx
from datetime import datetime

REGISTRAR_RISK = {
    # High abuse concentration relative to market share
    "namecheap":    {"score": 2, "label": "Elevated — high abuse rate"},
    "njalla":       {"score": 3, "label": "High — privacy-first, abuse-tolerant"},
    "reg.ru":       {"score": 2, "label": "Elevated — Russian registrar"},
    "internet.bs":  {"score": 2, "label": "Elevated — offshore registrar"},
    "1api":         {"score": 1, "label": "Moderate"},
    # Established, lower abuse rates
    "godaddy":      {"score": 0, "label": "Low — established registrar"},
    "cloudflare":   {"score": 0, "label": "Low — established registrar"},
    "markmonitor":  {"score": 0, "label": "Low — enterprise/brand protection"},
    "cscglobal":    {"score": 0, "label": "Low — enterprise"},
    "verisign":     {"score": 0, "label": "Low — established registrar"},
}

BULLETPROOF_NS_PATTERNS = [
    "frantech", "njalla", "1984hosting", "epik",
    "hostkey", "serverius", "combahton",
]

HIGH_RISK_STATUS = {
    "addperiod":       (2, "Registered in the last 5 days"),
    "serverhold":      (2, "Domain suspended by registry"),
    "clienthold":      (2, "Domain suspended by registrar"),
    "redemptionperiod":(1, "Domain expiring — not renewed"),
    "pendingdelete":   (3, "Domain deleting — available soon"),
    "pendingtransfer": (1, "Registrar transfer in progress"),
}

LOW_RISK_STATUS = {
    # These indicate legitimate protective registrations
    "servertransferprohibited",
    "clienttransferprohibited",
    "serverdeleteprohibited",
    "clientdeleteprohibited",
    "serverupdateprohibited",
    "clientupdateprohibited",
    "serverrenewprohibited",
    "clientrenewprohibited",
}


def get_vcard_data(vcard_array):
    """Extracts Name and Address from the jCard format."""
    results = {"name": None, "address": None}
    if not vcard_array or len(vcard_array) < 2:
        return results

    # vcard_array[1] contains the list of property arrays
    for prop in vcard_array[1]:
        # prop format: ["field", {params}, "type", "value"]
        field_type = prop[0]
        
        if field_type == 'fn':
            results["name"] = prop[3]
        
        if field_type == 'adr':
            # adr value is a list: [pob, ext, street, city, region, code, country]
            # We filter out empty strings and join them
            addr_parts = [part for part in prop[3] if part]
            results["address"] = ", ".join(addr_parts)
            
    return results

def find_registrar_info(entities):
    """Recursively searches for registrar name and location."""
    if not entities:
        return None
    
    for entity in entities:
        if 'registrar' in entity.get('roles', []):
            info = get_vcard_data(entity.get('vcardArray'))
            # Backup: if name is missing, use the handle
            if not info["name"]:
                info["name"] = entity.get('handle')
            return info
        
        # Check nested entities
        nested = find_registrar_info(entity.get('entities', []))
        if nested:
            return nested
    return None
    
def find_abuse_contact(entities):
    """Extract abuse email from entities with role 'abuse'."""
    if not entities:
        return None
    for entity in entities:
        if 'abuse' in entity.get('roles', []):
            vcard = entity.get('vcardArray', [])
            if vcard and len(vcard) > 1:
                for prop in vcard[1]:
                    if prop[0] == 'email':
                        return prop[3]
        nested = find_abuse_contact(entity.get('entities', []))
        if nested:
            return nested
    return None

def extract_transfer_events(events):
    """Find any registrar transfer events in the event history."""
    transfers = []
    for event in events:
        if event.get('eventAction') == 'transfer':
            transfers.append(event.get('eventDate', ''))
    return [format_date(t) for t in transfers]


def score_registrar(registrar_name: str) -> tuple[int, str]:
    """Score the registrar against known risk tiers."""
    if not registrar_name:
        return 1, "Unknown registrar"
    lower = registrar_name.lower()
    for key, data in REGISTRAR_RISK.items():
        if key in lower:
            return data["score"], data["label"]
    return 0, "Unclassified registrar"


def score_nameservers(ns_list: list[str]) -> tuple[int, list[str]]:
    """
    Score nameserver configuration for risk signals.
    Returns (score, list of reasons).
    """
    score = 0
    reasons = []

    if len(ns_list) < 2:
        score += 1
        reasons.append("Single nameserver — no redundancy")

    combined = " ".join(ns_list).lower()

    for pattern in BULLETPROOF_NS_PATTERNS:
        if pattern in combined:
            score += 3
            reasons.append(f"Nameserver on known bulletproof provider: {pattern}")
            break

    # Check if all NS are in same /24 — requires IP resolution
    # (deferred to the subdomain NS resolution pass)

    return score, reasons


def status_risk(status_list: list[str]) -> tuple[int, list[str]]:
    """Score domain status flags."""
    score = 0
    reasons = []
    normalised = [s.lower().replace(" ", "").replace("-", "") for s in status_list]

    for s in normalised:
        if s in HIGH_RISK_STATUS:
            pts, reason = HIGH_RISK_STATUS[s]
            score += pts
            reasons.append(reason)

    # All four clientX locks present = well-managed domain — bonus
    lock_count = sum(1 for s in normalised if s in LOW_RISK_STATUS)
    if lock_count >= 4:
        score = max(0, score - 1)  # Slight negative pressure on score

    return score, reasons

def format_date(date_str):
    """Simplifies RDAP timestamps to YYYY-MM-DD."""
    if not date_str or date_str == "N/A":
        return "N/A"
    # RDAP dates are usually ISO 8601 (2023-01-01T12:00:00Z)
    return date_str.split('T')[0]

def calculate_risk_score(data, reg_date_str):
    score = 0
    reasons = []

    # 1. New Domain Risk (The "Age" Factor)
    if reg_date_str and reg_date_str != "N/A":
        try:
            # Parse YYYY-MM-DD
            reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
            days_old = (datetime.now() - reg_date).days
            
            if days_old < 30:
                score += 3
                reasons.append("Ultra-new domain (<30 days)")
            elif days_old < 90:
                score += 1
                reasons.append("Relatively new domain (<90 days)")
        except:
            pass

    # 2. Status Anomalies
    status = [s.lower() for s in data.get('status', [])]
    if not status:
        score += 1
        reasons.append("No status flags found")
    if 'serverhold' in status or 'clienthold' in status:
        score += 2
        reasons.append("Domain is suspended (Hold status)")

    # 3. Name Server Analysis
    ns_list = data.get('nameservers', [])
    if len(ns_list) < 2:
        score += 1
        reasons.append("Low redundancy (only 1 nameserver)")

    # 4. Privacy Redaction
    # If the registrant entity exists but the vcard is empty or contains 'REDACTED'
    entities = data.get('entities', [])
    registrant = next((e for e in entities if 'registrant' in e.get('roles', [])), None)
    if registrant and "redacted" in str(registrant).lower():
        score += 1
        reasons.append("Registrant info redacted (Privacy proxy)")

    return score, reasons

def get_governance_metrics(data):
    events = data.get('events', [])
    
    # 1. Expiration Risk
    exp_date_str = next((e['eventDate'] for e in events if e['eventAction'] == 'expiration'), None)
    
    # 2. DNSSEC Status (Critical for IT Risk)
    # Checks if the domain is signed, preventing DNS hijacking
    dnssec = "Disabled"
    if 'secureDNS' in data:
        if data['secureDNS'].get('delegationSigned') is True:
            dnssec = "Enabled"

    return {
        "expiration": exp_date_str[:10] if exp_date_str else "N/A",
        "dnssec": dnssec
    }

def rdap_lookup(domain):
    # 1. Clean the input to avoid malformed URL errors
    domain = domain.strip().lower()
    url = f"https://rdap.org/domain/{domain}"
    
    # 2. Set a User-Agent to avoid being blocked as a basic bot
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        # 3. Explicitly follow redirects (essential for rdap.org)
        with httpx.Client(follow_redirects=True, headers=headers) as client:
            response = client.get(url, timeout=10.0)
            
            if response.status_code == 400:
                print(f"Error 400: The server rejected the request for '{domain}'.")
                print("Check if the domain is typed correctly (e.g., 'google.com' not '://google.com')")
                return
                
            response.raise_for_status()

            data = response.json()
            # Extract Dates using next() for efficiency
            events = data.get('events', [])
            raw_reg = next((e['eventDate'] for e in events if e['eventAction'] == 'registration'), "N/A")
            raw_mod = next((e['eventDate'] for e in events if e['eventAction'] == 'last changed'), "N/A")
            
            # Registrar
            reg_info = find_registrar_info(data.get('entities', [])) or {"name": "N/A", "address": "N/A"}

        # Extract Status
        status = data.get('status', []) # returns a list like ['client transfer prohibited']

        # Extract Name Servers
        ns_list = [ns.get('ldhName') for ns in data.get('nameservers', [])]

        # Extract Remarks (for abuse reporting info)
        remarks = [r.get('description', [])[0] for r in data.get('remarks', []) if r.get('description')]

        # Calculate Risk
        risk_score, risk_reasons = calculate_risk_score(data, raw_reg)

        # Governance Metrics
        gov = get_governance_metrics(data)

        # Print Results
        
        print(f"--- {domain.upper()} ---")
        print(f"Created:   {format_date(raw_reg)}")
        print(f"Updated:   {format_date(raw_mod)}")
        print(f"Registrar: {reg_info['name']}")
        print(f"Location:  {reg_info['address']}")
        print(f"Status:      {', '.join(status)}")
        print(f"NameServers: {', '.join(ns_list)}")
        print(f"Abuse Info:  {remarks[0] if remarks else 'N/A'}")
        print(f"\n--- GOVERNANCE ---")
        print(f"Expiration:  {gov['expiration']}")
        print(f"DNSSEC:      {gov['dnssec']}")  
        print(f"\n--- THREAT INTEL REPORT ---")
        print(f"Risk Score:  {risk_score}/7")
        if risk_reasons:
            print(f"Warnings:    {', '.join(risk_reasons)}")
            
        if risk_score >= 3:
            print("🚨 HIGH RISK: This domain matches common phishing/malware patterns.")
        else:
            print("✅ LOW RISK: Domain appears established.")
        
    except httpx.HTTPStatusError as e:
        print(f"HTTP Error {e.response.status_code}: {e.response.text[:100]}")
    except Exception as e:
        print(f"Connection Error: {e}")

if __name__ == "__main__":
    target = "excis.com"
    rdap_lookup(target)
