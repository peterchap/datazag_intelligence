import httpx
import asyncio
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

async def rdap_lookup_async(domain: str) -> dict:
    """
    Async version of rdap_lookup returning structured data for pipeline use.
    Replaces the synchronous WHOIS domain age call in compile_pure_dns_report.
    Returns a dict with all fields needed to populate the report.
    """
    domain = domain.strip().lower()
    url     = f"https://rdap.org/domain/{domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Datazag-InfraScout/1.0)"
    }

    result = {
        # Domain lifecycle
        "registered":        None,
        "updated":           None,
        "expires":           None,
        "domain_age_days":   -1,
        "days_to_expiry":    -1,

        # Registrar
        "registrar_name":    None,
        "registrar_address": None,
        "registrar_score":   0,
        "registrar_label":   "Unknown",

        # Nameservers (from RDAP — cross-check against DNS)
        "nameservers":       [],
        "ns_score":          0,
        "ns_reasons":        [],

        # Status flags
        "status":            [],
        "status_score":      0,
        "status_reasons":    [],
        "lock_count":        0,

        # Security
        "dnssec_enabled":    False,

        # Abuse
        "abuse_email":       None,
        "abuse_contact_present": False,

        # Transfer history
        "transfer_events":   [],
        "recent_transfer":   False,

        # Composite risk from RDAP signals
        "rdap_risk_score":   0,
        "rdap_risk_reasons": [],

        "rdap_available": False,
        "rdap_error":     None,
    }

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, headers=headers, timeout=10.0
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

        # ── Dates ──────────────────────────────────────────────────────────
        events    = data.get("events", [])
        raw_reg   = next((e["eventDate"] for e in events
                          if e["eventAction"] == "registration"), None)
        raw_mod   = next((e["eventDate"] for e in events
                          if e["eventAction"] == "last changed"), None)
        raw_exp   = next((e["eventDate"] for e in events
                          if e["eventAction"] == "expiration"), None)

        result["registered"] = format_date(raw_reg)
        result["updated"]    = format_date(raw_mod)
        result["expires"]    = format_date(raw_exp)

        if raw_reg and raw_reg != "N/A":
            try:
                reg_date = datetime.strptime(raw_reg[:10], "%Y-%m-%d")
                result["domain_age_days"] = max(0, (datetime.now() - reg_date).days)
            except Exception:
                pass

        if raw_exp and raw_exp != "N/A":
            try:
                exp_date = datetime.strptime(raw_exp[:10], "%Y-%m-%d")
                result["days_to_expiry"] = (exp_date - datetime.now()).days
            except Exception:
                pass

        # ── Registrar ──────────────────────────────────────────────────────
        entities   = data.get("entities", [])
        reg_info   = find_registrar_info(entities) or {"name": None, "address": None}
        reg_score, reg_label = score_registrar(reg_info.get("name"))

        result["registrar_name"]    = reg_info.get("name")
        result["registrar_address"] = reg_info.get("address")
        result["registrar_score"]   = reg_score
        result["registrar_label"]   = reg_label

        # ── Nameservers ────────────────────────────────────────────────────
        ns_list = [
            ns.get("ldhName", "").lower()
            for ns in data.get("nameservers", [])
        ]
        ns_score, ns_reasons = score_nameservers(ns_list)
        result["nameservers"] = ns_list
        result["ns_score"]    = ns_score
        result["ns_reasons"]  = ns_reasons

        # ── Status flags ───────────────────────────────────────────────────
        status_list   = data.get("status", [])
        status_score, status_reasons = status_risk(status_list)
        lock_count = sum(
            1 for s in status_list
            if s.lower().replace(" ", "").replace("-", "") in LOW_RISK_STATUS
        )

        result["status"]         = status_list
        result["status_score"]   = status_score
        result["status_reasons"] = status_reasons
        result["lock_count"]     = lock_count

        # ── DNSSEC ─────────────────────────────────────────────────────────
        secure_dns = data.get("secureDNS", {})
        result["dnssec_enabled"] = bool(secure_dns.get("delegationSigned"))

        # ── Abuse contact ──────────────────────────────────────────────────
        abuse_email = find_abuse_contact(entities)
        result["abuse_email"]          = abuse_email
        result["abuse_contact_present"] = abuse_email is not None

        # ── Transfer history ───────────────────────────────────────────────
        transfers = extract_transfer_events(events)
        result["transfer_events"] = transfers
        # Recent transfer = any transfer in last 180 days
        if transfers:
            try:
                latest = datetime.strptime(
                    max(t for t in transfers if t != "N/A"),
                    "%Y-%m-%d"
                )
                result["recent_transfer"] = (datetime.now() - latest).days < 180
            except Exception:
                pass

        # ── Composite RDAP risk score ──────────────────────────────────────
        rdap_score   = reg_score + ns_score + status_score
        rdap_reasons = (
            ([f"Registrar: {reg_label}"] if reg_score > 0 else []) +
            ns_reasons +
            status_reasons
        )

        if result["domain_age_days"] != -1:
            if result["domain_age_days"] < 30:
                rdap_score   += 3
                rdap_reasons.append("Ultra-new domain (< 30 days)")
            elif result["domain_age_days"] < 90:
                rdap_score   += 1
                rdap_reasons.append("New domain (< 90 days)")

        if result["days_to_expiry"] != -1 and 0 < result["days_to_expiry"] < 30:
            rdap_score   += 2
            rdap_reasons.append(f"Domain expires in {result['days_to_expiry']} days")

        if result["recent_transfer"]:
            rdap_score   += 1
            rdap_reasons.append("Registrar transfer within last 180 days")

        if not result["dnssec_enabled"]:
            rdap_score   += 1
            rdap_reasons.append("DNSSEC not enabled")

        result["rdap_risk_score"]   = rdap_score
        result["rdap_risk_reasons"] = rdap_reasons
        result["rdap_available"]    = True

    except httpx.HTTPStatusError as e:
        result["rdap_error"] = f"HTTP {e.response.status_code}"
    except Exception as e:
        result["rdap_error"] = str(e)[:200]

    return result

if __name__ == "__main__":
    target = "excis.com"
    asyncio.run(rdap_lookup_async(target))
