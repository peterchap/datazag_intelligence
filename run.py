"""
Entry point. Run against any Datazag DNS JSON file:

    python run.py --dns_file excis.json
    python run.py --dns_file atlassian.json --audience insurer
    python run.py --dns_file adaptavist.json --partner "Atlassian Platinum Partner" \
                                              --threat "Atlassian ransom demand April 2026"

Outputs JSON + Markdown + HTML for each audience to ./output/<domain>/
"""

import argparse
import asyncio
import json
import os
import re
from datetime import datetime,timezone
from pathlib import Path
from dotenv import load_dotenv

from adapter import DatazagCanonicalAdapter
from dnsproject.scripts.dns_generator import compile_pure_dns_report
from enrichment import enrich_http_and_shodan
from findings import passive_security_findings_v2
from fingerprints import TXT_FINGERPRINTS, ADDITIONAL_TXT_FINGERPRINTS
from scorer import DatazagCompositeScorer, NormalisedAnnotation, NormalisedDomainScore
from narrative import enrich_with_narrative
from renderers import render_all
from branding import BrandConfig

load_dotenv()

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "./output"))


# ---------------------------------------------------------------------------
# Ducklake Infrastructure Intelligence Extractor
# ---------------------------------------------------------------------------

def _fetch_infrastructure_intelligence(domain: str) -> dict:
    """
    Connects to the DuckLake Medallion architecture (via DuckDB) and extracts 
    the mathematically modeled risk vectors like Fast Flux, Dangling CNAMEs, and MOAS.
    Supports R2 remote lakes or local fallbacks.
    """
    import duckdb

    # Identify targets
    local_path = "C:/root/asn_data_v3/ducklake/gold/gold_risk_domain_*.parquet" if os.name == 'nt' else "/root/asn_data_v3/ducklake/gold/gold_risk_domain_*.parquet"
    target_path = os.environ.get("DUCKLAKE_GOLD_PATH", local_path)
    
    db = duckdb.connect()
    
    try:
        # Check for remote R2 HTTPFS setup
        if target_path.startswith("r2://") or target_path.startswith("s3://"):
            access_key = os.environ.get('R2_ACCESS_KEY', '')
            secret_key = os.environ.get('R2_SECRET_KEY', '')
            account_id = os.environ.get('R2_ACCOUNT_ID', '')
            if access_key and secret_key and account_id:
                db.execute("INSTALL httpfs; LOAD httpfs;")
                db.execute(f"""
                    CREATE OR REPLACE SECRET r2_creds (
                        TYPE r2,
                        KEY_ID '{access_key}',
                        SECRET '{secret_key}',
                        ACCOUNT_ID '{account_id}'
                    );
                """)
            else:
                return {} # Remote path but missing credentials, fail gracefully
                
        # Fast query across Gold Risk Tables
        query = f"""
            SELECT domain_risk_score, domain_risk_context 
            FROM read_parquet('{target_path}') 
            WHERE domain = '{domain}'
            LIMIT 1
        """
        df = db.execute(query).df()
        if not df.empty:
            raw_result = df.to_dict(orient="records")[0]
            # Context is a JSON string containing the reason codes array. 
            # Safely deserialise it so it can be dumped natively into the JSON payload.
            try:
                if raw_result.get("domain_risk_context"):
                    if isinstance(raw_result["domain_risk_context"], str):
                        raw_result["domain_risk_context"] = json.loads(raw_result["domain_risk_context"])
            except Exception:
                pass
            return raw_result
        return {}
    except Exception as e:
        # Silently degrade if the Gold table hasn't caught up to this domain yet
        return {}


# ---------------------------------------------------------------------------
# Certstream Dynamic Intelligence Array
# ---------------------------------------------------------------------------

def _fetch_certstream_ip_intel(raw_json: dict) -> dict:
    """
    Scans any resolved IP within the physical layer of the target payload,
    and dynamically checks if it is participating in an active BGP CertStream threat loop.
    """
    import re
    import duckdb
    
    # 1. Bruteforce extract all underlying IPs from the parsed Domain JSON
    raw_str = json.dumps(raw_json)
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_str)))
    if not ips:
        return {}
        
    certstream_path = "C:/root/asn_data_v3/cache/certstream/certstream.parquet" if os.name == 'nt' else "/root/asn_data_v3/cache/certstream/certstream.parquet"
    if not os.path.exists(certstream_path):
        return {}
        
    db = duckdb.connect()
    try:
        # 2. Vectorized Ducklake Lookup matching any extracted local IP to the global Threat Parquet
        ip_list_str = "['" + "', '".join(ips) + "']"
        query = f"""
            SELECT 
                SUM(certstream_hits) as total_threat_hits,
                SUM(a_certstream_hits) as a_hits,
                SUM(ns_certstream_hits) as ns_hits,
                SUM(mx_certstream_hits) as mx_hits
            FROM read_parquet('{certstream_path}')
            WHERE ip IN (SELECT * FROM UNNEST({ip_list_str}))
        """
        df = db.execute(query).df()
        if not df.empty and df['total_threat_hits'].iloc[0] is not None:
            hits = int(df['total_threat_hits'].iloc[0])
            if hits > 0:
                return {
                    "certstream_anomalies": hits,
                    "certstream_a_risk": int(df['a_hits'].iloc[0] or 0),
                    "certstream_ns_risk": int(df['ns_hits'].iloc[0] or 0),
                    "certstream_mx_risk": int(df['mx_hits'].iloc[0] or 0)
                }
    except Exception:
        pass
    return {}

# ---------------------------------------------------------------------------
# TXT intelligence extractor
# ---------------------------------------------------------------------------

def _extract_txt_intelligence(record) -> dict:
    """
    Extracts SaaS stack, identity providers, and anomalies
    from TXT records using the fingerprint patterns.
    """
    all_patterns = TXT_FINGERPRINTS + ADDITIONAL_TXT_FINGERPRINTS

    saas, identity, payment, ai_infra, security, email_mktg = [], [], [], [], [], []
    anomalies  = []
    unrecognised = []
    seen = set()

    category_map = {
        "saas":     saas,
        "identity": identity,
        "payment":  payment,
        "ai_infra": ai_infra,
        "security": security,
        "email":    email_mktg,
    }

    ANOMALY_PATTERNS = [
        r"[^a-zA-Z0-9=:_\-. /+@]",
        r"(?:password|passwd|secret|token|key|api_key|credential)",
    ]

    for txt in record.txt_records:
        matched = False
        for pattern, service, category in all_patterns:
            if re.search(pattern, txt, re.IGNORECASE):
                if service not in seen:
                    seen.add(service)
                    bucket = category_map.get(category, saas)
                    bucket.append(service)
                matched = True
                break

        if not matched:
            skip_prefixes = (
                "v=spf1", "v=dmarc1", "v=mcpv1",
                "google-site-verification", "ms=",
                "apple-domain-verification", "_",
            )
            if (not any(txt.lower().startswith(p) for p in skip_prefixes)
                    and len(txt) > 8):
                unrecognised.append(txt[:80])

        for pattern in ANOMALY_PATTERNS:
            skip = ("v=spf1","v=dmarc1","google-site-verification","ms=","apple-domain")
            if any(txt.lower().startswith(s) for s in skip):
                break
            if re.search(pattern, txt, re.IGNORECASE):
                anomalies.append(txt[:80])
                break

    stripe_count   = sum(1 for t in record.txt_records if t.startswith("stripe-verification="))
    docusign_count = sum(1 for t in record.txt_records if t.startswith("docusign="))

    return {
        "saas_platforms":     saas,
        "identity_providers": identity,
        "payment_processors": payment,
        "ai_infrastructure":  ai_infra,
        "security_tooling":   security,
        "email_marketing":    email_mktg,
        "all_identified":     list(seen),
        "total_identified":   len(seen),
        "anomalous_records":  anomalies,
        "unrecognised":       unrecognised,
        "stripe_count":       stripe_count,
        "docusign_count":     docusign_count,
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

async def run(
    dns_file: str = None,       # existing — load from JSON
    domain: str = None,         # new — live DNS fetch
    audience: str = "insurer",
    partner_context: str = None,
    threat_context: str = None,
    skip_narrative: bool = False,
    output_dir: Path = None,
    brand_profile: str = None,
) -> dict:
    # Validate — must have one or the other
    if not dns_file and not domain:
        raise ValueError("Provide either --dns_file or --domain")
    if dns_file and not domain:
        # Will be set from raw after load — existing behaviour
        pass
    # Load brand config early
    brand = BrandConfig.load(brand_profile)
    print(f"  Brand: {brand.brand_name}")

    # 1. Load raw record
    if dns_file:
        with open(dns_file) as f:
            raw = json.load(f)
        domain = raw.get("domain", "unknown")
    else:
        # Live DNS fetch — calls the full pipeline directly
        print(f"\n  Running live DNS fetch for {domain}...")
        raw = await compile_pure_dns_report(domain)
    print(f"\n  Analysing {domain}...")

    # 2. Parse canonical record
    adapter = DatazagCanonicalAdapter(raw)
    record  = adapter.parse()
    print(f"  Parsed — {len(record.txt_records)} TXT records, "
          f"IPv6: {record.is_dual_stack}, "
          f"MX: {record.annotation.mx_provider_name or 'none'}")

    # 3. Generate passive findings
    findings = passive_security_findings_v2(record)
    
    # 3.5 Dynamic Certstream Threat Hit Injection!
    # Evaluates physical infrastructure against Ducklake Gold BGP tables
    certstream_intel = _fetch_certstream_ip_intel(raw)
    if certstream_intel.get("certstream_anomalies"):
        findings.append({
            "severity": "high",
            "category": "threat_intelligence",
            "label": "CERTSTREAM_INFRA_HIT",
            "description": f"Domain perfectly overlays infrastructure actively serving {certstream_intel['certstream_anomalies']} distinct malicious certificates inside the Datazag Global BGP Feed."
        })
        
    critical = [f for f in findings if f["severity"] == "critical"]
    high     = [f for f in findings if f["severity"] == "high"]
    print(f"  Findings — {len(critical)} critical, {len(high)} high, "
          f"{len(findings)} total")

    http_section, shodan_section = await enrich_http_and_shodan(
    domain=domain,
    record=record,
    raw=raw,
    shodan_api_key=os.environ.get("SHODAN_API_KEY"),
    )
    
    # ── Merge findings ──────────────────────────────────────────────────────

    _NORMALISE_SEV = {"elevated": "high", "low": "medium"}

    findings.extend(http_section.get("findings", []))
    findings.extend(shodan_section.get("findings", []))
    
    # Normalise to canonical vocabulary before anything else sees the list
    for f in findings:
        f["severity"] = _NORMALISE_SEV.get(f.get("severity", "info"), f.get("severity", "info"))

    # 4. Compute composite score
    scorer       = DatazagCompositeScorer()
    annotation   = NormalisedAnnotation.from_raw(raw)
    domain_score = NormalisedDomainScore(
        domain=domain,
        ip=record.a_records[0] if record.a_records else "",
        is_phishing=record.is_phishing,
        is_malware=record.is_malware,
        is_parked=int(raw.get("parking_points", 0)) > 3,
        is_disposable=False,
        dmarc=record.email_auth.dmarc_raw,
        spf=record.email_auth.spf_raw,
        mx_status_flag="ACTIVE" if record.mx_records else "NONE",
        final_ip_risk_score=float(raw.get("risk_score", 0)) / 100,
        score_pct=int(raw.get("risk_score", 0)),
        last_scanned=record.scanned_at,
        is_flagged=record.is_phishing or record.is_malware,
        threat_categories=(
            (["phishing"] if record.is_phishing else []) +
            (["malware"]  if record.is_malware  else [])
        ),
    )

    composite = scorer.compute(
        domain=domain,
        dns_posture_score=record.risk.score,
        email_spoof_score={
            "critical": 100,
            "high":      70,
            "medium":    40,
            "none":       5,
        }.get(record.email_auth.spoofing_severity, 20),
        ip_score=None,
        domain_score=domain_score,
        annotation=annotation,
    )
    print(f"  Score — {composite.composite_score}/100 "
          f"({composite.risk_band}) | confidence: {composite.confidence}")
    print(f"  Driver — {composite.primary_driver}")

    # Fetch deep infrastructure intelligence locally or from R2!
    infra_intel = _fetch_infrastructure_intelligence(domain)
    if infra_intel:
        print(f"  [+] Attached Gold Infrastructure Risk (Score: {infra_intel.get('domain_risk_score', 0):.2f})")

    # 5. Assemble the FULL output dict first
    #    Narrative needs the complete data — do this before the API call
    output = {
        "domain":       domain,
        "subdomains":    raw.get("subdomains", []),
        "cert_analysis": raw.get("cert_analysis", {}),
        "rdap":          raw.get("rdap", {}),
        "scanned_at":   record.scanned_at,
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "audience":     audience,

        "composite_score": {
            "score":          composite.composite_score,
            "risk_band":      composite.risk_band,
            "confidence":     composite.confidence,
            "primary_driver": composite.primary_driver,
            "components":     composite.score_components,
            "nudges": {
                "mx_provider":    record.annotation.mx_provider_name,
                "mx_trust_nudge": composite.mx_trust_nudge_applied,
                "mx_risk_bias":   record.annotation.mx_risk_bias,
                "provider_trust": composite.provider_trust_nudge_applied,
                "tld_risk":       record.annotation.tld_risk_level,
                "tld_adjustment": composite.tld_risk_adjustment,
                "asn_risk_level": record.annotation.asn_risk_level,
            },
        },

        "risk_score_engine": {
            "score":          record.risk.score,
            "bucket":         record.risk.bucket,
            "profile":        record.risk.profile,
            "config_version": record.risk.config_version,
            "rules": [
                {"rule": r.rule, "points": r.points}
                for r in record.risk.reasons
            ],
            "trust_rules": [
                {"rule": r.rule, "points": r.points}
                for r in record.risk.negative_contributions
            ],
            "risk_rules": [
                {"rule": r.rule, "points": r.points}
                for r in record.risk.positive_contributions
            ],
        },

        "dns_records": {
            "a":      record.a_records,
            "aaaa":   record.aaaa_records,
            "mx":     record.mx_records,
            "ns":     record.ns_records,
            "txt":    record.txt_records,
            "caa":    record.caa_records,
            "mail_a": record.mail_a_records,
            "www_a":  record.www_a_records,
        },

        "email_auth": {
            "spf":                    record.email_auth.spf_all_mechanism,
            "spf_raw":                record.email_auth.spf_raw,
            "spf_includes":           record.email_auth.spf_includes,
            "spf_ip4_ranges":         record.email_auth.spf_ip4_ranges,
            "spf_strictness":         record.email_auth.spf_strictness,
            "dmarc_policy":           record.email_auth.dmarc_policy,
            "dmarc_raw":              record.email_auth.dmarc_raw,
            "dmarc_pct":              record.email_auth.dmarc_pct,
            "aspf":                   record.email_auth.dmarc_aspf,
            "adkim":                  record.email_auth.dmarc_adkim,
            "dmarc_rua":              record.email_auth.dmarc_rua,
            "dmarc_ruf":              record.email_auth.dmarc_ruf,
            "dmarc_fo":               record.email_auth.dmarc_fo,
            "mta_sts":                record.email_auth.mta_sts_status,
            "mta_sts_mode":           record.email_auth.mta_sts_mode,
            "tls_rpt":                record.email_auth.tls_rpt_status,
            "tls_rpt_rua":            record.email_auth.tls_rpt_rua,
            "bimi":                   record.email_auth.bimi_status,
            "bimi_raw":               record.email_auth.bimi_raw,
            "dnssec":                 record.email_auth.dnssec_enabled,
            "is_spoofable":           record.email_auth.is_spoofable,
            "spoofing_severity":      record.email_auth.spoofing_severity,
            "is_fully_authenticated": record.email_auth.is_fully_authenticated,
            "missing_layers":         record.email_auth.missing_layers,
        },

        "technographics": {
            "mx_provider_name":     record.annotation.mx_provider_name,
            "mx_mbp_category":      record.annotation.mx_mbp_category,
            "mx_risk_bias":         record.annotation.mx_risk_bias,
            "mx_trust_nudge":       record.annotation.mx_trust_nudge,
            "ns_provider_name":     record.annotation.ns_provider_name,
            "ns_provider_category": record.annotation.ns_provider_category,
            "ns_brand_hit":         record.annotation.ns_brand_hit,
            "isp_name":             record.annotation.isp_name,
            "isp_country":          record.annotation.isp_country,
            "asn":                  record.annotation.asn,
            "asn_risk_level":       record.annotation.asn_risk_level,
            "tld_country":          record.annotation.tld_country,
            "tld_risk_level":       record.annotation.tld_risk_level,
            "is_cdn_ugc":           record.annotation.is_cdn_ugc,
            "is_hosting_cdn":       record.annotation.is_hosting_cdn,
            "net_trust_score":      record.annotation.net_trust_score,
        },

        "infrastructure": {
            "cdn":         record.annotation.isp_name,
            "isp":         record.annotation.isp_name,
            "asn":         record.annotation.asn,
            "dual_stack":  record.is_dual_stack,
            "ip_int":      record.ip_int,
            "ns_primary":  record.ns_primary,
            "mx_provider": record.annotation.mx_provider_name,
            "mx_category": record.annotation.mx_mbp_category,
            "ns_provider": record.annotation.ns_provider_name,
        },

        "certificates": {
            "https_ok":           record.https_cert.ok if record.https_cert else None,
            "https_days_left":    record.https_cert.days_remaining if record.https_cert else None,
            "https_issuer":       record.https_cert.issuer if record.https_cert else None,
            "https_issuer_org":   record.https_cert.issuer_org if record.https_cert else None,
            "https_san_count":    record.https_cert.san_count if record.https_cert else None,
            "https_label":        record.https_cert.label if record.https_cert else None,
            "https_lets_encrypt": record.https_cert.is_lets_encrypt if record.https_cert else None,
            "https_expiring":     record.https_cert.is_expiring_soon if record.https_cert else None,
            "smtp_ok":            record.smtp.cert.ok if record.smtp.cert else None,
            "smtp_days_left":     record.smtp.cert.days_remaining if record.smtp.cert else None,
            "smtp_issuer":        record.smtp.cert.issuer if record.smtp.cert else None,
            "smtp_issuer_org":    record.smtp.cert.issuer_org if record.smtp.cert else None,
            "smtp_banner":        record.smtp.banner_raw,
            "smtp_banner_host":   record.smtp.banner_host,
            "smtp_banner_detail": record.smtp.banner_detail,
            "provider_live":      record.smtp.provider_confirmed,
        },

        "labels": {
            "dmarc_policy":          record.label_dmarc_policy,
            "spf_strictness":        record.label_spf_strictness,
            "ttl_bucket":            record.label_ttl_bucket,
            "ssl_issuer":            record.label_ssl_issuer,
            "active_infrastructure": record.label_active_infrastructure,
        },

        "threat_flags": {
            "is_phishing":      record.is_phishing,
            "is_malware":       record.is_malware,
            "is_new_domain":    record.is_new_domain,
            "has_security_txt": record.has_security_txt,
            "has_caa":          record.has_caa,
        },

        "change_signals": {
            "ns_changed":      record.changes.ns_changed,
            "ip_changed":      record.changes.ip_changed,
            "country_changed": record.changes.country_changed,
            "ttl_drop_big":    record.changes.ttl_drop_big,
            "is_dynamic_dns":  record.changes.is_dynamic_dns,
            "mx_misconfigured": record.changes.mx_misconfigured_provider,
            "parking_points":  record.changes.parking_points,
            "subdomain_points": record.changes.subdomain_points,
            "any_change":      record.changes.any_change_signal,
            "any_threat":      record.changes.any_threat_signal,
        },

        "infrastructure_intelligence": infra_intel,
        "http_enrichment":   http_section,
        "shodan_enrichment": shodan_section,
        "txt_intelligence": _extract_txt_intelligence(record),
        "findings":  findings,
        "narrative": {},        # Populated below after API call
    }

    # 6. Narrative enrichment — called with the FULL output dict
    if not skip_narrative and os.environ.get("ANTHROPIC_API_KEY"):
        print(f"  Generating narrative ({audience} audience)...")
        narrative = await enrich_with_narrative(
            domain=domain,
            score=composite.composite_score,
            risk_band=composite.risk_band,
            findings=findings,
            output=output,          # full dict — all fields now populated
            partner_context=partner_context,
            threat_context=threat_context,
            audience=audience,
        )
        output["narrative"] = narrative
        print(f"  Key finding: {narrative.get('key_finding','')[:80]}...")
    else:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("  Skipping narrative — ANTHROPIC_API_KEY not set")

    # 7. Render and write output files
    all_reports = render_all(output, brand=brand)

    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    for aud, formats in all_reports.items():
        for fmt, content in formats.items():
            ext = {"json": "json", "markdown": "md", "html": "html"}[fmt]
            path = out_dir / f"{aud}.{ext}"
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

    print(f"\n  Output written to {out_dir}/")
    print("  12 files — 4 audiences × 3 formats (JSON, Markdown, HTML)")

    return output


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag DNS Intelligence Engine")

# Input — mutually exclusive
input_group = parser.add_mutually_exclusive_group(required=True)
input_group.add_argument("--dns_file", default=None,
                         help="Path to pre-collected Datazag DNS JSON file")
input_group.add_argument("--domain",   default=None,
                         help="Domain to scan live e.g. adaptavist.com")

parser.add_argument("--audience",     default="insurer",
                    choices=["insurer","consultant","it","sales"])
parser.add_argument("--partner",      default=None)
parser.add_argument("--threat",       default=None)
parser.add_argument("--output-dir",   default=None)
parser.add_argument("--no-narrative", action="store_true")
parser.add_argument("--brand",        default=None)

args = parser.parse_args()

asyncio.run(run(
    dns_file=args.dns_file,
    domain=args.domain,
    audience=args.audience,
    partner_context=args.partner,
    threat_context=args.threat,
    skip_narrative=args.no_narrative,
    output_dir=Path(args.output_dir) if args.output_dir else None,
    brand_profile=args.brand,
))