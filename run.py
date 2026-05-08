"""
run.py — Datazag DNS Intelligence Engine
-----------------------------------------
Usage:
    python run.py --dns_file excis.json
    python run.py --domain normcyber.com --audience insurer
    python run.py --dns_file adaptavist.json --partner "Atlassian Platinum Partner" \
                                              --threat "Subject of ransom demand"

Outputs JSON + Markdown + HTML + PDF for each of 4 audiences to ./output/<domain>/
"""

import argparse
import asyncio
import duckdb
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from adapter import DatazagCanonicalAdapter
from dnsproject.scripts.dns_generator import compile_pure_dns_report
from enrichment import enrich_http_and_shodan
from findings import passive_security_findings_v2
from fingerprints import TXT_FINGERPRINTS, ADDITIONAL_TXT_FINGERPRINTS
from dnsproject.riskscore.infrastructure.domain_intelligence_api import DomainIntelligenceAPI
from scorer import DatazagCompositeScorer, NormalisedAnnotation, NormalisedDomainScore
from narrative import enrich_with_narrative
from renderers import render_all
from cyber_risk_scores import CyberRiskScorer
from playwright.async_api import async_playwright
from branding import BrandConfig

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "./output"))


# ---------------------------------------------------------------------------
# Finding deduplication
# ---------------------------------------------------------------------------

def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Deduplicates by finding key, keeping the entry with the best evidence.
    Findings without a key (e.g. certstream injection) are preserved as-is.
    """
    seen: dict[str, dict] = {}

    def has_evidence(f: dict) -> bool:
        ev = f.get("evidence", "")
        return bool(ev) and ev not in ("n/a", "")

    for f in findings:
        key = f.get("finding", "")
        if not key:
            continue
        if key not in seen:
            seen[key] = f
        elif has_evidence(f) and not has_evidence(seen[key]):
            seen[key] = f  # replace with better-evidenced version

    keyless = [f for f in findings if not f.get("finding")]
    return list(seen.values()) + keyless


# ---------------------------------------------------------------------------
# NS delegation findings (post-resolution, uses enriched subdomain data)
# ---------------------------------------------------------------------------

def _ns_delegation_findings(subdomains: list[dict], primary_ns_provider: str | None) -> list[dict]:
    """
    Generates findings from NS delegation signals resolved in dns_generator.
    Called after passive_security_findings_v2 so findings can be merged/deduped.
    """
    findings = []
    seen_dangling = False
    seen_external: set[str] = set()

    for sub in subdomains:
        fqdn = sub.get("dns_name", "")
        if not fqdn:
            continue

        ns_risk = sub.get("ns_delegation_risk")

        if ns_risk == "dangling_ns_delegation" and not seen_dangling:
            seen_dangling = True
            findings.append({
                "finding":     "subdomain_ns_takeover",
                "severity":    "critical",
                "title":       f"NS delegation takeover risk: {fqdn}",
                "evidence":    (
                    f"Delegated to: {', '.join(sub.get('ns_records', []))} "
                    f"— nameserver does not resolve"
                ),
                "detail":      (
                    f"{fqdn} is delegated to a nameserver that no longer resolves. "
                    f"An attacker who registers that nameserver's domain gains "
                    f"complete DNS control over {fqdn} — affecting all record types "
                    f"including A, MX, and TXT. More dangerous than a CNAME takeover "
                    f"because it affects the entire subdomain zone."
                ),
                "remediation": (
                    f"Remove the NS delegation for {fqdn} immediately or "
                    f"re-register the nameserver domain. "
                    f"Audit all DNS providers for lapsed registrations."
                ),
            })

        elif (ns_risk == "high_risk_ns_provider"
              and fqdn not in seen_external):
            seen_external.add(fqdn)
            findings.append({
                "finding":     "subdomain_high_risk_ns",
                "severity":    "high",
                "title":       f"Subdomain delegated to high-risk DNS provider: {fqdn}",
                "evidence":    f"NS: {', '.join(sub.get('ns_records', []))}",
                "detail":      (
                    f"{fqdn} is delegated to a free or historically abuse-prone "
                    f"DNS provider. These providers are commonly used for malicious "
                    f"infrastructure and reduce trust for any subdomain delegated to them."
                ),
                "remediation": (
                    "Migrate the delegated zone to an enterprise DNS provider "
                    "or consolidate under the parent domain's nameservers."
                ),
            })

        elif (sub.get("is_delegated")
              and not sub.get("ns_delegation_same_provider")
              and ns_risk not in ("dangling_ns_delegation", "high_risk_ns_provider")
              and fqdn not in seen_external):
            seen_external.add(fqdn)
            findings.append({
                "finding":     "subdomain_external_ns_delegation",
                "severity":    "medium",
                "title":       f"Subdomain delegated to different DNS provider: {fqdn}",
                "evidence":    (
                    f"Parent NS provider: {primary_ns_provider or '?'}, "
                    f"Subdomain NS: {', '.join(sub.get('ns_records', []))}"
                ),
                "detail":      (
                    f"{fqdn} is delegated to a different DNS provider than the "
                    f"parent domain. May indicate a separately managed service, "
                    f"an acquisition, or shadow IT. Verify the delegation is "
                    f"intentional and the delegated zone has equivalent controls."
                ),
                "remediation": (
                    "Verify this delegation is authorised. Ensure the delegated "
                    "zone has DNSSEC, CAA records, and equivalent email auth "
                    "if it serves MX records."
                ),
            })

    return findings


# ---------------------------------------------------------------------------
# Medallion Intelligence Extraction
# ---------------------------------------------------------------------------

def _derive_findings_from_medallion(api_payload: dict, domain: str) -> list[dict]:
    """
    Pulls pre-scored domain risk signals from the Medallion intelligence payload
    and converts them to findings.
    """
    findings = []
    if not api_payload or "risk_assessment" not in api_payload:
        return findings

    risk = api_payload["risk_assessment"]

    def _f(val) -> float:
        try:
            return float(val or 0)
        except (TypeError, ValueError):
            return 0.0

    fast_flux = _f(risk.get("fast_flux_risk", 0))
    dga = _f(risk.get("dga_risk", 0))
    concentration = _f(risk.get("concentration_risk", 0))
    certstream_risk = _f(risk.get("certstream_risk", 0))
    dangling = _f(risk.get("dangling_cname_risk", 0))

    if fast_flux > 0.6:
        findings.append({
            "finding":     "fast_flux_detected",
            "severity":    "critical" if fast_flux > 0.8 else "high",
            "title":       f"Fast-flux DNS pattern detected (score: {fast_flux:.2f})",
            "evidence":    f"Datazag corpus fast-flux score: {fast_flux:.2f}/1.0",
            "detail":      "This domain exhibits fast-flux DNS patterns — rapid rotation of A records across multiple IPs. Fast-flux is a strong indicator of botnet C2 infrastructure or bulletproof hosting used to evade takedown.",
            "remediation": "Investigate whether this domain is under external DNS manipulation. Check for unauthorised NS or glue record changes at your registrar.",
            "category":    "infrastructure_intelligence",
        })

    if dga > 0.6:
        findings.append({
            "finding":     "dga_pattern_detected",
            "severity":    "high",
            "title":       f"Domain generation algorithm pattern (score: {dga:.2f})",
            "evidence":    f"DGA risk score: {dga:.2f}/1.0",
            "detail":      "The domain name exhibits characteristics associated with algorithmically generated domains — a technique used by malware families to generate C2 rendezvous points that are difficult to blocklist en masse.",
            "remediation": "Verify domain ownership and registration intent.",
            "category":    "infrastructure_intelligence",
        })

    if concentration > 0.7:
        findings.append({
            "finding":     "malicious_concentration",
            "severity":    "high",
            "title":       f"High malicious neighbour concentration (score: {concentration:.2f})",
            "evidence":    f"Concentration risk score: {concentration:.2f}/1.0",
            "detail":      "This domain's infrastructure is co-located with a high density of domains associated with malicious activity in the Datazag corpus of 320M domains. Shared infrastructure increases cross-contamination risk and signals poor hosting neighbourhood quality.",
            "remediation": "Consider migrating to dedicated infrastructure with a lower-risk hosting provider. Review co-hosted domains for malicious activity.",
            "category":    "infrastructure_intelligence",
        })

    if certstream_risk > 0.5:
        findings.append({
            "finding":     "certstream_domain_risk",
            "severity":    "high",
            "title":       f"CertStream threat activity on domain infrastructure (score: {certstream_risk:.2f})",
            "evidence":    f"CertStream risk score: {certstream_risk:.2f}/1.0",
            "detail":      "Infrastructure hosting this domain is associated with active malicious certificate issuance in the Datazag CertStream BGP feed. This indicates the IP or ASN is being used to issue certificates for phishing or malware delivery domains.",
            "remediation": "Investigate co-hosted infrastructure for malicious certificate activity. Consider migrating to dedicated infrastructure.",
            "category":    "infrastructure_intelligence",
        })

    if dangling > 0.7:
        findings.append({
            "finding":     "corpus_dangling_cname_risk",
            "severity":    "medium",
            "title":       f"Dangling CNAME risk flagged in Datazag corpus (score: {dangling:.2f})",
            "evidence":    f"Corpus dangling CNAME risk: {dangling:.2f}/1.0",
            "detail":      "The Datazag corpus has flagged elevated dangling CNAME risk for this domain based on historical DNS patterns across 320M domains. This may indicate previously unresolved CNAME targets or infrastructure instability.",
            "remediation": "Audit all CNAME records for this domain and remove any pointing to unregistered or expired targets.",
            "category":    "infrastructure_intelligence",
        })

    certstream_hits = api_payload.get("certstream", {}).get("hits", 0)
    if certstream_hits > 0:
        findings.append({
            "finding":  "certstream_infra_hit",
            "severity": "high",
            "title":    f"Infrastructure serving {certstream_hits} malicious certificates in Datazag BGP feed",
            "evidence": f"certstream_hits: {certstream_hits}",
            "detail":   "This domain's infrastructure is co-located with infrastructure currently serving distinct malicious certificates in the Datazag CertStream BGP feed. This indicates active malicious certificate issuance on shared infrastructure.",
            "remediation": "Investigate co-hosted infrastructure for malicious activity. Consider migrating to dedicated infrastructure if malicious neighbours are confirmed.",
            "category": "threat_intelligence",
        })

    return findings


# ---------------------------------------------------------------------------
# TXT intelligence extractor
# ---------------------------------------------------------------------------

def _extract_txt_intelligence(record) -> dict:
    """
    Identifies SaaS platforms, identity providers, and anomalies
    from TXT records using the combined fingerprint pattern lists.
    """
    all_patterns = TXT_FINGERPRINTS + ADDITIONAL_TXT_FINGERPRINTS

    saas, identity, payment, ai_infra, security, email_mktg = [], [], [], [], [], []
    anomalies    = []
    unrecognised = []
    seen: set[str] = set()

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
        r"^[0-9a-f]{40,}$",  # bare hex token — unidentified verification or stale credential
    ]

    SKIP_PREFIXES = (
        "v=spf1", "v=dmarc1", "v=mcpv1",
        "google-site-verification", "ms=",
        "apple-domain-verification", "_",
    )
    ANOMALY_SKIP = ("v=spf1", "v=dmarc1", "google-site-verification", "ms=", "apple-domain")

    for txt in record.txt_records:
        matched = False
        for pattern, service, category in all_patterns:
            if re.search(pattern, txt, re.IGNORECASE):
                if service not in seen:
                    seen.add(service)
                    category_map.get(category, saas).append(service)
                matched = True
                break

        if not matched:
            if not any(txt.lower().startswith(p) for p in SKIP_PREFIXES) and len(txt) > 8:
                unrecognised.append(txt[:80])

        for pattern in ANOMALY_PATTERNS:
            if any(txt.lower().startswith(s) for s in ANOMALY_SKIP):
                break
            if re.search(pattern, txt, re.IGNORECASE):
                anomalies.append(txt[:80])
                break

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
        "stripe_count":       sum(1 for t in record.txt_records if t.startswith("stripe-verification=")),
        "docusign_count":     sum(1 for t in record.txt_records if t.startswith("docusign=")),
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

async def run(
    dns_file: str       = None,
    domain: str         = None,
    audience: str       = "insurer",
    partner_context: str = None,
    threat_context: str  = None,
    skip_narrative: bool = False,
    output_dir: Path    = None,
    brand_profile: str  = None,
) -> dict:

    if not dns_file and not domain:
        raise ValueError("Provide either --dns_file or --domain")

    # ── Load brand early ───────────────────────────────────────────────────
    brand = BrandConfig.load(brand_profile)
    print(f"  Brand: {brand.brand_name}")

    # ── Step 1: Load or fetch raw DNS record ──────────────────────────────
    if dns_file:
        with open(dns_file) as fh:
            raw = json.load(fh)
        domain = raw.get("domain", "unknown")
    else:
        print(f"\n  Running live DNS fetch for {domain}...")
        raw = await compile_pure_dns_report(domain)
        raw.setdefault("domain", domain)

    print(f"\n  Analysing {domain}...")

    # ── Step 2: Parse canonical record ───────────────────────────────────
    adapter = DatazagCanonicalAdapter(raw)
    record  = adapter.parse()
    print(
        f"  Parsed — {len(record.txt_records)} TXT records, "
        f"IPv6: {record.is_dual_stack}, "
        f"MX: {record.annotation.mx_provider_name or 'none'}"
    )

    # ── Step 3: Build subdomain summary for findings generator ────────────
    rdap_data    = raw.get("rdap") or {}
    subdomains   = raw.get("subdomains") or []
    subs_summary = raw.get("subdomain_summary") or {}

    # Fallback — compute summary from subdomain list if not pre-computed
    if not subs_summary and isinstance(subdomains, list) and subdomains:
        total = len(subdomains)
        subs_summary = {
            "total":                   total,
            "no_hsts_count":           sum(1 for s in subdomains if not s.get("hsts")),
            "no_csp_count":            sum(1 for s in subdomains if not s.get("csp")),
            "version_disclosed_count": sum(1 for s in subdomains if s.get("server_version")),
            "dangling_cname_count":    sum(1 for s in subdomains if s.get("is_dangling_cname")),
            "malicious_ip_count":      sum(1 for s in subdomains if s.get("is_malicious_ip")),
            "no_https_pct":            round(sum(1 for s in subdomains if not s.get("hsts")) / total * 100),
            "no_csp_pct":              round(sum(1 for s in subdomains if not s.get("csp")) / total * 100),
        }

    # Fetch Medallion Intelligence Snapshot
    print("  Fetching Medallion infrastructure intelligence...")
    
    fallback_asn = getattr(record.annotation, "asn", None) if hasattr(record, "annotation") and record.annotation else None
    
    api = DomainIntelligenceAPI(db_path="/root/asn_data_v3/ducklake/infrastructure_operations_snapshot.duckdb")
    medallion_intel = api.get_domain_intelligence(domain, profile=None, fallback_asn=fallback_asn)
    if "error" in medallion_intel:
        print(f"  [!] Medallion API returned error: {medallion_intel['error']}")
        medallion_intel = {}

    # ── Step 3a: Core passive findings ───────────────────────────────────
    findings = passive_security_findings_v2(
        record,
        subs=subs_summary,
        rdap=rdap_data,
        subdomains=subdomains,
    ) or[]

    # ── Step 3b: NS delegation findings (require resolved subdomain data) ─
    # Derive parent NS provider from raw NS records
    ns_raw = raw.get("dns_profile", {}).get("records", {}).get("NS", {}).get("raw", [])
    primary_ns_provider = None
    if ns_raw:
        first_ns = str(ns_raw[0]).rstrip(".").lower()
        primary_ns_provider = ".".join(first_ns.split(".")[-2:])

    if isinstance(subdomains, list):
        findings.extend(_ns_delegation_findings(subdomains, primary_ns_provider))

    # ── Step 3c: Infrastructure & Medallion hit injection ─────────────────
    findings.extend(_derive_findings_from_medallion(medallion_intel, domain))

    # ── Step 3d: HTTP + Shodan enrichment ─────────────────────────────────
    http_section, shodan_section = await enrich_http_and_shodan(
        domain=domain,
        record=record,
        raw=raw,
        shodan_api_key=os.environ.get("SHODAN_API_KEY"),
    )

    findings.extend(http_section.get("findings", []))
    findings.extend(shodan_section.get("findings", []))

    # Normalise severity vocabulary
    _NORMALISE_SEV = {"elevated": "high", "low": "medium"}
    for f in findings:
        f["severity"] = _NORMALISE_SEV.get(
            f.get("severity", "info"),
            f.get("severity", "info"),
        )

    # Deduplicate — keep best-evidenced version of each finding key
    findings = _deduplicate_findings(findings)

    critical = [f for f in findings if f.get("severity") == "critical"]
    high     = [f for f in findings if f.get("severity") == "high"]
    print(f"  Findings — {len(critical)} critical, {len(high)} high, {len(findings)} total")

    # ── Step 4: Composite risk score ──────────────────────────────────────
    scorer       = DatazagCompositeScorer()
    annotation   = NormalisedAnnotation.from_raw(raw)
    print(f"  DEBUG annotation: mx={annotation.mx_provider_name}, asn_risk={annotation.asn_risk_level}")
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
            "critical": 100, "high": 70, "medium": 40, "none": 5,
        }.get(record.email_auth.spoofing_severity, 20),
        ip_score=None,
        domain_score=domain_score,
        annotation=annotation,
    )
    print(
        f"  Score — {composite.composite_score}/100 "
        f"({composite.risk_band}) | confidence: {composite.confidence}"
    )
    print(f"  Driver — {composite.primary_driver}")

    # ── Step 4a: Medallion infrastructure intelligence ─────────────────────
    if medallion_intel.get("risk_assessment"):
        print(f"  [+] Medallion infrastructure risk score: "
              f"{medallion_intel['risk_assessment'].get('infra_score', 0):.2f}")


        # ── Step 4b: Run CyberRiskScorer for comprehensive scoring ────────
        # ── Six-dimension cyber risk profile ──────────────────────────────────
    # Must run after output dict exists but before narrative
    # Build a minimal output preview for the scorer
    _score_input = {
        "domain":          domain,
        "subdomains":    subdomains,          # ← ADD: takeover data for floor overrides
        "findings":      findings,            # ← ADD: HSTS/CSP coverage parsing
        "cert_analysis": raw.get("cert_analysis") or {},   # ← ADD: missed renewals
        "email_auth":      {
            "spf":            record.email_auth.spf_all_mechanism,
            "spf_raw":        record.email_auth.spf_raw,
            "aspf":           record.email_auth.dmarc_aspf,
            "adkim":          record.email_auth.dmarc_adkim,
            "dmarc_policy":   record.email_auth.dmarc_policy,
            "dmarc_rua":      record.email_auth.dmarc_rua,
            "mta_sts":        record.email_auth.mta_sts_status,
            "mta_sts_mode":   record.email_auth.mta_sts_mode,
            "tls_rpt":        record.email_auth.tls_rpt_status,
            "bimi":           record.email_auth.bimi_status,
            "dnssec":         record.email_auth.dnssec_enabled,
            "is_spoofable":   record.email_auth.is_spoofable,
        },
        "technographics":   {
            "mx_provider_name": record.annotation.mx_provider_name,
            "asn_risk_level":   record.annotation.asn_risk_level,
            "is_cdn_ugc":       record.annotation.is_cdn_ugc,
        },
        "txt_intelligence": _extract_txt_intelligence(record),
        "certificates": {
            "https_ok":           record.https_cert.ok if record.https_cert else None,
            "https_days_left":    record.https_cert.days_remaining if record.https_cert else None,
            "https_lets_encrypt": record.https_cert.is_lets_encrypt if record.https_cert else None,
            "provider_live":      record.smtp.provider_confirmed,
        },
        "threat_flags": {
            "is_new_domain":    record.is_new_domain,
            "has_security_txt": record.has_security_txt,
            "has_caa":          record.has_caa,
        },
        "change_signals": {
            "any_change":      record.changes.any_change_signal,
            "is_dynamic_dns":  record.changes.is_dynamic_dns,
        },
        "labels": {
            "ttl_bucket": record.label_ttl_bucket,
        },
        "dns_records": {
            "aaaa": record.aaaa_records,
        },
    }

    cyber_scorer  = CyberRiskScorer()
    cyber_profile = cyber_scorer.score(_score_input, partner_context=partner_context)
    print(
        f"  Cyber risk — underwriting score: {cyber_profile.underwriting_score}/100 "
        f"({cyber_profile.premium_signal}), "
        f"primary vector: {cyber_profile.primary_claim_vector}"
    )
    # ── Step 5: Assemble output dict ──────────────────────────────────────
    output = {
        # Identity
        "domain":       domain,
        "scanned_at":   record.scanned_at,
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "audience":     audience,

        # Subdomain and registration data
        "subdomains":    subdomains,
        "cert_analysis": raw.get("cert_analysis") or {},
        "rdap":          raw.get("rdap") or {},

        # Risk scoring — rule engine (technical posture, always preserved)
        "risk_score_breakdown": [
            {"rule": r.rule, "points": r.points}
            for r in record.risk.reasons
        ],
 
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
            "rules":       [{"rule": r.rule, "points": r.points} for r in record.risk.reasons],
            "trust_rules": [{"rule": r.rule, "points": r.points} for r in record.risk.negative_contributions],
            "risk_rules":  [{"rule": r.rule, "points": r.points} for r in record.risk.positive_contributions],
        },
 
        # Six-dimension underwriting profile (CyberRiskScorer)
        # This is the authoritative score for insurer, sales, and consultant audiences.
        # IT audience uses composite_score (technical posture) instead.
        "cyber_risk_profile": {
            "underwriting_score":   cyber_profile.underwriting_score,
            "underwriting_band":    cyber_profile.underwriting_band,
            "premium_signal":       cyber_profile.premium_signal,
            "primary_claim_vector": cyber_profile.primary_claim_vector,
            "floor_override":       cyber_profile.floor_override,
            "score_breakdown": {
                "bec":               cyber_profile.score_breakdown["bec"],
                "ransomware":        cyber_profile.score_breakdown["ransomware"],
                "data_breach":       cyber_profile.score_breakdown["data_breach"],
                "supply_chain":      cyber_profile.score_breakdown["supply_chain"],
                "phishing_platform": cyber_profile.score_breakdown["phishing_platform"],
                "maturity_offset":   cyber_profile.score_breakdown["maturity_offset"],
            },
            "dimension_narratives": {
                "bec":               cyber_profile.bec.narrative,
                "ransomware":        cyber_profile.ransomware.narrative,
                "data_breach":       cyber_profile.data_breach.narrative,
                "supply_chain":      cyber_profile.supply_chain.narrative,
                "phishing_platform": cyber_profile.phishing_platform.narrative,
                "maturity":          cyber_profile.maturity.narrative,
            },
            "subdomain_risk": {
                "total":              cyber_profile.subdomains.total,
                "has_takeover":       cyber_profile.subdomains.has_takeover,
                "has_auth_takeover":  cyber_profile.subdomains.has_auth_takeover,
                "takeover_providers": cyber_profile.subdomains.takeover_providers,
                "takeover_count":     len(cyber_profile.subdomains.takeover_vulnerable),
            },
        },
 
        # Audience-appropriate display score — used by renderers and narrative
        # insurer / sales / consultant → underwriting score (floor overrides applied)
        # it → technical posture score (maps to fixable controls)
        "display_score": {
            "insurer":    cyber_profile.underwriting_score,
            "sales":      cyber_profile.underwriting_score,
            "consultant": cyber_profile.underwriting_score,
            "it":         composite.composite_score,
        }.get(audience, composite.composite_score),
 
        "display_risk_band": {
            "insurer":    cyber_profile.underwriting_band,
            "sales":      cyber_profile.underwriting_band,
            "consultant": cyber_profile.underwriting_band,
            "it":         composite.risk_band,
        }.get(audience, composite.risk_band),

        # DNS records
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

        # Email authentication
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

        # Technographics
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
            "is_hosting_cdn":       getattr(record.annotation, "is_hosting_cdn", False),
            "net_trust_score":      record.annotation.net_trust_score,
        },

        # Infrastructure
        "infrastructure": {
            "cdn":        record.annotation.isp_name,
            "isp":        record.annotation.isp_name,
            "asn":        record.annotation.asn,
            "dual_stack": record.is_dual_stack,
            "ip_int":     record.ip_int,
            "ns_primary": record.ns_primary,
            "mx_provider": record.annotation.mx_provider_name,
            "mx_category": record.annotation.mx_mbp_category,
            "ns_provider": record.annotation.ns_provider_name,
        },

        # Certificates
        "certificates": {
            "https_ok":           record.https_cert.ok              if record.https_cert else None,
            "https_days_left":    record.https_cert.days_remaining  if record.https_cert else None,
            "https_issuer":       record.https_cert.issuer          if record.https_cert else None,
            "https_issuer_org":   record.https_cert.issuer_org      if record.https_cert else None,
            "https_san_count":    record.https_cert.san_count       if record.https_cert else None,
            "https_label":        record.https_cert.label           if record.https_cert else None,
            "https_lets_encrypt": record.https_cert.is_lets_encrypt if record.https_cert else None,
            "https_expiring":     record.https_cert.is_expiring_soon if record.https_cert else None,
            "smtp_ok":            record.smtp.cert.ok               if record.smtp.cert else None,
            "smtp_days_left":     record.smtp.cert.days_remaining   if record.smtp.cert else None,
            "smtp_issuer":        record.smtp.cert.issuer           if record.smtp.cert else None,
            "smtp_issuer_org":    record.smtp.cert.issuer_org       if record.smtp.cert else None,
            "smtp_banner":        record.smtp.banner_raw,
            "smtp_banner_host":   record.smtp.banner_host,
            "smtp_banner_detail": record.smtp.banner_detail,
            "provider_live":      record.smtp.provider_confirmed,
        },

        # Labels and flags
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
            "ns_changed":       record.changes.ns_changed,
            "ip_changed":       record.changes.ip_changed,
            "country_changed":  record.changes.country_changed,
            "ttl_drop_big":     record.changes.ttl_drop_big,
            "is_dynamic_dns":   record.changes.is_dynamic_dns,
            "mx_misconfigured": record.changes.mx_misconfigured_provider,
            "parking_points":   record.changes.parking_points,
            "subdomain_points": record.changes.subdomain_points,
            "any_change":       record.changes.any_change_signal,
            "any_threat":       record.changes.any_threat_signal,
        },

        # Infrastructure intelligence (Medallion Snapshot + raw JSON pass-through)
        "infrastructure_intelligence":   medallion_intel,
        "bgp_routing":                   medallion_intel.get("routing") or raw.get("bgp_routing") or {},
        "ip_reputation":                 medallion_intel.get("risk_assessment") or raw.get("ip_reputation") or {},
        "infrastructure_concentration":  medallion_intel.get("concentration") or raw.get("infrastructure_concentration") or {},
        "certificate_intelligence":      raw.get("certificate_intelligence")     or {},
        "geolocation":                   raw.get("geolocation_jurisdiction")     or {},
        "velocity":                      medallion_intel.get("historical_velocity") or raw.get("historical_velocity") or {},
        "abuse_contact":                 raw.get("abuse_contact_quality")        or {},
        "infrastructure_correlation":    raw.get("infrastructure_correlation")   or {},
        "blocklist_signals":             medallion_intel.get("threat_feeds") or raw.get("blocklist_signals") or {},

        # Port scan — placeholder until permission model is in place
        "port_scan": raw.get("port_scan") or {
            "available":           False,
            "requires_permission": True,
            "note":                "Available for commissioned assessments with written authorisation",
        },

        # Enrichment sections
        "http_enrichment":   http_section,
        "shodan_enrichment": shodan_section,
        "txt_intelligence":  _extract_txt_intelligence(record),

        # Findings and narrative (narrative populated below)
        "findings":  findings,
        "narrative": {},
    }
    print("cert_analysis sample:", output.get("cert_analysis", [{}])[0] if isinstance(output.get("cert_analysis"), list) else output.get("cert_analysis"))
    # ── Step 5a: Persist raw output JSON if output_dir provided ───────────
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        domain_key = record.domain.replace(".", "_")
        scanned_ts = record.scanned_at.replace(":", "").replace(" ", "__")
        raw_path   = output_dir / f"{domain_key}__{scanned_ts}.json"
        with open(raw_path, "w") as fh:
            json.dump(output, fh, indent=2, default=str)
        print(f"  Saved raw output: {raw_path}")

    # ── Step 6: Narrative enrichment ─────────────────────────────────────
    if not skip_narrative and os.environ.get("ANTHROPIC_API_KEY"):
        print(f"  Generating narrative ({audience} audience)...")
        narrative = await enrich_with_narrative(
            domain=domain,
            score=output["display_score"],
            risk_band=output["display_risk_band"],
            findings=findings,
            output=output,
            partner_context=partner_context,
            threat_context=threat_context,
            audience=audience,
        )
        output["narrative"] = narrative
        print(f"  Key finding: {narrative.get('key_finding', '')[:80]}...")
    else:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("  Skipping narrative — ANTHROPIC_API_KEY not set")

    # ── Step 7: Render reports ────────────────────────────────────────────
    all_reports = render_all(output, brand=brand)

    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    html_paths: list[tuple[Path, Path]] = []
    for aud, formats in all_reports.items():
        for fmt, content in formats.items():
            ext  = {"json": "json", "markdown": "md", "html": "html"}[fmt]
            path = out_dir / f"{aud}.{ext}"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            if ext == "html":
                html_paths.append((path, out_dir / f"{aud}.pdf"))

    # ── Step 8: PDF generation via Playwright ────────────────────────────
    if html_paths:
        print(f"\n  Converting {len(html_paths)} HTML reports to PDF...")
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            for html_path, pdf_path in html_paths:
                print(f"  → {pdf_path.name}")
                page = await browser.new_page()
                await page.goto(
                    f"file:///{html_path.absolute().as_posix()}",
                    wait_until="networkidle",
                )
                await page.pdf(
                    path=str(pdf_path),
                    format="A4",
                    print_background=True,
                    prefer_css_page_size=True,
                    margin={"top": "0", "right": "0", "bottom": "0", "left": "0"},
                )
            await browser.close()

    print(f"\n  Output written to {out_dir}/")
    print("  16 files — 4 audiences × 4 formats (JSON, Markdown, HTML, PDF)")

    return output


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag DNS Intelligence Engine")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--dns_file", default=None,
        help="Path to pre-collected Datazag DNS JSON file",
    )
    input_group.add_argument(
        "--domain", default=None,
        help="Domain to scan live, e.g. normcyber.com",
    )

    parser.add_argument("--audience",     default="insurer",
                        choices=["insurer", "consultant", "it", "sales"])
    parser.add_argument("--partner",      default=None,
                        help="Partner context e.g. 'Atlassian Platinum Partner'")
    parser.add_argument("--threat",       default=None,
                        help="Threat context e.g. 'Subject of ransom demand'")
    parser.add_argument("--output-dir",   default=None,
                        help="Output directory (overrides OUTPUT_DIR in .env)")
    parser.add_argument("--no-narrative", action="store_true",
                        help="Skip Claude API narrative generation")
    parser.add_argument("--brand",        default=None,
                        help="Brand profile name e.g. 'acme_mssp'")

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