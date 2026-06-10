"""
findings_rules.py
-----------------
Turn the typed medallion contract (+ platform-impersonation data) into the
finding dicts the report renderers already understand:

    {finding, severity, title, evidence, detail, remediation, category}

`severity` uses the existing vocabulary (critical/high/elevated/medium/low/info)
so the renderers' sort/filter machinery (`_SEV_ORDER`) keeps working.

Ported and extended from dnsproject/scripts/compile_intelligence.py:163
(`_derive_findings_from_medallion`). Thresholds are the v1 calibration.
"""

from __future__ import annotations

from typing import Optional

from intelligence_contract import DomainIntelligence, PlatformImpersonation


def _fmt(v: float) -> str:
    return f"{v:.2f}"


# ---------------------------------------------------------------------------
# Threat-pillar rules (infrastructure / hosting neighbourhood)
# ---------------------------------------------------------------------------

def _threat_findings(di: DomainIntelligence) -> list[dict]:
    out: list[dict] = []
    r = di.risk_assessment

    if r.fast_flux_risk > 0.6:
        out.append({
            "finding": "fast_flux_detected",
            "severity": "critical" if r.fast_flux_risk > 0.8 else "high",
            "title": f"Fast-flux DNS pattern detected (score: {_fmt(r.fast_flux_risk)})",
            "evidence": f"Datazag corpus fast-flux score: {_fmt(r.fast_flux_risk)}/1.0",
            "detail": "This domain exhibits fast-flux DNS patterns — rapid rotation of A "
                      "records across multiple IPs, a strong indicator of botnet C2 "
                      "infrastructure or bulletproof hosting used to evade takedown.",
            "remediation": "Investigate whether this domain is under external DNS "
                           "manipulation. Check for unauthorised NS or glue record changes "
                           "at your registrar.",
            "category": "infrastructure_intelligence",
        })

    if r.dga_risk > 0.6:
        out.append({
            "finding": "dga_pattern_detected",
            "severity": "high",
            "title": f"Domain-generation-algorithm pattern (score: {_fmt(r.dga_risk)})",
            "evidence": f"DGA risk score: {_fmt(r.dga_risk)}/1.0",
            "detail": "The domain name has characteristics of algorithmically generated "
                      "domains — used by malware families to create C2 rendezvous points "
                      "that resist en-masse blocklisting.",
            "remediation": "Verify domain ownership and registration intent.",
            "category": "infrastructure_intelligence",
        })

    if r.concentration_risk > 0.7:
        out.append({
            "finding": "malicious_concentration",
            "severity": "high",
            "title": f"High malicious-neighbour concentration (score: {_fmt(r.concentration_risk)})",
            "evidence": f"Concentration risk score: {_fmt(r.concentration_risk)}/1.0",
            "detail": "This domain's infrastructure is co-located with a high density of "
                      "domains associated with malicious activity in the Datazag corpus. "
                      "Shared infrastructure increases cross-contamination risk.",
            "remediation": "Consider migrating to dedicated infrastructure with a "
                           "lower-risk hosting provider. Review co-hosted domains.",
            "category": "infrastructure_intelligence",
        })

    if r.certstream_risk > 0.5:
        out.append({
            "finding": "certstream_domain_risk",
            "severity": "high",
            "title": f"CertStream threat activity on infrastructure (score: {_fmt(r.certstream_risk)})",
            "evidence": f"CertStream risk score: {_fmt(r.certstream_risk)}/1.0",
            "detail": "Infrastructure hosting this domain is associated with active "
                      "malicious certificate issuance in the Datazag CertStream BGP feed.",
            "remediation": "Investigate co-hosted infrastructure for malicious certificate "
                           "activity. Consider migrating to dedicated infrastructure.",
            "category": "infrastructure_intelligence",
        })

    if r.dangling_cname_risk > 0.7 or di.domain_dns_facts.is_dangling_cname:
        tgt = di.domain_dns_facts.cname_target
        out.append({
            "finding": "corpus_dangling_cname_risk",
            "severity": "high",
            "title": "Dangling CNAME — subdomain-takeover exposure",
            "evidence": (f"CNAME target: {tgt}" if tgt
                         else f"Corpus dangling-CNAME risk: {_fmt(r.dangling_cname_risk)}/1.0"),
            "detail": "A CNAME points at a target that no longer resolves to controlled "
                      "infrastructure. An attacker who claims the target resource can serve "
                      "content from your subdomain, enabling phishing and cookie theft.",
            "remediation": "Audit all CNAME records and remove any pointing to unregistered "
                           "or expired targets.",
            "category": "infrastructure_intelligence",
        })

    if r.infra_score > 0.4:
        out.append({
            "finding": "infra_neighbourhood_risk",
            "severity": "high" if r.infra_score > 0.7 else "medium",
            "title": f"Elevated hosting-network risk (infra score: {_fmt(r.infra_score)})",
            "evidence": f"ASN/prefix infrastructure risk: {_fmt(r.infra_score)}/1.0",
            "detail": "The hosting network (ASN/prefix) carries elevated infrastructure "
                      "risk in the Datazag corpus — driven by abuse density, routing "
                      "hygiene, or network type.",
            "remediation": "Review the hosting provider's abuse posture; consider a "
                           "reputable network with RPKI and MANRS participation.",
            "category": "infrastructure_intelligence",
        })

    if r.ip_direct_threat_score > 0.5:
        out.append({
            "finding": "ip_direct_threat",
            "severity": "high",
            "title": f"Hosting IP carries direct threat signal (score: {_fmt(r.ip_direct_threat_score)})",
            "evidence": f"IP direct threat score: {_fmt(r.ip_direct_threat_score)}/1.0",
            "detail": "The serving IP is directly associated with threat activity "
                      "(blocklist / PTR / ownership signals) in the Datazag corpus.",
            "remediation": "Validate the serving IP and migrate off flagged infrastructure.",
            "category": "threat_intelligence",
        })

    # Active threat-feed listings — categorical, severe.
    _FEED_COPY = {
        "feodo": ("Feodo C2 tracker", "command-and-control infrastructure"),
        "urlhaus": ("URLhaus", "malware distribution"),
        "sslbl": ("SSL Blacklist", "malicious TLS certificate"),
        "threatfox": ("ThreatFox", "indicator-of-compromise match"),
        "spamhaus": ("Spamhaus DROP", "do-not-route/peer listed prefix"),
    }
    for feed in di.threat_feeds.listed_feeds():
        label, why = _FEED_COPY[feed]
        out.append({
            "finding": f"threat_feed_{feed}",
            "severity": "critical",
            "title": f"Listed on {label}",
            "evidence": f"{label}: listed",
            "detail": f"This domain's serving infrastructure is listed on {label} "
                      f"({why}). Active feed listings are a direct compromise indicator.",
            "remediation": "Treat the host as compromised: isolate, investigate, and "
                           "migrate to clean infrastructure; request delisting once remediated.",
            "category": "threat_intelligence",
        })

    if di.certstream.hits > 0:
        out.append({
            "finding": "certstream_infra_hit",
            "severity": "high",
            "title": f"Infrastructure serving {di.certstream.hits} malicious certificate(s)",
            "evidence": f"certstream_hits: {di.certstream.hits}",
            "detail": "This domain's infrastructure is co-located with infrastructure "
                      "currently issuing malicious certificates in the Datazag CertStream "
                      "BGP feed.",
            "remediation": "Investigate co-hosted infrastructure; migrate to dedicated "
                           "infrastructure if malicious neighbours are confirmed.",
            "category": "threat_intelligence",
        })

    # Malicious co-tenancy from concentration pivots.
    for pf in di.concentration.pivot_findings:
        if pf.malicious_count >= 5:
            examples = ", ".join(pf.examples[:3]) if pf.examples else "—"
            out.append({
                "finding": f"cotenancy_{pf.dimension}_{pf.value}",
                "severity": "high" if pf.malicious_count >= 25 else "medium",
                "title": f"{pf.malicious_count} malicious domains share this {pf.dimension} "
                         f"({pf.value})",
                "evidence": f"{pf.dimension}={pf.value}; malicious_count={pf.malicious_count}; "
                            f"examples: {examples}",
                "detail": "Your infrastructure shares an "
                          f"{pf.dimension} with a cluster of domains flagged as malicious. "
                          "Co-tenancy raises reputation and contagion risk.",
                "remediation": "Where feasible, move to dedicated IP/ASN space away from the "
                               "malicious cluster.",
                "category": "threat_intelligence",
            })

    if di.historical_velocity.ip_churn_score > 0.6:
        hv = di.historical_velocity
        out.append({
            "finding": "high_ip_churn",
            "severity": "medium",
            "title": f"High IP churn over 30 days (score: {_fmt(hv.ip_churn_score)})",
            "evidence": f"ip_changes_30d={hv.ip_changes_30d}; asn_diversity_30d="
                        f"{hv.asn_diversity_30d}; churn={_fmt(hv.ip_churn_score)}/1.0",
            "detail": "The domain's resolving infrastructure has changed frequently in the "
                      "last 30 days — consistent with fast-flux or unstable hosting.",
            "remediation": "Confirm the churn is expected (e.g. CDN). Investigate if not.",
            "category": "infrastructure_intelligence",
        })

    return out


# ---------------------------------------------------------------------------
# Trust-pillar rules (email auth / routing integrity)
# ---------------------------------------------------------------------------

def _trust_findings(di: DomainIntelligence) -> list[dict]:
    out: list[dict] = []
    es, rt, fa = di.email_security, di.routing, di.facts

    if es.dmarc_risk:
        out.append({
            "finding": "no_dmarc_enforcement",
            "severity": "high",
            "title": "DMARC not enforced",
            "evidence": "email_security.dmarc_risk = true",
            "detail": "Without an enforcing DMARC policy (p=quarantine/reject) attackers can "
                      "spoof your domain in email, enabling phishing of staff, customers and "
                      "partners.",
            "remediation": "Publish DMARC at p=quarantine, monitor RUA reports, then move to "
                           "p=reject.",
            "category": "email_security",
        })

    if es.spf_risk:
        out.append({
            "finding": "spf_weak",
            "severity": "medium",
            "title": "SPF not strict",
            "evidence": "email_security.spf_risk = true",
            "detail": "SPF is missing or not in strict (-all) mode, weakening sender "
                      "validation and DMARC alignment.",
            "remediation": "Ensure all sending sources are covered and set SPF to -all.",
            "category": "email_security",
        })

    if not es.modern_security_present:
        out.append({
            "finding": "no_modern_email_security",
            "severity": "medium",
            "title": "Modern email-security controls absent",
            "evidence": "email_security.modern_security_present = false",
            "detail": "Enforcing DMARC together with strict SPF is not present, so the domain "
                      "is not fully protected against spoofing and downgrade attacks.",
            "remediation": "Complete DMARC enforcement and strict SPF; add MTA-STS and TLS-RPT.",
            "category": "email_security",
        })

    if rt.rpki_state == "invalid":
        out.append({
            "finding": "rpki_invalid",
            "severity": "critical",
            "title": "RPKI state INVALID — route hijack exposure",
            "evidence": "routing.rpki_state = invalid",
            "detail": "The announcing prefix fails RPKI origin validation. Networks that drop "
                      "RPKI-invalid routes may blackhole traffic, and the prefix is more "
                      "easily hijacked.",
            "remediation": "Work with the hosting/network provider to publish a correct ROA "
                           "for the prefix.",
            "category": "routing_security",
        })
    elif rt.rpki_state == "unknown":
        out.append({
            "finding": "rpki_unknown",
            "severity": "medium",
            "title": "RPKI state unknown — no ROA published",
            "evidence": "routing.rpki_state = unknown",
            "detail": "No RPKI ROA covers the announcing prefix, leaving origin validation "
                      "unavailable and raising hijack risk.",
            "remediation": "Encourage the network operator to publish ROAs (RPKI).",
            "category": "routing_security",
        })

    if rt.moas_detected:
        out.append({
            "finding": "moas_anomaly",
            "severity": "high",
            "title": "Multiple-origin AS (MOAS) anomaly on the prefix",
            "evidence": "routing.moas_detected = true",
            "detail": "The prefix is announced from more than one origin AS — a classic "
                      "route-hijack / misconfiguration signal.",
            "remediation": "Confirm all announcing ASNs are authorised; investigate any that "
                           "are not.",
            "category": "routing_security",
        })

    if fa.is_manrs_culprit:
        out.append({
            "finding": "manrs_culprit",
            "severity": "high",
            "title": "Hosting AS flagged as a MANRS routing culprit",
            "evidence": "facts.is_manrs_culprit = true",
            "detail": "The hosting AS has been associated with routing incidents (hijacks / "
                      "leaks) in MANRS data.",
            "remediation": "Prefer networks with clean routing-security records.",
            "category": "routing_security",
        })
    elif not fa.is_manrs_member:
        out.append({
            "finding": "not_manrs_member",
            "severity": "info",
            "title": "Hosting AS is not a MANRS participant",
            "evidence": "facts.is_manrs_member = false",
            "detail": "The hosting network does not participate in MANRS routing-security "
                      "norms. Informational, not a defect.",
            "remediation": "Consider providers with MANRS participation for better routing "
                           "hygiene.",
            "category": "routing_security",
        })

    return out


# ---------------------------------------------------------------------------
# External-threat rules (platform impersonation)
# ---------------------------------------------------------------------------

def _impersonation_findings(impersonations: list[PlatformImpersonation]) -> list[dict]:
    out: list[dict] = []
    for imp in impersonations:
        if imp.count_30d <= 0:
            continue
        sev = "high" if imp.count_30d >= 20 else "medium" if imp.count_30d >= 5 else "info"
        examples = ", ".join(imp.sample_domains[:3]) if imp.sample_domains else "—"
        out.append({
            "finding": f"platform_impersonation_{imp.platform}",
            "severity": sev,
            "title": f"{imp.count_30d} lookalike domains impersonating {imp.platform} (30d)",
            "evidence": f"{imp.platform}: {imp.count_7d} in 7d / {imp.count_30d} in 30d; "
                        f"examples: {examples}",
            "detail": f"Your organisation uses {imp.platform}. Attackers have registered "
                      f"{imp.count_30d} lookalike/typosquat domains targeting that platform in "
                      "the last 30 days. Staff who trust the platform are the phishing target.",
            "remediation": f"Brief staff on {imp.platform} phishing; enforce phishing-resistant "
                           "MFA; consider takedown of the lookalikes most likely to target you.",
            "category": "external_threat",
        })
    return out


# ---------------------------------------------------------------------------
# Reason-code passthrough (nothing silently dropped)
# ---------------------------------------------------------------------------

# Known corpus reason codes → presentable copy. Unknown codes fall back to a
# generic template so they still surface.
REASON_CODE_COPY: dict[str, dict] = {
    "SPAMHAUS_ASN_DROP": {"severity": "critical",
                          "title": "Hosting ASN on Spamhaus DROP",
                          "detail": "The hosting AS is on the Spamhaus DROP list (do not "
                                    "route or peer)."},
    "FEODO_INFRA_OVERLAP": {"severity": "high",
                            "title": "Infrastructure overlaps Feodo C2",
                            "detail": "Hosting overlaps Feodo command-and-control ranges."},
    "HIGH_BGP_CHURN": {"severity": "medium",
                       "title": "High BGP prefix churn",
                       "detail": "The prefix shows high hour-over-hour churn."},
    "MALICIOUS_IP_DENSITY": {"severity": "high",
                             "title": "High malicious-IP density on network",
                             "detail": "The network hosts a high density of malicious IPs."},
    "THREAT_DENSITY_SURGE": {"severity": "high",
                             "title": "Recent threat-density surge on network",
                             "detail": "A recent surge in malicious activity was observed on "
                                       "the hosting network."},
    "HIGH_RISK_NETWORK_TYPE": {"severity": "medium",
                               "title": "High-risk network type",
                               "detail": "The network type (e.g. bulletproof/abuse-tolerant) "
                                         "is high risk."},
}


def _humanise(code: str) -> str:
    return code.replace("_", " ").title()


def _reason_code_findings(di: DomainIntelligence, already: set[str]) -> list[dict]:
    out: list[dict] = []
    for code in di.risk_assessment.reason_codes:
        key = f"reason_{code.lower()}"
        if key in already:
            continue
        copy = REASON_CODE_COPY.get(code)
        out.append({
            "finding": key,
            "severity": copy["severity"] if copy else "medium",
            "title": copy["title"] if copy else _humanise(code),
            "evidence": f"Datazag corpus reason code: {code}",
            "detail": copy["detail"] if copy else
                      f"The Datazag corpus flagged this domain's infrastructure with reason "
                      f"code '{code}'.",
            "remediation": "Review the flagged infrastructure signal.",
            "category": "infrastructure_intelligence",
        })
    return out


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def derive_findings(
    di: DomainIntelligence,
    impersonations: Optional[list[PlatformImpersonation]] = None,
) -> list[dict]:
    """Build the full findings list from the medallion contract + impersonation data."""
    if not di.has_intelligence:
        return []

    findings: list[dict] = []
    findings += _threat_findings(di)
    findings += _trust_findings(di)
    findings += _impersonation_findings(impersonations or [])

    seen = {f["finding"] for f in findings}
    findings += _reason_code_findings(di, seen)
    return findings
