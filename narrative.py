# narrative.py
import aiohttp
import json
import os
import re
from aiohttp import TCPConnector
from aiohttp.resolver import ThreadedResolver
from typing import Optional

from intelligence_contract import (
    DomainIntelligence,
    ReportViewModel,
    build_view_models,
)

AUDIENCE_TONE = {
    "insurer":     "a cyber insurance underwriter assessing policy risk and making underwriting decisions",
    "consultant":  "a senior security consultant preparing a detailed technical briefing for a client",
    "it":          "an IT security manager reviewing their own organisation's infrastructure posture",
    "sales":       "a sales team preparing a compelling prospect outreach brief",
    # Consolidated report set (healthreport/audiences.py)
    "advisory":    "a senior security consultant briefing a client, blending technical findings "
                   "with commercial talking points a sales conversation can use",
    "remediation": "an IT lead planning the remediation queue, writing so a non-technical "
                   "economic buyer can also follow the cost and business impact",
    "flagship":    "an executive reader assessing their organisation's trust posture and "
                   "threat/attack surface",
    "external_threat": "a security lead assessing platform-impersonation and brand-lookalike "
                       "threats targeting their staff and customers",
}


def _vm_from_output(output: dict) -> Optional[ReportViewModel]:
    """Resolve a typed view-model from the legacy compiled output dict.

    The pipeline passes riskscore's medallion payload through under
    `infrastructure_intelligence`; when it is medallion-shaped, parse it.
    Returns None when no corpus intelligence is present — the prompt then says
    so explicitly instead of silently rendering NO_DATA on a wrong scale.
    """
    infra_intel = output.get("infrastructure_intelligence") or {}
    if isinstance(infra_intel, dict) and "risk_assessment" in infra_intel:
        payload = {**infra_intel,
                   "domain": infra_intel.get("domain") or output.get("domain", "")}
        di = DomainIntelligence.model_validate(payload)
        if di.has_intelligence:
            return build_view_models(di)
    return None


def _medallion_block(vm: Optional[ReportViewModel]) -> str:
    """The Datazag corpus-intelligence section of the prompt, from the typed
    medallion contract. All scores are 0.00-1.00 (higher = worse)."""
    if vm is None or not vm.has_intelligence:
        return (
            "=== DATAZAG GLOBAL INFRASTRUCTURE INTELLIGENCE ===\n"
            "No Datazag corpus intelligence is available for this domain "
            "(first assessment or domain not yet in the corpus). Do not "
            "fabricate infrastructure-intelligence claims."
        )

    t, th = vm.trust, vm.threat
    hv = th.historical_velocity

    reason_lines = "\n".join(f"  - {c}" for c in th.reason_codes) or "  (none)"
    feed_line = ", ".join(th.listed_feeds) if th.listed_feeds else "none"
    pivot_lines = "\n".join(
        f"  - {pf.malicious_count} malicious domains share this {pf.dimension} "
        f"({pf.value})" + (f" — e.g. {', '.join(pf.examples[:3])}" if pf.examples else "")
        for pf in th.pivot_findings if pf.malicious_count > 0
    ) or "  (no malicious co-tenancy observed)"

    return f"""=== DATAZAG GLOBAL INFRASTRUCTURE INTELLIGENCE (medallion corpus) ===
All scores 0.00-1.00, higher = worse. Composite: {vm.composite_score}/100 (grade {vm.grade.letter}).
Risk assessment:
  Infrastructure (ASN/prefix) risk: {th.infra_score:.2f}
  IP direct threat score: {th.ip_direct_threat_score:.2f}
  Fast-flux risk: {th.fast_flux_risk:.2f}
  DGA risk: {th.dga_risk:.2f}
  Concentration risk: {th.concentration_risk:.2f}
  CertStream risk: {th.certstream_risk:.2f}
  Dangling-CNAME risk: {th.dangling_cname_risk:.2f}{f" (target: {th.cname_target})" if th.is_dangling_cname and th.cname_target else ""}
Corpus reason codes:
{reason_lines}
Active threat-feed listings: {feed_line}
CertStream hits on serving infrastructure: {th.certstream_hits}
Routing integrity: RPKI {t.rpki_state}; MOAS {"DETECTED" if t.moas_detected else "none"}; \
prefix churn {t.prefixes_churn_total}; MANRS member: {"yes" if t.is_manrs_member else "no"}\
{"; MANRS CULPRIT" if t.is_manrs_culprit else ""}
Email security (corpus): mx_type={t.mx_type}, mx_risk={t.mx_risk_score:.2f}, \
DMARC {"AT RISK (not enforced)" if t.dmarc_risk else "enforced"}, \
SPF {"AT RISK (not strict)" if t.spf_risk else "strict"}, \
modern controls {"present" if t.modern_security_present else "incomplete"}
Historical velocity (30 days): {hv.ip_changes_30d} IP changes, \
{hv.asn_diversity_30d} distinct ASNs, {hv.geo_diversity_30d} geographies, \
IP churn score {hv.ip_churn_score:.2f}
Malicious co-tenancy:
{pivot_lines}"""


def _external_threat_block(vm: Optional[ReportViewModel]) -> str:
    """Platform-impersonation section: imitations of the platforms the
    organisation uses, plus own-brand lookalikes (7/30-day windows)."""
    if vm is None:
        return ""
    ext = vm.external_threat
    if not ext.impersonations and not ext.own_brand.count_30d:
        return ""

    lines = ["=== EXTERNAL THREAT — PLATFORM IMPERSONATION (7/30-day windows) ==="]
    if ext.detected_platforms:
        lines.append(f"Detected platform stack: {', '.join(ext.detected_platforms)}")
    for imp in ext.impersonations:
        sample = f" — e.g. {', '.join(imp.sample_domains[:3])}" if imp.sample_domains else ""
        lines.append(f"  {imp.platform}: {imp.count_7d} in 7d / {imp.count_30d} in 30d "
                     f"({imp.trend}){sample}")
    if ext.own_brand.count_30d:
        ob = ext.own_brand
        sample = f" — e.g. {', '.join(ob.sample_domains[:3])}" if ob.sample_domains else ""
        lines.append(f"  Own-brand lookalikes: {ob.count_7d} in 7d / {ob.count_30d} in 30d{sample}")
    return "\n".join(lines)


def build_narrative_prompt(
    domain: str,
    score: int,
    risk_band: str,
    findings: list[dict],
    output: dict,
    partner_context: Optional[str] = None,
    threat_context: Optional[str] = None,
    audience: str = "insurer",
    vm: Optional[ReportViewModel] = None,
) -> str:
    """Assemble the narrative prompt. Pure function — extracted from
    enrich_with_narrative so it can be tested without an API call."""

    ea          = output.get("email_auth", {})
    tech        = output.get("technographics", {})
    ti          = output.get("txt_intelligence", {})
    certs       = output.get("certificates", {})
    infra       = output.get("infrastructure", {})
    labels      = output.get("labels", {})
    flags       = output.get("threat_flags", {})
    changes     = output.get("change_signals", {})
    dns         = output.get("dns_records", {})
    cs_raw      = output.get("composite_score", {})
    cs          = cs_raw if isinstance(cs_raw, dict) else {"score": cs_raw}
    if vm is None:
        vm = _vm_from_output(output)

    # ── Risk engine ───────────────────────────────────────────────────────

    risk_eng = output.get("risk_score_engine") or {
        "score":          0,
        "bucket":         "unknown",
        "config_version": "unknown",
        "risk_rules":     [],
        "trust_rules":    [],
        "rules":          [],
    }

    rules_detail = "\n".join(
        f"  +{r.get('points', 0):5.1f}  {r.get('rule', '')}"
        for r in risk_eng.get("risk_rules", [])
        if r.get("points", 0) > 0
    ) or "  (no risk rules fired)"

    trust_detail = "\n".join(
        f"  -{abs(r.get('points', 0)):5.1f}  {r.get('rule', '')}"
        for r in risk_eng.get("trust_rules", [])
        if r.get("points", 0) != 0
    ) or "  (no trust rules fired)"

    # ── Findings ──────────────────────────────────────────────────────────

    _SEV_ORDER = {
        "critical": 0, "high": 1, "elevated": 2,
        "medium": 3,   "low": 4,  "info": 5,
    }

    findings_detail = "\n".join(
        f"  [{f.get('severity', 'info').upper()}] "
        f"{f.get('title') or f.get('label', 'Finding')}\n"
        f"    Evidence: {f.get('evidence', '')[:120]}\n"
        f"    Detail: {(f.get('detail') or f.get('description', ''))[:200]}\n"
        f"    Fix: {(f.get('remediation') or '')[:120]}"
        for f in sorted(
            findings,
            key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 5)
        )
    )

    # ── Supporting prompt variables ───────────────────────────────────────

    saas_all = ti.get("all_identified", [])
    high_risk_saas = [
        s for s in saas_all
        if any(k in s.lower() for k in ("lastpass", "okta", "twilio", "mailchimp", "circleci"))
    ]

    missing_layers_prompt = "\n".join(filter(None, [
        f"- NO SPF RECORD: Any server can send as @{domain}"
            if not ea.get("spf_raw") else "",
        "- NO DMARC: No spoofing protection policy"
            if not ea.get("dmarc_policy") else "",
        f"- DMARC p={ea.get('dmarc_policy')} (not reject): Partial enforcement only"
            if ea.get("dmarc_policy") and ea.get("dmarc_policy") != "reject" else "",
        "- NO MTA-STS: SMTP downgrade attacks possible"
            if ea.get("mta_sts") in ("NXDOMAIN", "NOT_FOUND", "NODATA") else "",
        "- NO TLS-RPT: No SMTP TLS failure visibility"
            if ea.get("tls_rpt") in ("NXDOMAIN", "NOT_FOUND", "NODATA") else "",
        "- NO BIMI: Brand logo not shown in email clients"
            if ea.get("bimi") in ("NOT_FOUND", "NXDOMAIN", "NODATA") else "",
        "- NO DNSSEC: DNS responses unsigned"
            if not ea.get("dnssec") else "",
        "- NO CAA RECORDS: Any CA can issue certificates"
            if not flags.get("has_caa") else "",
        "- NO SECURITY.TXT: No responsible disclosure policy"
            if not flags.get("has_security_txt") else "",
    ]))

    # ── Subdomain intelligence ────────────────────────────────────────────

    subs_list = output.get("subdomains") or []
    subs_sum  = output.get("subdomain_summary") or {}
    mx_ptr    = subs_sum.get("mx_ptr_results") or []

    high_risk_subs = [
        s for s in subs_list
        if s.get("risk_level") in ("critical", "high")
    ][:8]

    dangling_subs = [
        s for s in subs_list
        if s.get("is_dangling_cname") or
           s.get("ns_delegation_risk") == "dangling_ns_delegation"
    ][:5]

    takeover_subs = [
        s for s in subs_list
        if s.get("is_takeover_vulnerable")
    ][:5]

    malicious_subs = [
        s for s in subs_list
        if s.get("is_malicious_ip")
    ][:5]

    mx_ptr_invalid = [r for r in mx_ptr if not r.get("ptr_valid")]

    def _sub_line(s: dict) -> str:
        a   = s.get("a_records", [])
        ptr = s.get("ptr_reveals_provider", "") or "no PTR"
        rsn = "; ".join(s.get("risk_reasons", [])[:1])
        return (
            f"  {s.get('dns_name','')} — {s.get('risk_level','')} — "
            f"A:{a[0] if a else '?'} — PTR:{ptr}"
            + (f" — {rsn}" if rsn else "")
        )

    subdomain_section = ""
    if subs_list:
        lines = [
            f"=== SUBDOMAIN INTELLIGENCE ({len(subs_list)} subdomains) ===",
            f"Total subdomains: {subs_sum.get('total', len(subs_list))}",
            f"High/critical risk: {subs_sum.get('high_risk_count', 0)}",
            f"Dangling CNAMEs: {subs_sum.get('dangling_cname_count', 0)}",
            f"Takeover vulnerable: {subs_sum.get('takeover_vulnerable_count', 0)}",
            f"Malicious IP co-location: {subs_sum.get('malicious_ip_count', 0)}",
            f"Internal IPs in public DNS: {subs_sum.get('internal_ip_count', 0)}",
            f"Delegated zones: {subs_sum.get('delegated_zone_count', 0)}",
            f"MX PTR mismatches: {len(mx_ptr_invalid)}",
            "",
        ]

        if high_risk_subs:
            lines.append("High-risk subdomains:")
            lines.extend(_sub_line(s) for s in high_risk_subs)
            lines.append("")

        if takeover_subs:
            lines.append("Takeover-vulnerable subdomains:")
            lines.extend(
                f"  {s.get('dns_name','')} → {s.get('takeover_provider','?')} "
                f"(CNAME: {s.get('cname','?')})"
                for s in takeover_subs
            )
            lines.append("")

        if malicious_subs:
            lines.append("Subdomains resolving to malicious IPs:")
            lines.extend(
                f"  {s.get('dns_name','')} → "
                f"{s.get('a_records',['?'])[0]} "
                f"({', '.join(s.get('ip_malicious_feeds',[]) or ['blocklist'])})"
                for s in malicious_subs
            )
            lines.append("")

        if dangling_subs:
            lines.append("Dangling subdomains (CNAME or NS target does not resolve):")
            lines.extend(
                f"  {s.get('dns_name','')} — "
                f"{'NS takeover' if s.get('ns_delegation_risk') == 'dangling_ns_delegation' else 'CNAME dangling'}"
                for s in dangling_subs
            )
            lines.append("")

        if mx_ptr_invalid:
            lines.append("MX PTR mismatches (affects mail deliverability):")
            lines.extend(
                f"  {r['mx_host']} ({r['mx_ip']}) — "
                f"PTR: {', '.join(r.get('ptr_records', [])) or 'absent'}"
                for r in mx_ptr_invalid
            )
            lines.append("")

        subdomain_section = "\n".join(lines)

    # ── Prompt ────────────────────────────────────────────────────────────

    prompt = f"""You are producing a detailed DNS intelligence report for {AUDIENCE_TONE.get(audience, AUDIENCE_TONE["consultant"])}.

DOMAIN: {domain}
SCANNED: {output.get('scanned_at', '')}
{f'PARTNER CONTEXT: {partner_context}' if partner_context else ''}
{f'THREAT CONTEXT: {threat_context}' if threat_context else ''}

=== COMPOSITE RISK SCORE ===
Score: {score}/100 ({risk_band})
Confidence: {cs.get('confidence', '?')}
Primary driver: {cs.get('primary_driver', '?')}
Components: {json.dumps(cs.get('components', {}), indent=2)}
Nudges applied:
  MX provider: {cs.get('nudges', {}).get('mx_provider', '?')} (trust nudge: {cs.get('nudges', {}).get('mx_trust_nudge', 0):+.1f}, risk bias: {cs.get('nudges', {}).get('mx_risk_bias', 0):+.1f})
  ASN risk level: {cs.get('nudges', {}).get('asn_risk_level', '?')}
  TLD risk: {cs.get('nudges', {}).get('tld_risk', '?')} (adjustment: {cs.get('nudges', {}).get('tld_adjustment', 0):+.1f})

=== RULE ENGINE BREAKDOWN ===
Score: {risk_eng.get('score', 0)}/100 ({risk_eng.get('bucket', '?')}) — config {risk_eng.get('config_version', '?')}
Risk rules fired:
{rules_detail}
Trust rules fired:
{trust_detail}

=== EMAIL AUTHENTICATION ===
SPF: {ea.get('spf_raw', 'NOT FOUND')}
  Mechanism: {ea.get('spf', '?')} | Strictness: {ea.get('spf_strictness', '?')}
  Includes: {', '.join(ea.get('spf_includes', []))}
  IP4 ranges: {', '.join(ea.get('spf_ip4_ranges', []))}
DMARC: {ea.get('dmarc_raw', 'NOT FOUND')}
  Policy: {ea.get('dmarc_policy', 'missing')} | pct={ea.get('dmarc_pct', 0)}
  aspf={ea.get('aspf', '?')} adkim={ea.get('adkim', '?')} fo={ea.get('dmarc_fo', '?')}
  RUA: {ea.get('dmarc_rua', 'none')} | RUF: {ea.get('dmarc_ruf', 'none')}
MTA-STS: {ea.get('mta_sts', '?')} (mode: {ea.get('mta_sts_mode') or 'not configured'})
TLS-RPT: {ea.get('tls_rpt', '?')}
BIMI: {ea.get('bimi', '?')}
DNSSEC: {ea.get('dnssec', '?')}
Is spoofable: {ea.get('is_spoofable', False)} (severity: {ea.get('spoofing_severity', '?')})
Fully authenticated: {ea.get('is_fully_authenticated', False)}
Missing layers: {', '.join(ea.get('missing_layers', []) or ['none'])}

=== TECHNOGRAPHICS ===
MX provider: {tech.get('mx_provider_name', '?')} — category: {tech.get('mx_mbp_category', '?')}
NS provider: {tech.get('ns_provider_name', '?')} — category: {tech.get('ns_provider_category', '?')}
ISP: {tech.get('isp_name', '?')} ({tech.get('isp_country', '?')}) — ASN: {tech.get('asn', '?')}
ASN risk level: {tech.get('asn_risk_level', '?')}
Hosting CDN: {'Yes — known CDN infrastructure, fast-flux and network risk signals are suppressed for this domain' if tech.get('is_hosting_cdn') else 'No'}
TLD risk: {tech.get('tld_risk_level', '?')} ({tech.get('tld_country', '?')})
Net trust score: {tech.get('net_trust_score', 0):+.1f}
CDN/UGC mail: {tech.get('is_cdn_ugc', False)}

SaaS stack ({ti.get('total_identified', 0)} services identified):
  All: {', '.join(saas_all) if saas_all else 'none'}
  Identity: {', '.join(ti.get('identity_providers', []))}
  AI infrastructure: {', '.join(ti.get('ai_infrastructure', []))}
  Payment: {', '.join(ti.get('payment_processors', []))}
  Security tooling: {', '.join(ti.get('security_tooling', []))}
  HIGH RISK (known breaches): {', '.join(high_risk_saas) if high_risk_saas else 'none'}
  Anomalous TXT records: {json.dumps(ti.get('anomalous_records', []))}

=== CERTIFICATES ===
HTTPS: {certs.get('https_issuer_org', '?')} ({certs.get('https_label', '?')})
  Days remaining: {certs.get('https_days_left', '?')} {'— EXPIRING SOON' if certs.get('https_expiring') else ''}
  SANs: {certs.get('https_san_count', '?')} | Let's Encrypt: {certs.get('https_lets_encrypt', '?')}
SMTP: {certs.get('smtp_issuer_org', '?')}
  Days remaining: {certs.get('smtp_days_left', '?')}
  Banner: {certs.get('smtp_banner', 'none')}
  Provider live confirmed: {certs.get('provider_live', False)}

=== INFRASTRUCTURE ===
IPv6 dual-stack: {infra.get('dual_stack', False)}
A records: {', '.join(dns.get('a', []))}
AAAA records: {', '.join(dns.get('aaaa', []))}
MX records: {', '.join(f"{r['priority']}:{r['host']}" if isinstance(r, dict) else str(r) for r in dns.get('mx', []))}
NS records: {', '.join(dns.get('ns', []))}
CAA records: {', '.join(dns.get('caa', [])) or 'NONE'}
TXT records ({len(dns.get('txt', []))} total):
{chr(10).join('  ' + t for t in dns.get('txt', []))}

=== LABELS ===
DMARC policy label: {labels.get('dmarc_policy', '?')}
SPF strictness label: {labels.get('spf_strictness', '?')}
TTL bucket: {labels.get('ttl_bucket', '?')}
SSL issuer label: {labels.get('ssl_issuer', '?')}
Active infrastructure: {labels.get('active_infrastructure', '?')}

=== THREAT FLAGS ===
Phishing: {flags.get('is_phishing', False)}
Malware: {flags.get('is_malware', False)}
New domain: {flags.get('is_new_domain', False)}
Security.txt: {flags.get('has_security_txt', False)}
CAA records: {flags.get('has_caa', False)}

=== CHANGE SIGNALS ===
NS changed: {changes.get('ns_changed', False)}
IP changed: {changes.get('ip_changed', False)}
Country changed: {changes.get('country_changed', False)}
TTL big drop: {changes.get('ttl_drop_big', False)}
Dynamic DNS: {changes.get('is_dynamic_dns', False)}
MX misconfigured: {changes.get('mx_misconfigured', False)}
Parking points: {changes.get('parking_points', 0)}

{subdomain_section}

=== MISSING SECURITY LAYERS — DISCUSS EACH IN NARRATIVE ===
{missing_layers_prompt}

For each missing layer above, explain:
1. The specific attack scenario
2. What an attacker can do because it is missing
3. The specific DNS record needed to fix it

{_medallion_block(vm)}

{_external_threat_block(vm)}

=== ALL FINDINGS ===
{findings_detail}
---

Return ONLY a valid JSON object with exactly these fields:

{{
  "key_finding": "The single most important finding in one precise sentence. Reference specific evidence. If a subdomain takeover, dangling CNAME, or malicious IP co-location is present, lead with that.",
  "executive_summary": "3-4 sentences. Lead with composite score and primary driver. Name specific services and risk signals. Mention subdomain count and any critical subdomain findings if present.",
  "threat_narrative": "5-8 sentences of deep interpretive analysis. Reference specific DNS evidence throughout. If high-risk subdomains exist (VPN endpoints, staging, admin panels), explain the specific attack scenario each enables and name the subdomain. If takeover-vulnerable CNAMEs exist, explain what an attacker gains by claiming the target resource. If malicious IPs are present on subdomains, explain the contagion and trust risk. Interweave the Datazag corpus-intelligence signals (RPKI state, MOAS anomalies, fast-flux, DGA, threat-feed listings, malicious co-tenancy, 30-day velocity) if present. If platform-impersonation activity is present, name the most-targeted platform and its 30-day lookalike count, and explain the staff-phishing scenario it enables.",
  "positive_signals": "2-3 sentences identifying what this domain does well. Name specific providers, policies, and score contributions.",
  "remediation_priority": "For each critical or high finding, one sentence with the specific fix and expected impact. Numbered list. Lead with subdomain takeover or malicious IP findings if present.",
  "insurer_signals": "3-4 sentences translating technical findings into policy risk language. Mention attack vectors and likely claim types. Reference how Datazag Infrastructure Telemetry (BGP routing, infrastructure scores, subdomain exposure) impacts actuarial cyber risk premiums. Note any subdomain takeover or malicious co-location as direct premium loading signals.",
  "saas_stack_analysis": "2-3 sentences on the SaaS stack breadth, any high-risk services, what it reveals about the organisation, supply chain implications."
}}"""

    return prompt


async def enrich_with_narrative(
    domain: str,
    score: int,
    risk_band: str,
    findings: list[dict],
    output: dict,
    partner_context: Optional[str] = None,
    threat_context: Optional[str] = None,
    audience: str = "insurer",
    vm: Optional[ReportViewModel] = None,
) -> dict:
    prompt = build_narrative_prompt(
        domain=domain,
        score=score,
        risk_band=risk_band,
        findings=findings,
        output=output,
        partner_context=partner_context,
        threat_context=threat_context,
        audience=audience,
        vm=vm,
    )

    # ── API call ──────────────────────────────────────────────────────────

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
    }

    data = None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json={
                    "model":      "claude-sonnet-4-6",
                    "max_tokens": 3000,
                    "messages":   [{"role": "user", "content": prompt}],
                },
            ) as resp:
                data = await resp.json()

    except aiohttp.ClientConnectorDNSError:
        connector = TCPConnector(resolver=ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json={
                    "model":      "claude-sonnet-4-6",
                    "max_tokens": 3000,
                    "messages":   [{"role": "user", "content": prompt}],
                },
            ) as resp:
                data = await resp.json()

    if not data:
        return _empty_narrative()

    # ── Parse response ────────────────────────────────────────────────────

    raw_text = data.get("content", [{}])[0].get("text", "").strip()
    return _safe_parse_narrative(raw_text)


def _safe_parse_narrative(raw: str) -> dict:
    """
    Parse narrative JSON response defensively.
    Handles: empty string, markdown fences, error messages.
    """
    if not raw or not raw.strip():
        return _empty_narrative()

    text = raw.strip()

    # Strip markdown code fences
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()

    # Non-JSON response — error message from model
    if not text.startswith("{"):
        return {
            **_empty_narrative(),
            "key_finding":  "Narrative generation failed — non-JSON response",
            "raw_response": text[:200],
        }

    try:
        parsed = json.loads(text)
        return {**_empty_narrative(), **parsed}
    except json.JSONDecodeError as e:
        return {
            **_empty_narrative(),
            "key_finding":  f"Narrative JSON parse error: {e}",
            "raw_response": text[:200],
        }


def _empty_narrative() -> dict:
    return {
        "key_finding":          "",
        "executive_summary":    "",
        "threat_narrative":     "",
        "positive_signals":     "",
        "remediation_priority": "",
        "insurer_signals":      "",
        "saas_stack_analysis":  "",
    }