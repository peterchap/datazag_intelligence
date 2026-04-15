# narrative.py

import os
import json
import aiohttp
from aiohttp import TCPConnector
from aiohttp.resolver import ThreadedResolver
from typing import Optional


async def enrich_with_narrative(
    domain: str,
    score: int,
    risk_band: str,
    findings: list[dict],
    output: dict,
    partner_context: Optional[str] = None,
    threat_context: Optional[str] = None,
    audience: str = "insurer",
) -> dict:

    AUDIENCE_TONE = {
        "insurer":    "a cyber insurance underwriter assessing policy risk and making underwriting decisions",
        "consultant": "a senior security consultant preparing a detailed technical briefing for a client",
        "it":         "an IT security manager reviewing their own organisation's infrastructure posture",
        "sales":      "a sales team preparing a compelling prospect outreach brief",
    }

    ea       = output.get("email_auth", {})
    tech     = output.get("technographics", {})
    ti       = output.get("txt_intelligence", {})
    certs    = output.get("certificates", {})
    infra    = output.get("infrastructure", {})
    labels   = output.get("labels", {})
    flags    = output.get("threat_flags", {})
    changes  = output.get("change_signals", {})
    dns      = output.get("dns_records", {})
    risk_eng = output.get("risk_score_engine", {})
    cs_raw   = output.get("composite_score", {})
    cs       = cs_raw if isinstance(cs_raw, dict) else {"score": cs_raw}

    findings_detail = "\n".join(
        f"  [{f['severity'].upper()}] {f['title']}\n"
        f"    Evidence: {f.get('evidence','')[:120]}\n"
        f"    Detail: {f.get('detail','')[:200]}\n"
        f"    Fix: {(f.get('remediation') or '')[:120]}"
        for f in sorted(
            findings,
            key=lambda x: ["critical","high","medium","info"].index(
                x.get("severity","info")
            )
        )
    )

    rules_detail = "\n".join(
        f"  {'+' if r['points']>0 else ''}{r['points']:+d}  {r['rule']}"
        for r in risk_eng.get("rules", [])
    )

    saas_all = ti.get("all_identified", [])
    high_risk_saas = [
        s for s in saas_all
        if any(k in s.lower() for k in ("lastpass","okta","twilio","mailchimp","circleci"))
    ]

    missing_layers_prompt = "\n".join(filter(None, [
        f"- NO SPF RECORD: Any server can send as @{domain}" if not ea.get('spf_raw') else "",
        "- NO DMARC: No spoofing protection policy" if not ea.get('dmarc_policy') else "",
        f"- DMARC p={ea.get('dmarc_policy')} (not reject): Partial enforcement only" if ea.get('dmarc_policy') and ea.get('dmarc_policy') != 'reject' else "",
        "- NO MTA-STS: SMTP downgrade attacks possible" if ea.get('mta_sts') in ('NXDOMAIN','NOT_FOUND','NODATA') else "",
        "- NO TLS-RPT: No SMTP TLS failure visibility" if ea.get('tls_rpt') in ('NXDOMAIN','NOT_FOUND','NODATA') else "",
        "- NO BIMI: Brand logo not shown in email clients" if ea.get('bimi') in ('NOT_FOUND','NXDOMAIN','NODATA') else "",
        "- NO DNSSEC: DNS responses unsigned" if not ea.get('dnssec') else "",
        "- NO CAA RECORDS: Any CA can issue certificates" if not flags.get('has_caa') else "",
        "- NO SECURITY.TXT: No responsible disclosure policy" if not flags.get('has_security_txt') else "",
    ]))

    prompt = f"""You are producing a detailed DNS intelligence report for {AUDIENCE_TONE[audience]}.

DOMAIN: {domain}
SCANNED: {output.get('scanned_at','')}
{f'PARTNER CONTEXT: {partner_context}' if partner_context else ''}
{f'THREAT CONTEXT: {threat_context}' if threat_context else ''}

=== COMPOSITE RISK SCORE ===
Score: {score}/100 ({risk_band})
Confidence: {cs.get('confidence','?')}
Primary driver: {cs.get('primary_driver','?')}
Components: {json.dumps(cs.get('components',{}), indent=2)}
Nudges applied:
  MX provider: {cs.get('nudges',{}).get('mx_provider','?')} (trust nudge: {cs.get('nudges',{}).get('mx_trust_nudge',0):+.1f}, risk bias: {cs.get('nudges',{}).get('mx_risk_bias',0):+.1f})
  ASN risk level: {cs.get('nudges',{}).get('asn_risk_level','?')}
  TLD risk: {cs.get('nudges',{}).get('tld_risk','?')} (adjustment: {cs.get('nudges',{}).get('tld_adjustment',0):+.1f})

=== RULE ENGINE BREAKDOWN ===
Score: {risk_eng.get('score',0)}/100 ({risk_eng.get('bucket','?')}) — config {risk_eng.get('config_version','?')}
Rules:
{rules_detail}

=== EMAIL AUTHENTICATION ===
SPF: {ea.get('spf_raw','NOT FOUND')}
  Mechanism: {ea.get('spf','?')} | Strictness: {ea.get('spf_strictness','?')}
  Includes: {', '.join(ea.get('spf_includes',[]))}
  IP4 ranges: {', '.join(ea.get('spf_ip4_ranges',[]))}
DMARC: {ea.get('dmarc_raw','NOT FOUND')}
  Policy: {ea.get('dmarc_policy','missing')} | pct={ea.get('dmarc_pct',0)}
  aspf={ea.get('aspf','?')} adkim={ea.get('adkim','?')} fo={ea.get('dmarc_fo','?')}
  RUA: {ea.get('dmarc_rua','none')} | RUF: {ea.get('dmarc_ruf','none')}
MTA-STS: {ea.get('mta_sts','?')} (mode: {ea.get('mta_sts_mode') or 'not configured'})
TLS-RPT: {ea.get('tls_rpt','?')}
BIMI: {ea.get('bimi','?')}
DNSSEC: {ea.get('dnssec','?')}
Is spoofable: {ea.get('is_spoofable',False)} (severity: {ea.get('spoofing_severity','?')})
Fully authenticated: {ea.get('is_fully_authenticated',False)}
Missing layers: {', '.join(ea.get('missing_layers',[]) or ['none'])}

=== TECHNOGRAPHICS ===
MX provider: {tech.get('mx_provider_name','?')} — category: {tech.get('mx_mbp_category','?')}
NS provider: {tech.get('ns_provider_name','?')} — category: {tech.get('ns_provider_category','?')}
ISP: {tech.get('isp_name','?')} ({tech.get('isp_country','?')}) — ASN: {tech.get('asn','?')}
ASN risk level: {tech.get('asn_risk_level','?')}
TLD risk: {tech.get('tld_risk_level','?')} ({tech.get('tld_country','?')})
Net trust score: {tech.get('net_trust_score',0):+.1f}
CDN/UGC: {tech.get('is_cdn_ugc',False)}

SaaS stack ({ti.get('total_identified',0)} services identified):
  All: {', '.join(saas_all) if saas_all else 'none'}
  Identity: {', '.join(ti.get('identity_providers',[]))}
  AI infrastructure: {', '.join(ti.get('ai_infrastructure',[]))}
  Payment: {', '.join(ti.get('payment_processors',[]))}
  Security tooling: {', '.join(ti.get('security_tooling',[]))}
  HIGH RISK (known breaches): {', '.join(high_risk_saas) if high_risk_saas else 'none'}
  Anomalous TXT records: {json.dumps(ti.get('anomalous_records',[]))}

=== CERTIFICATES ===
HTTPS: {certs.get('https_issuer_org','?')} ({certs.get('https_label','?')})
  Days remaining: {certs.get('https_days_left','?')} {'— EXPIRING SOON' if certs.get('https_expiring') else ''}
  SANs: {certs.get('https_san_count','?')} | Let's Encrypt: {certs.get('https_lets_encrypt','?')}
SMTP: {certs.get('smtp_issuer_org','?')}
  Days remaining: {certs.get('smtp_days_left','?')}
  Banner: {certs.get('smtp_banner','none')}
  Provider live confirmed: {certs.get('provider_live',False)}

=== INFRASTRUCTURE ===
IPv6 dual-stack: {infra.get('dual_stack',False)}
A records: {', '.join(dns.get('a',[]))}
AAAA records: {', '.join(dns.get('aaaa',[]))}
MX records: {', '.join(f"{r['priority']}:{r['host']}" for r in dns.get('mx',[]))}
NS records: {', '.join(dns.get('ns',[]))}
CAA records: {', '.join(dns.get('caa',[])) or 'NONE'}
TXT records ({len(dns.get('txt',[]))} total):
{chr(10).join('  ' + t for t in dns.get('txt',[]))}

=== LABELS ===
DMARC policy label: {labels.get('dmarc_policy','?')}
SPF strictness label: {labels.get('spf_strictness','?')}
TTL bucket: {labels.get('ttl_bucket','?')}
SSL issuer label: {labels.get('ssl_issuer','?')}
Active infrastructure: {labels.get('active_infrastructure','?')}

=== THREAT FLAGS ===
Phishing: {flags.get('is_phishing',False)}
Malware: {flags.get('is_malware',False)}
New domain: {flags.get('is_new_domain',False)}
Security.txt: {flags.get('has_security_txt',False)}
CAA records: {flags.get('has_caa',False)}

=== CHANGE SIGNALS ===
NS changed: {changes.get('ns_changed',False)}
IP changed: {changes.get('ip_changed',False)}
Country changed: {changes.get('country_changed',False)}
TTL big drop: {changes.get('ttl_drop_big',False)}
Dynamic DNS: {changes.get('is_dynamic_dns',False)}
MX misconfigured: {changes.get('mx_misconfigured',False)}
Parking points: {changes.get('parking_points',0)}

=== MISSING SECURITY LAYERS — DISCUSS EACH IN NARRATIVE ===
{missing_layers_prompt}

For each missing layer above, explain:
1. The specific attack scenario
2. What an attacker can do because it is missing
3. The specific DNS record needed to fix it

=== ALL FINDINGS ===
{findings_detail}
---

Return ONLY a valid JSON object with exactly these fields:

{{
  "key_finding": "The single most important finding in one precise sentence. Reference specific evidence.",
  "executive_summary": "3-4 sentences. Lead with composite score and primary driver. Name specific services and risk signals.",
  "threat_narrative": "5-8 sentences of deep interpretive analysis connecting findings to real threat scenarios. Reference specific DNS evidence throughout.",
  "positive_signals": "2-3 sentences identifying what this domain does well. Name specific providers, policies, and score contributions.",
  "remediation_priority": "For each critical or high finding, one sentence with the specific fix and expected impact. Numbered list.",
  "insurer_signals": "3-4 sentences translating technical findings into policy risk language. Mention attack vectors, likely claim types, premium implications.",
  "saas_stack_analysis": "2-3 sentences on the SaaS stack breadth, any high-risk services, what it reveals about the organisation, supply chain implications."
}}"""

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
    }

    data = None

    # Primary attempt
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json={
                    "model":      "claude-sonnet-4-20250514",
                    "max_tokens": 3000,
                    "messages":   [{"role": "user", "content": prompt}],
                },
            ) as resp:
                data = await resp.json()

    except aiohttp.ClientConnectorDNSError:
        # DNS fallback — use threaded resolver
        connector = TCPConnector(resolver=ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json={
                    "model":      "claude-sonnet-4-20250514",
                    "max_tokens": 3000,
                    "messages":   [{"role": "user", "content": prompt}],
                },
            ) as resp:
                data = await resp.json()

    if not data:
        return _empty_narrative()

    text = data["content"][0]["text"].strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "key_finding":          text[:200],
            "executive_summary":    "",
            "threat_narrative":     "",
            "positive_signals":     "",
            "remediation_priority": "",
            "insurer_signals":      "",
            "saas_stack_analysis":  "",
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