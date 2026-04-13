# run.py
"""
Entry point. Run against any Datazag DNS JSON file:

    python run.py guardian.json
    python run.py atlassian.json --audience insurer
    python run.py adaptavist.json --partner "Atlassian Platinum Partner" \
                                  --threat "Atlassian ransom demand April 2026"

Outputs JSON + Markdown + HTML for each audience to ./output/<domain>/
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from adapter import DatazagCanonicalAdapter
from findings import passive_security_findings_v2
from scorer import DatazagCompositeScorer, NormalisedAnnotation
from narrative import enrich_with_narrative


async def run(
    dns_file: str,
    audience: str = "insurer",
    partner_context: str = None,
    threat_context: str = None,
    skip_narrative: bool = False,
) -> dict:

    # 1. Load raw record
    with open(dns_file) as f:
        raw = json.load(f)

    domain = raw.get("domain", "unknown")
    print(f"\n  Analysing {domain}...")

    # 2. Parse canonical record
    adapter = DatazagCanonicalAdapter(raw)
    record  = adapter.parse()
    print(f"  Parsed — {len(record.txt_records)} TXT records, "
          f"IPv6: {record.is_dual_stack}, "
          f"MX: {record.annotation.mx_provider_name or 'none'}")

    # 3. Generate passive findings
    findings = passive_security_findings_v2(record)
    critical = [f for f in findings if f["severity"] == "critical"]
    high     = [f for f in findings if f["severity"] == "high"]
    print(f"  Findings — {len(critical)} critical, {len(high)} high, "
          f"{len(findings)} total")

    # 4. Compute composite score using inline annotation
    scorer     = DatazagCompositeScorer()
    annotation = NormalisedAnnotation.from_raw(raw)

    # Build a minimal domain score from inline fields
    from scorer import NormalisedDomainScore
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
            ["phishing"] * record.is_phishing +
            ["malware"]  * record.is_malware
        ),
    )

    composite = scorer.compute(
        domain=domain,
        dns_posture_score=record.risk.score,
        email_spoof_score={
            "critical": 100, "high": 70,
            "medium": 40, "none": 5,
        }.get(record.email_auth.spoofing_severity, 20),
        ip_score=None,            # No separate IP lookup needed — inline
        domain_score=domain_score,
        annotation=annotation,
    )
    print(f"  Score — {composite.composite_score}/100 "
          f"({composite.risk_band}) | confidence: {composite.confidence}")
    print(f"  Driver — {composite.primary_driver}")

    # 5. Narrative enrichment (Claude API)
    narrative = {}
    if not skip_narrative and os.environ.get("ANTHROPIC_API_KEY"):
        print(f"  Generating narrative ({audience} audience)...")
        email_summary = (
            f"SPF {record.email_auth.spf_all_mechanism}, "
            f"DMARC p={record.email_auth.dmarc_policy or 'missing'}, "
            f"spoofable: {record.email_auth.is_spoofable}"
        )
        saas = record.annotation.mx_provider_name and \
               [record.annotation.mx_provider_name] or []
        
        narrative = await enrich_with_narrative(
            domain=domain,
            score=composite.composite_score,
            risk_band=composite.risk_band,
            findings=findings,
            saas_stack=saas,
            email_auth_summary=email_summary,
            partner_context=partner_context,
            threat_context=threat_context,
            audience=audience,
        )
        print(f"  Key finding: {narrative.get('key_finding','')[:80]}...")
    elif not os.environ.get("ANTHROPIC_API_KEY"):
        print("  Skipping narrative — ANTHROPIC_API_KEY not set")

    # 6. Assemble output
    output = {
        "domain":        domain,
        "scanned_at":    record.scanned_at,
        "generated_at":  datetime.utcnow().isoformat() + "Z",
        "audience":      audience,
        "composite_score": {
            "score":          composite.composite_score,
            "risk_band":      composite.risk_band,
            "confidence":     composite.confidence,
            "primary_driver": composite.primary_driver,
            "components":     composite.score_components,
            "nudges": {
                "mx_provider":    record.annotation.mx_provider_name,
                "mx_trust_nudge": composite.mx_trust_nudge_applied,
                "asn_risk_level": record.annotation.asn_risk_level,
                "tld_risk":       record.annotation.tld_risk_level,
            },
        },
        "risk_score_breakdown": [
            {"rule": r.rule, "points": r.points}
            for r in record.risk.reasons
        ],
        "email_auth": {
            "spf":              record.email_auth.spf_all_mechanism,
            "dmarc_policy":     record.email_auth.dmarc_policy,
            "dmarc_pct":        record.email_auth.dmarc_pct,
            "aspf":             record.email_auth.dmarc_aspf,
            "adkim":            record.email_auth.dmarc_adkim,
            "mta_sts":          record.email_auth.mta_sts_status,
            "tls_rpt":          record.email_auth.tls_rpt_status,
            "bimi":             record.email_auth.bimi_status,
            "is_spoofable":     record.email_auth.is_spoofable,
            "missing_layers":   record.email_auth.missing_layers,
        },
        "infrastructure": {
            "cdn":              record.annotation.mx_provider_name,
            "isp":              record.annotation.isp_name,
            "asn":              record.annotation.asn,
            "dual_stack":       record.is_dual_stack,
            "mx_provider":      record.annotation.mx_provider_name,
            "mx_category":      record.annotation.mx_mbp_category,
            "ns_provider":      record.annotation.ns_provider_name,
        },
        "certificates": {
            "https_days_left":  record.https_cert.days_remaining if record.https_cert else None,
            "https_issuer":     record.https_cert.issuer_org if record.https_cert else None,
            "https_expiring":   record.https_cert.is_expiring_soon if record.https_cert else None,
            "smtp_days_left":   record.smtp.cert.days_remaining if record.smtp.cert else None,
            "smtp_banner":      record.smtp.banner_raw,
            "provider_live":    record.smtp.provider_confirmed,
        },
        "change_signals": {
            "any_change":       record.changes.any_change_signal,
            "any_threat":       record.changes.any_threat_signal,
            "ns_changed":       record.changes.ns_changed,
            "ip_changed":       record.changes.ip_changed,
        },
        "findings": findings,
        "narrative": narrative,
    }

    # 7. Write output files
    out_dir = Path("output") / domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    json_path = out_dir / f"{audience}.json"
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    # Markdown
    md_path = out_dir / f"{audience}.md"
    with open(md_path, "w") as f:
        f.write(_to_markdown(output))

    print(f"\n  Output written to {out_dir}/")
    print(f"    {json_path}")
    print(f"    {md_path}")

    return output


def _to_markdown(o: dict) -> str:
    cs = o["composite_score"]
    ea = o["email_auth"]
    n  = o.get("narrative", {})

    lines = [
        f"# Intelligence brief — {o['domain']}",
        f"*{o['generated_at']} · {o['audience']} view*",
        "",
    ]

    if n.get("key_finding"):
        lines += [f"> {n['key_finding']}", ""]

    lines += [
        f"## Score: {cs['score']}/100 — {cs['risk_band'].upper()}",
        f"Confidence: {cs['confidence']} · Primary driver: {cs['primary_driver']}",
        "",
        "| Component | Score |",
        "|-----------|-------|",
    ]
    for k, v in cs.get("components", {}).items():
        lines.append(f"| {k.replace('_', ' ').title()} | {v} |")

    lines += [
        "",
        "## Email security",
        f"- SPF: `{ea['spf']}`",
        f"- DMARC: `p={ea['dmarc_policy'] or 'missing'}`"
        + (f" pct={ea['dmarc_pct']}" if ea["dmarc_policy"] else ""),
        f"- Spoofable: {'YES' if ea['is_spoofable'] else 'No'}",
        f"- Missing: {', '.join(ea['missing_layers']) or 'nothing critical'}",
        "",
        "## Findings",
        "",
    ]

    for sev in ["critical", "high", "medium", "info"]:
        fs = [f for f in o["findings"] if f.get("severity") == sev]
        if fs:
            lines.append(f"### {sev.upper()}")
            for f in fs:
                lines += [
                    f"**{f['title']}**  ",
                    f"{f.get('detail', '')}  ",
                    f"*Fix: {f.get('remediation', 'n/a')}*",
                    "",
                ]

    if n.get("threat_narrative"):
        lines += ["## Threat narrative", "", n["threat_narrative"], ""]

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag DNS Intelligence Engine")
    parser.add_argument("file",    help="Path to Datazag DNS JSON file")
    parser.add_argument("--audience",  default="insurer",
                        choices=["insurer","consultant","it","sales"])
    parser.add_argument("--partner",   default=None,
                        help="Partner context e.g. 'Atlassian Platinum Partner'")
    parser.add_argument("--threat",    default=None,
                        help="Threat context e.g. 'Subject of ransom demand'")
    parser.add_argument("--no-narrative", action="store_true",
                        help="Skip Claude API call (faster, no cost)")
    args = parser.parse_args()

    asyncio.run(run(
        dns_file=args.file,
        audience=args.audience,
        partner_context=args.partner,
        threat_context=args.threat,
        skip_narrative=args.no_narrative,
    ))