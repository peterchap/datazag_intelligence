"""
renderers.py
------------
Four audience renderers that operate on the output dict
produced by run.py — no SubdomainReport dependency.
Works directly from CanonicalDNSRecord + findings + composite score.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional
from branding import BrandConfig


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

RISK_COLOURS = {
    "critical": {"bg": "#FCEBEB", "text": "#791F1F", "border": "#A32D2D"},
    "high":     {"bg": "#FAEEDA", "text": "#633806", "border": "#854F0B"},
    "medium":   {"bg": "#E6F1FB", "text": "#0C447C", "border": "#185FA5"},
    "info":     {"bg": "#EAF3DE", "text": "#27500A", "border": "#3B6D11"},
}

_SEV_ORDER = {
    "critical": 0, "high": 1, "elevated": 2,
    "medium": 3,   "low": 4,  "info": 5,
}

RISK_BAND_COLOUR = {
    "critical": "#A32D2D",
    "high":     "#854F0B",
    "medium":   "#185FA5",
    "low":      "#3B6D11",
}

def _fmt_int(val) -> str:
    """Format integer with comma separator, return '—' for None/non-int."""
    return f"{val:,}" if isinstance(val, int) else '—'

def _badge(severity: str) -> str:
    c = RISK_COLOURS.get(severity, RISK_COLOURS["info"])
    return (
        f'<span style="background:{c["bg"]};color:{c["text"]};'
        f'padding:2px 8px;border-radius:4px;font-size:11px;'
        f'font-weight:600;text-transform:uppercase">{severity}</span>'
    )


def _score_bar(score: int, invert: bool = True) -> str:
    if invert:
        colour = "#A32D2D" if score >= 75 else "#854F0B" if score >= 40 else "#3B6D11"
    else:
        colour = "#3B6D11" if score >= 75 else "#854F0B" if score >= 40 else "#A32D2D"
    return (
        f'<div style="background:#eee;border-radius:3px;height:6px;width:100%;margin:4px 0">'
        f'<div style="background:{colour};width:{score}%;height:100%;border-radius:3px"></div></div>'
    )


def _findings_table(findings: list[dict], columns: list[tuple], max_rows: int = 50) -> str:
    th = ('style="text-align:left;padding:8px 12px;font-size:11px;font-weight:600;'
          'border-bottom:1px solid #e0e0e0;color:#666;text-transform:uppercase;'
          'letter-spacing:.04em;white-space:nowrap"')
    td = ('style="padding:7px 12px;font-size:12px;border-bottom:1px solid #f5f5f5;vertical-align:top"')

    headers = "".join(f"<th {th}>{label}</th>" for label, _ in columns)
    rows = ""
    for i, f in enumerate(findings[:max_rows]):
        bg = ' style="background:#fafafa"' if i % 2 == 0 else ""
        cells = "".join(f"<td {td}>{fn(f)}</td>" for _, fn in columns)
        rows += f"<tr{bg}>{cells}</tr>"

    overflow = ""
    if len(findings) > max_rows:
        overflow = (
            f'<p style="font-size:12px;color:#888;margin:8px 0 0">'
            f'+ {len(findings) - max_rows} additional findings omitted</p>'
        )
    return (
        f'<div style="overflow-x:auto">'
        f'<table style="width:100%;border-collapse:collapse">'
        f'<thead><tr>{headers}</tr></thead>'
        f'<tbody>{rows}</tbody></table></div>{overflow}'
    )

# ---------------------------------------------------------------------------
# Base renderer
# ---------------------------------------------------------------------------

class BaseRenderer:
    def __init__(self, output: dict):
        self.o           = output
        self.domain      = output["domain"]
        self.cs          = output["composite_score"]
        self.ea          = output["email_auth"]
        self.infra       = output["infrastructure"]
        self.certs       = output["certificates"]
        self.findings    = output.get("findings", [])
        self.narrative   = output.get("narrative", {})
        self.changes     = output.get("change_signals", {})
        self.score_breakdown = output.get("risk_score_breakdown", [])
        self.dns         = output.get("dns_records", {})
        self.subdomains  = output.get("subdomains", [])
        self.cert_analysis = output.get("cert_analysis", {})
        self.rdap        = output.get("rdap", {})
        self.tech        = output.get("technographics", {})
        self.labels      = output.get("labels", {})
        self.flags       = output.get("threat_flags", {})
        self.txt_intel   = output.get("txt_intelligence", {})
        self.risk_engine = output.get("risk_score_engine", {})
        self.display_score     = output.get("display_score", self.cs["score"])
        self.display_risk_band = output.get("display_risk_band", self.cs["risk_band"])
        self.cyber_profile     = output.get("cyber_risk_profile", {})

    # --- Branding -----------------------------------------------------------

    def _html_header(self, brand: "BrandConfig", report_type: str) -> str:
        # User requested Datazag branding with an option to include customer's logo.
        datazag_logo = """<svg height="36" viewBox="0 0 160 36" xmlns="http://www.w3.org/2000/svg">
          <text x="0" y="26" font-family="'Inter', sans-serif" font-size="24" font-weight="800" letter-spacing="-1" fill="#FFFFFF">DATAZAG</text>
        </svg>"""
        customer_logo = brand.wordmark_svg(height=28) if (brand.brand_name != "Datazag" or brand.logo_svg) else ""
        return f"""
        <div class="print-header">
            <div style="display: flex; align-items: center; gap: 20px;">
                <div class="brand-logo">{datazag_logo}</div>
                <div style="border-left: 1px solid rgba(255,255,255,0.25); height: 30px;"></div>
                <div style="display: flex; flex-direction: column;">
                    <div style="color: rgba(255,255,255,0.7); font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600;">{brand.report_prefix}</div>
                    <div style="color: #FFFFFF; font-size: 14px; font-weight: 500; letter-spacing: 0.02em;">{report_type}</div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 24px; text-align: right;">
                {f'<div class="customer-logo" style="opacity: 0.9;">{customer_logo}</div>' if customer_logo else ''}
                <div style="display: flex; flex-direction: column; align-items: flex-end;">
                    <div style="color: {brand.accent_colour}; font-size: 18px; font-weight: 700; letter-spacing: -0.02em;">{self.domain}</div>
                    <div style="color: rgba(255,255,255,0.6); font-size: 11px; margin-top: 2px;">{self.o.get('generated_at','')[:10]}</div>
                </div>
            </div>
        </div>"""

    def _html_contact_block(self, brand: "BrandConfig") -> str:
        return f"""
        <div class="contact-block avoid-break">
            <div class="contact-col">
                <div class="contact-heading">Questions about this report?</div>
                <div class="contact-item"><span class="contact-label">Email:</span> <span class="contact-value">{brand.contact_email}</span></div>
                {f'<div class="contact-item"><span class="contact-label">Phone:</span> <span class="contact-value">{brand.contact_phone}</span></div>' if brand.contact_phone else ''}
                <div class="contact-item"><span class="contact-label">Web:</span> <span class="contact-value">{brand.contact_web}</span></div>
            </div>
            <div class="cta-col">
                <div class="cta-heading">{brand.cta_heading}</div>
                <div class="cta-body">{brand.cta_body}</div>
            </div>
        </div>"""

    def _html_footer(self, brand: "BrandConfig") -> str:
        footer_text = "" if brand.is_white_label else brand.report_footer
        return f"""
        <div class="print-footer avoid-break">
            <div class="footer-notice">{brand.confidentiality_notice}</div>
            {f'<div class="footer-text">{footer_text}</div>' if footer_text else ''}
        </div>"""

    def _html_shell_branded(self, brand: "BrandConfig", report_type: str, body: str) -> str:
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{brand.report_prefix} — {self.domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
    /* CSS Reset & Base */
    * {{ box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    @page {{ size: A4; margin: 0; }}
    body {{
        font-family: 'Inter', sans-serif;
        font-size: 12px;
        color: #1E293B;
        margin: 0;
        padding: 0;
        background: #F8FAFC;
        line-height: 1.5;
    }}
    .page-container {{
        background: #FFFFFF;
        margin: 0 auto;
        padding: 40px 50px;
        min-height: 297mm;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    
    /* Typography */
    h1 {{ font-size: 24px; font-weight: 700; margin: 0 0 12px; letter-spacing: -0.03em; color: #0F172A; }}
    h2 {{ font-size: 13px; font-weight: 700; margin: 32px 0 16px; text-transform: uppercase; letter-spacing: 0.08em; color: {brand.primary_colour}; border-bottom: 2px solid {brand.accent_colour}; padding-bottom: 8px; page-break-after: avoid; }}
    h3 {{ font-size: 14px; font-weight: 600; margin: 20px 0 10px; color: #334155; page-break-after: avoid; }}
    .meta {{ font-size: 11px; color: #64748B; margin: 0 0 24px }}
    code {{ font-family: 'JetBrains Mono', monospace; font-size: 10px; background: #F1F5F9; padding: 2px 6px; border-radius: 4px; color: #334155; }}
    a {{ color: {brand.accent_dark}; text-decoration: none; }}
    
    /* Header */
    .print-header {{
        background: linear-gradient(135deg, {brand.primary_colour} 0%, #1E293B 100%);
        margin: -40px -50px 32px;
        padding: 32px 50px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 4px solid {brand.accent_colour};
    }}
    
    /* Grid & Cards */
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 16px 0 24px; }}
    .card {{ background: #F8FAFC; border-radius: 8px; padding: 16px; border: 1px solid #E2E8F0; border-top: 3px solid {brand.accent_colour}; break-inside: avoid; }}
    .card .num {{ font-size: 28px; font-weight: 800; line-height: 1; color: #0F172A; letter-spacing: -0.02em; }}
    .card .lbl {{ font-size: 10px; color: #64748B; margin-top: 6px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }}
    
    /* Tables */
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 11px; margin-bottom: 24px; border-radius: 8px; overflow: hidden; border: 1px solid #E2E8F0; }}
    th {{ background: #F1F5F9; padding: 10px 12px; text-align: left; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: #475569; border-bottom: 1px solid #E2E8F0; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #F1F5F9; color: #334155; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:nth-child(even) td {{ background-color: #F8FAFC; }}
    
    /* Alerts & Signals */
    .signal {{ border-left: 4px solid; padding: 12px 16px; margin: 12px 0; border-radius: 0 8px 8px 0; font-size: 12px; line-height: 1.5; background: #FFF; box-shadow: 0 1px 3px rgba(0,0,0,0.05); break-inside: avoid; }}
    
    /* Print Utilities */
    .avoid-break {{ page-break-inside: avoid; break-inside: avoid; }}
    .page-break {{ page-break-before: always; break-before: page; }}
    
    /* Footer / Contact */
    .contact-block {{ display: grid; grid-template-columns: 1fr 1.2fr; gap: 32px; margin-top: 48px; padding-top: 32px; border-top: 2px solid #E2E8F0; }}
    .contact-heading {{ font-size: 14px; font-weight: 700; color: #0F172A; margin-bottom: 16px; }}
    .contact-item {{ font-size: 11px; margin-bottom: 8px; }}
    .contact-label {{ color: #64748B; display: inline-block; width: 50px; }}
    .contact-value {{ color: #0F172A; font-weight: 500; }}
    .cta-col {{ background: #F8FAFC; border-radius: 12px; padding: 20px; border-left: 4px solid {brand.accent_colour}; }}
    .cta-heading {{ font-size: 14px; font-weight: 700; color: #0F172A; margin-bottom: 8px; }}
    .cta-body {{ font-size: 11px; color: #475569; line-height: 1.6; margin-bottom: 0; }}
    
    .print-footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #E2E8F0; text-align: center; }}
    .footer-notice {{ font-size: 10px; color: #94A3B8; font-weight: 500; }}
    .footer-text {{ font-size: 9px; color: #CBD5E1; margin-top: 4px; }}
    </style>
    </head>
    <body>
    <div class="page-container">
        {self._html_header(brand, report_type)}
        <div class="content-body">
            {body}
        </div>
        {self._html_contact_block(brand)}
        {self._html_footer(brand)}
    </div>
    </body>
    </html>"""

    # --- Shared markdown builders -------------------------------------------

    def _dns_records_md(self) -> str:
        lines = ["## DNS records", ""]
        for rtype, records in self.dns.items():
            if not records:
                continue
            vals = [f"{r['priority']}:{r['host']}" for r in records] if rtype == "mx" else records
            lines.append(f"**{rtype.upper()}**")
            for v in vals:
                lines.append(f"  - `{v}`")
            lines.append("")
        return "\n".join(lines)

    def _technographics_md(self) -> str:
        t, ti = self.tech, self.txt_intel
        lines = [
            "## Technographics", "",
            "| Signal | Value |", "|--------|-------|",
            f"| MX provider | {t.get('mx_provider_name') or '—'} ({t.get('mx_mbp_category') or '—'}) |",
            f"| MX trust nudge | {t.get('mx_trust_nudge',0):+.1f} |",
            f"| MX risk bias | {t.get('mx_risk_bias',0):+.1f} |",
            f"| NS provider | {t.get('ns_provider_name') or '—'} ({t.get('ns_provider_category') or '—'}) |",
            f"| ISP | {t.get('isp_name') or '—'} ({t.get('isp_country') or '—'}) |",
            f"| ASN | AS{t.get('asn') or '—'} — risk: {t.get('asn_risk_level') or '—'} |",
            f"| TLD risk | {t.get('tld_risk_level') or '—'} |",
            f"| Net trust score | {t.get('net_trust_score',0):+.1f} |",
            f"| CDN/UGC | {'Yes' if t.get('is_cdn_ugc') else 'No'} |",
            f"| Hosting CDN | {'Yes' if t.get('is_hosting_cdn') else 'No'} |",
            "", "### SaaS stack", "",
        ]
        if ti.get("all_identified"):
            for svc in ti["all_identified"]:
                lines.append(f"- {svc}")
        else:
            lines.append("- No services identified from TXT records")
        if ti.get("anomalous_records"):
            lines += ["", "### Anomalous TXT records", ""]
            for a in ti["anomalous_records"]:
                lines.append(f"- `{a}`")
        return "\n".join(lines)

    def _risk_breakdown_md(self) -> str:
        re = self.risk_engine
        lines = [
            "## Risk score breakdown", "",
            f"Score: **{re.get('score',0)}/100** ({re.get('bucket','?')}) — config {re.get('config_version','?')}",
            "", "| Rule | Points |", "|------|--------|",
        ]
        for r in re.get("rules", []):
            sign = f"+{r['points']}" if r["points"] > 0 else str(r["points"])
            lines.append(f"| {r['rule']} | {sign} |")
        return "\n".join(lines)

    def _labels_md(self) -> str:
        lbl, flags = self.labels, self.flags
        lines = [
            "## Labels and flags", "",
            "| Label | Value |", "|-------|-------|",
            f"| DMARC policy | {lbl.get('dmarc_policy') or '—'} |",
            f"| SPF strictness | {lbl.get('spf_strictness') or '—'} |",
            f"| TTL bucket | {lbl.get('ttl_bucket') or '—'} |",
            f"| SSL issuer | {lbl.get('ssl_issuer') or '—'} |",
            f"| Active infrastructure | {'Yes' if lbl.get('active_infrastructure') else 'No'} |",
            f"| Is phishing | {'YES' if flags.get('is_phishing') else 'No'} |",
            f"| Is malware | {'YES' if flags.get('is_malware') else 'No'} |",
            f"| Is new domain | {'Yes' if flags.get('is_new_domain') else 'No'} |",
            f"| Has security.txt | {'Yes' if flags.get('has_security_txt') else 'No'} |",
            f"| Has CAA | {'Yes' if flags.get('has_caa') else 'No'} |",
        ]
        return "\n".join(lines)

    def _certs_md(self) -> str:
        c = self.certs
        lines = [
            "## Certificates", "", "| Field | Value |", "|-------|-------|",
            f"| HTTPS issuer | {c.get('https_issuer_org') or '—'} (`{c.get('https_label') or '—'}`) |",
            f"| HTTPS days left | {c.get('https_days_left') or '—'} {'⚠ EXPIRING SOON' if c.get('https_expiring') else ''} |",
            f"| HTTPS SANs | {c.get('https_san_count') or '—'} |",
            f"| SMTP issuer | {c.get('smtp_issuer_org') or '—'} |",
            f"| SMTP days left | {c.get('smtp_days_left') or '—'} |",
            f"| SMTP banner | `{c.get('smtp_banner') or '—'}` |",
            f"| Provider live | {'Confirmed' if c.get('provider_live') else 'Not verified'} |",
        ]
        return "\n".join(lines)

    def _changes_md(self) -> str:
        ch = self.changes
        lines = [
            "## Change signals", "", "| Signal | Status |", "|--------|--------|",
            f"| NS changed | {'YES ⚠' if ch.get('ns_changed') else 'No'} |",
            f"| IP changed | {'YES ⚠' if ch.get('ip_changed') else 'No'} |",
            f"| Country changed | {'YES ⚠' if ch.get('country_changed') else 'No'} |",
            f"| TTL big drop | {'YES ⚠' if ch.get('ttl_drop_big') else 'No'} |",
            f"| Dynamic DNS | {'YES ⚠' if ch.get('is_dynamic_dns') else 'No'} |",
            f"| MX misconfigured | {'YES ⚠' if ch.get('mx_misconfigured') else 'No'} |",
            f"| Parking points | {ch.get('parking_points', 0)} |",
        ]
        return "\n".join(lines)

    def _rdap_md(self) -> str:
        rdap = self.rdap
        if not rdap.get("rdap_available"):
            return ""
        lines = [
            "## Domain registration", "",
            "| Field | Value |", "|-------|-------|",
            f"| Registrar | {rdap.get('registrar_name', '—')} |",
            f"| Registrar risk | {rdap.get('registrar_label', '—')} |",
            f"| Registered | {rdap.get('registered', '—')} |",
            f"| Expires | {rdap.get('expires', '—')} |",
            f"| Days to expiry | {rdap.get('days_to_expiry', '—')} |",
            f"| Domain age | {rdap.get('domain_age_days', '—')} days |",
            f"| DNSSEC | {'enabled' if rdap.get('dnssec_enabled') else 'not enabled'} |",
            f"| Abuse contact | {rdap.get('abuse_email') or 'not found'} |",
            f"| RDAP risk score | {rdap.get('rdap_risk_score', 0)} |",
        ]
        reasons = rdap.get("rdap_risk_reasons", [])
        if reasons:
            lines += ["", "**Registration risk signals:**"]
            for r in reasons:
                lines.append(f"- {r}")
        return "\n".join(lines)

    def _cert_analysis_md(self) -> str:
        summary = self.cert_analysis.get("summary", {})
        if not summary:
            return ""
        lines = [
            "## Certificate intelligence", "",
            "| Metric | Value |", "|--------|-------|",
            f"| Total subdomains | {summary.get('total_unique_subdomains', 0)} |",
            f"| Wildcard zones | {summary.get('wildcard_zones', 0)} |",
            f"| Expiring within 30d | {summary.get('expiring_within_30d', 0)} |",
            f"| Expiring within 60d | {summary.get('expiring_within_60d', 0)} |",
            f"| Expired | {summary.get('expired', 0)} |",
            f"| Missed renewals | {summary.get('missed_renewals', 0)} |",
            f"| Cross-domain SANs | {summary.get('cross_domain_sans', 0)} |",
            f"| High churn subdomains | {summary.get('high_churn_subdomains', 0)} |",
            "",
        ]
        for section, label in [
            ("missed_renewals",   "Missed renewals"),
            ("expired",           "Expired certs"),
            ("cert_churn",        "High cert churn"),
            ("cross_domain_sans", "Cross-domain SANs"),
        ]:
            items = self.cert_analysis.get(section, [])
            if items:
                lines += [f"**{label}:**"]
                for r in items[:5]:
                    lines.append(f"- `{r['dns_name']}`")
                lines.append("")
        return "\n".join(lines)

    def _subdomains_md(self, limit: int = 50) -> str:
        if not self.subdomains:
            return ""
        lines = [f"## Subdomain corpus ({len(self.subdomains)} subdomains)", ""]
        for s in self.subdomains[:limit]:
            fqdn    = s.get("dns_name", "")
            expired = s.get("is_expired", False)
            days    = s.get("days_remaining")
            risk    = s.get("risk_level", "")
            if not risk or risk == "other":
                risk = self._derive_subdomain_risk(fqdn)
            days_label = "EXPIRED ⚠" if expired else f"{days}d" if days is not None else "—"
            flag = " ⚠" if risk in ("critical", "high") else ""
            lines.append(f"- `{fqdn}` — {risk}{flag} · {days_label}")
        if len(self.subdomains) > limit:
            lines.append(f"- *...and {len(self.subdomains) - limit} more*")
        return "\n".join(lines)

    # --- Shared HTML builders -----------------------------------------------

    def _html_score_ring_layout(self, grid_cards: str) -> str:
        score = self.display_score
        risk_band = self.display_risk_band.replace("_", " ").title()
        color = RISK_BAND_COLOUR.get(self.display_risk_band, "#666")
        
        return f"""
        <div style="display: flex; gap: 24px; margin: 16px 0 24px; align-items: stretch;">
            <div style="flex: 0 0 200px; background: #FFFFFF; border: 1px solid #E2E8F0; border-top: 3px solid {color}; border-radius: 8px; padding: 20px; display: flex; flex-direction: column; align-items: center; justify-content: center; box-shadow: 0 1px 3px rgba(0,0,0,0.05); break-inside: avoid;">
                <div style="font-size: 10px; color: #64748B; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin-bottom: 4px; text-align: center;">Domain assessed</div>
                <div style="font-size: 13px; font-weight: 600; color: #0F172A; margin-bottom: 16px; text-align: center; word-break: break-all;">{self.domain}</div>
                
                <div style="position: relative; width: 90px; height: 90px;">
                    <svg viewBox="0 0 36 36" style="width: 100%; height: 100%;">
                        <path stroke="#F1F5F9" fill="none" stroke-width="3.5" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                        <path stroke="{color}" fill="none" stroke-width="3.5" stroke-dasharray="{score}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                    </svg>
                    <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                        <div style="font-size: 26px; font-weight: 800; color: #0F172A; line-height: 1; letter-spacing: -0.02em;">{score}</div>
                        <div style="font-size: 10px; color: #64748B; font-weight: 600;">/100</div>
                    </div>
                </div>
                
                <div style="font-size: 14px; font-weight: 700; color: {color}; margin-top: 16px; text-align: center;">{risk_band} risk</div>
                <div style="font-size: 9px; color: #94A3B8; margin-top: 4px; text-align: center;">0 = low &middot; 100 = critical</div>
            </div>
            
            <div style="flex: 1;">
                <div class="grid" style="margin: 0; height: 100%; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));">
                    {grid_cards}
                </div>
            </div>
        </div>
        """

    def _infrastructure_routing_html(self) -> str:
        bgp   = self.o.get("bgp_routing") or {}
        ip    = self.o.get("ip_reputation") or {}
        infra = self.o.get("infrastructure_concentration") or {}
        geo   = self.o.get("geolocation") or {}

        # Always render — show corpus intelligence even if BGP not yet enriched
        has_bgp_data = any([
            bgp.get("rpki_state") not in (None, "unknown", ""),
            bgp.get("moas_detected"),
            ip.get("spamhaus_zen"),
            ip.get("asn_core_risk", 0) > 0,
        ])

        if not has_bgp_data:
            return """
            <h2>Infrastructure &amp; routing intelligence</h2>
            <div style="background:#f7f8f9;border-radius:8px;padding:16px;color:#666;font-size:13px">
            BGP and routing telemetry will appear here once this domain is indexed
            in the Datazag DuckLake pipeline. For live scans this populates automatically.
            </div>"""
        
        infra_intel = self.o.get("infrastructure_intelligence") or {}
        context = infra_intel.get("domain_risk_context", {})
        if isinstance(context, str):
            import json
            try:
                context = json.loads(context)
            except Exception:
                context = {}
                
        domain_details = context.get("domain_details", context)
        
        rpki = str(domain_details.get("rpki_status", "unknown")).upper()
        rpki_color = "#3B6D11" if rpki == "VALID" else "#A32D2D" if rpki == "INVALID" else "#64748B"
        
        hijack = domain_details.get("asn_hijack_history", False)
        hijack_val = "Detected" if hijack else "None"
        hijack_color = "#A32D2D" if hijack else "#3B6D11"
        
        moas = domain_details.get("moas_risk", "none")
        moas_color = "#A32D2D" if str(moas).lower() != "none" and moas else "#64748B"
        
        churn = domain_details.get("bgp_strangeness", "stable")
        
        ff = domain_details.get("fast_flux_risk", 0.0)
        try:
            ff_label = "Elevated" if float(ff) > 0.5 else "Low"
        except (ValueError, TypeError):
            ff_label = "Low"
            
        dga = domain_details.get("dga_risk", 0.0)
        try:
            dga_label = "Elevated" if float(dga) > 0.5 else "Low"
        except (ValueError, TypeError):
            dga_label = "Low"
            
        isp = self.tech.get("isp_name", "Unknown ISP") or "Unknown ISP"
        asn = self.tech.get("asn", "Unknown ASN") or "Unknown ASN"
        asn_risk = str(self.tech.get("asn_risk_level", "medium")).upper()
        trust = self.tech.get("net_trust_score", 50)
        
        return f"""
        <h2>Infrastructure & Routing Analysis</h2>
        <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;padding:16px;margin-bottom:24px;box-shadow: 0 1px 2px rgba(0,0,0,0.02); break-inside: avoid;">
            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #F1F5F9; padding-bottom: 12px; margin-bottom: 12px;">
                <div style="flex: 1;">
                    <div style="font-size:11px;color:#64748B;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Primary ASN</div>
                    <div style="font-size:13px;font-weight:600;color:#0F172A">{asn}</div>
                </div>
                <div style="flex: 1.5;">
                    <div style="font-size:11px;color:#64748B;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Hosting Network</div>
                    <div style="font-size:13px;font-weight:600;color:#0F172A">{isp}</div>
                </div>
                <div style="flex: 1;">
                    <div style="font-size:11px;color:#64748B;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Network Trust Score</div>
                    <div style="font-size:13px;font-weight:600;color:#0F172A">{trust}/100</div>
                </div>
            </div>
            
            <div style="display:grid;grid-template-columns:repeat(2, 1fr);gap:16px;margin-top:16px;">
                <!-- Column 1: Routing -->
                <div>
                    <h3 style="font-size:12px;color:#334155;margin:0 0 8px 0;text-transform:uppercase;letter-spacing:0.02em;">BGP Routing Posture</h3>
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="padding:6px 0;font-size:12px;color:#475569;border-bottom:1px solid #F8FAFC;">RPKI State</td>
                            <td style="padding:6px 0;text-align:right;border-bottom:1px solid #F8FAFC;"><span style="font-size:11px;font-weight:600;color:{rpki_color};background:#F8FAFC;padding:2px 6px;border-radius:4px;border:1px solid #E2E8F0;">{rpki}</span></td>
                        </tr>
                        <tr>
                            <td style="padding:6px 0;font-size:12px;color:#475569;border-bottom:1px solid #F8FAFC;">Hijack History</td>
                            <td style="padding:6px 0;text-align:right;border-bottom:1px solid #F8FAFC;"><span style="font-size:11px;font-weight:600;color:{hijack_color};background:#F8FAFC;padding:2px 6px;border-radius:4px;border:1px solid #E2E8F0;">{hijack_val}</span></td>
                        </tr>
                        <tr>
                            <td style="padding:6px 0;font-size:12px;color:#475569;border-bottom:1px solid #F8FAFC;">MOAS Risk</td>
                            <td style="padding:6px 0;text-align:right;border-bottom:1px solid #F8FAFC;"><span style="font-size:11px;font-weight:600;color:{moas_color};background:#F8FAFC;padding:2px 6px;border-radius:4px;border:1px solid #E2E8F0;">{str(moas).title()}</span></td>
                        </tr>
                        <tr>
                            <td style="padding:6px 0;font-size:12px;color:#475569;border-bottom:1px solid #F8FAFC;">BGP Stability</td>
                            <td style="padding:6px 0;text-align:right;border-bottom:1px solid #F8FAFC;"><span style="font-size:11px;font-weight:600;color:#64748B;background:#F8FAFC;padding:2px 6px;border-radius:4px;border:1px solid #E2E8F0;">{str(churn).title()}</span></td>
                        </tr>
                    </table>
                </div>
                
                <!-- Column 2: Threat Modeling -->
                <div>
                    <h3 style="font-size:12px;color:#334155;margin:0 0 8px 0;text-transform:uppercase;letter-spacing:0.02em;">Threat Intelligence</h3>
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="padding:6px 0;font-size:12px;color:#475569;border-bottom:1px solid #F8FAFC;">Fast Flux Risk</td>
                            <td style="padding:6px 0;text-align:right;border-bottom:1px solid #F8FAFC;"><span style="font-size:11px;font-weight:600;color:{'#A32D2D' if ff_label == 'Elevated' else '#3B6D11'};background:#F8FAFC;padding:2px 6px;border-radius:4px;border:1px solid #E2E8F0;">{ff_label}</span></td>
                        </tr>
                        <tr>
                            <td style="padding:6px 0;font-size:12px;color:#475569;border-bottom:1px solid #F8FAFC;">DGA Entropy Risk</td>
                            <td style="padding:6px 0;text-align:right;border-bottom:1px solid #F8FAFC;"><span style="font-size:11px;font-weight:600;color:{'#A32D2D' if dga_label == 'Elevated' else '#3B6D11'};background:#F8FAFC;padding:2px 6px;border-radius:4px;border:1px solid #E2E8F0;">{dga_label}</span></td>
                        </tr>
                        <tr>
                            <td style="padding:6px 0;font-size:12px;color:#475569;border-bottom:1px solid #F8FAFC;">ASN Risk Tier</td>
                            <td style="padding:6px 0;text-align:right;border-bottom:1px solid #F8FAFC;"><span style="font-size:11px;font-weight:600;color:#64748B;background:#F8FAFC;padding:2px 6px;border-radius:4px;border:1px solid #E2E8F0;">{asn_risk}</span></td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
        """

    def _rdap_html(self) -> str:
        rdap = self.rdap
        if not rdap.get("rdap_available"):
            return ""
        risk_reasons = ", ".join(rdap.get("rdap_risk_reasons", [])) or "none"
        risk_block = ""
        if risk_reasons != "none":
            risk_block = (
                f'<div style="background:#FAEEDA;border-left:3px solid #854F0B;'
                f'padding:10px 14px;border-radius:0 6px 6px 0;font-size:12px;margin:10px 0;color:#412402">'
                f'<strong>Registration risk signals:</strong> {risk_reasons}</div>'
            )
        return f"""
        <h2>Domain registration</h2>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:10px 0">
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">Registrar</div>
            <div style="font-size:13px;font-weight:500">{rdap.get('registrar_name') or '—'}</div>
            <div style="font-size:11px;color:#888;margin-top:2px">{rdap.get('registrar_label') or ''}</div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">Domain age</div>
            <div style="font-size:22px;font-weight:600">{rdap.get('domain_age_days', '—')}</div>
            <div style="font-size:11px;color:#888;margin-top:2px">days · registered {rdap.get('registered', '—')}</div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">Expiry</div>
            <div style="font-size:13px;font-weight:500">{rdap.get('expires', '—')}</div>
            <div style="font-size:11px;color:#888;margin-top:2px">{rdap.get('days_to_expiry', '—')} days remaining</div>
        </div>
        </div>
        <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:#555;margin-top:6px">
        <span>DNSSEC: <strong>{'enabled' if rdap.get('dnssec_enabled') else 'not enabled'}</strong></span>
        <span>RDAP risk score: <strong>{rdap.get('rdap_risk_score', 0)}</strong></span>
        <span>Abuse contact: <strong>{rdap.get('abuse_email') or 'not found'}</strong></span>
        </div>
        {risk_block}"""

    def _cert_analysis_html(self) -> str:
        summary = self.cert_analysis.get("summary", {})
        if not summary:
            return ""
        missed  = self.cert_analysis.get("missed_renewals", [])
        expired = self.cert_analysis.get("expired", [])
        churn   = self.cert_analysis.get("cert_churn", [])
        cross   = self.cert_analysis.get("cross_domain_sans", [])

        def alert_block(colour_key, label, items):
            if not items:
                return ""
            colours = {"red": ("#FCEBEB","#A32D2D"), "orange": ("#FAEEDA","#854F0B"), "blue": ("#E6F1FB","#185FA5")}
            bg, border = colours[colour_key]
            names = ", ".join(r["dns_name"] for r in items[:5])
            return (f'<div style="background:{bg};border-left:3px solid {border};'
                    f'padding:10px 14px;border-radius:0 6px 6px 0;font-size:12px;margin:8px 0">'
                    f'<strong>{label}:</strong> {names}</div>')

        exp_colour = lambda n, k: f"color:{'#A32D2D' if summary.get(k,0) > 0 else 'inherit'}"
        return f"""
        <h2>Certificate intelligence — {summary.get('total_unique_subdomains', 0)} subdomains</h2>
        <div class="grid">
        <div class="card"><div class="num">{summary.get('total_unique_subdomains', 0)}</div><div class="lbl">Total subdomains</div></div>
        <div class="card"><div class="num" style="{exp_colour(0,'expiring_within_60d')}">{summary.get('expiring_within_60d', 0)}</div><div class="lbl">Expiring 60d</div></div>
        <div class="card"><div class="num" style="{exp_colour(0,'expired')}">{summary.get('expired', 0)}</div><div class="lbl">Expired</div></div>
        <div class="card"><div class="num" style="{exp_colour(0,'missed_renewals')}">{summary.get('missed_renewals', 0)}</div><div class="lbl">Missed renewals</div></div>
        <div class="card"><div class="num">{summary.get('wildcard_zones', 0)}</div><div class="lbl">Wildcard zones</div></div>
        <div class="card"><div class="num">{summary.get('cross_domain_sans', 0)}</div><div class="lbl">Cross-domain SANs</div></div>
        </div>
        {alert_block("red",    "Missed renewals",         missed)}
        {alert_block("red",    "Expired certs",           expired)}
        {alert_block("orange", "High cert churn",         churn)}
        {alert_block("blue",   "Cross-domain SANs found", cross)}"""

    def _subdomains_html(self, limit: int = 50) -> str:
        if not self.subdomains:
            return ""

        RISK_COLOURS_SUB = {
            "critical": ("#FCEBEB", "#A32D2D", "#791F1F"),
            "high":     ("#FAEEDA", "#854F0B", "#633806"),
            "medium":   ("#E6F1FB", "#185FA5", "#0C447C"),
            "info":     ("#F9FAFB", "#E2E8F0", "#374151"),
        }

        # Summary stats
        total     = len(self.subdomains)
        ca        = self.cert_analysis.get("summary", {})
        counts    = {
            "critical":   sum(1 for s in self.subdomains if s.get("risk_level") == "critical"),
            "high":       sum(1 for s in self.subdomains if s.get("risk_level") == "high"),
            "dangling":   sum(1 for s in self.subdomains if s.get("is_dangling_cname") or s.get("ns_delegation_risk") == "dangling_ns_delegation"),
            "takeover":   sum(1 for s in self.subdomains if s.get("is_takeover_vulnerable")),
            "malicious":  sum(1 for s in self.subdomains if s.get("is_malicious_ip")),
            "delegated":  sum(1 for s in self.subdomains if s.get("is_delegated")),
            "missed":     ca.get("missed_renewals", 0),
            "expiring30": ca.get("expiring_within_30d", 0),
        }

        stat_cards = f"""
        <div style="display:grid;grid-template-columns:repeat(8,1fr);gap:6px;margin:12px 0">
        {''.join(
            f'<div style="background:{bg};border-radius:6px;padding:8px;text-align:center">'
            f'<div style="font-size:18px;font-weight:700;color:{col}">{val}</div>'
            f'<div style="font-size:9px;color:{col};opacity:.8;text-transform:uppercase;'
            f'letter-spacing:.04em;margin-top:2px">{label}</div></div>'
            for label, val, bg, col in [
                ("Total",         total,              "#f7f8f9", "#374151"),
                ("Critical",      counts["critical"], "#FCEBEB", "#A32D2D"),
                ("High",          counts["high"],     "#FAEEDA", "#854F0B"),
                ("Dangling",      counts["dangling"], "#FCEBEB", "#A32D2D"),
                ("Takeover risk", counts["takeover"], "#FCEBEB", "#A32D2D"),
                ("Malicious IP",  counts["malicious"],"#FCEBEB", "#A32D2D"),
                ("Missed renew",  counts["missed"],   "#FCEBEB" if counts["missed"] else "#f7f8f9",
                                "#A32D2D" if counts["missed"] else "#374151"),
                ("Expiring 30d",  counts["expiring30"],"#FAEEDA" if counts["expiring30"] else "#f7f8f9",
                                "#854F0B" if counts["expiring30"] else "#374151"),
            ]
        )}
        </div>"""

        rows = ""
        for s in sorted(
            self.subdomains[:limit],
            key=lambda x: ["critical","high","medium","info"].index(x.get("risk_level","info"))
        ):
            fqdn     = s.get("dns_name", "")
            risk     = s.get("risk_level", "info")
            bg, border, text = RISK_COLOURS_SUB.get(risk, RISK_COLOURS_SUB["info"])

            # Risk badge
            risk_badge = (
                f'<span style="background:{bg};color:{text};border:1px solid {border};'
                f'padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;'
                f'text-transform:uppercase">{risk}</span>'
                if risk != "info" else ""
            )

            # A records
            a_recs = s.get("a_records", [])
            a_html = (
                f'<span style="font-family:monospace;font-size:10px">'
                + "<br>".join(a_recs[:2])
                + ("..." if len(a_recs) > 2 else "")
                + "</span>"
            ) if a_recs else '<span style="color:#aaa;font-size:10px">—</span>'

            # PTR / provider
            provider = s.get("ptr_reveals_provider") or ""
            ptr_html = (
                f'<span style="font-size:11px;color:#555">{provider}</span>'
                if provider else
                '<span style="font-size:10px;color:#aaa">no PTR</span>'
                if s.get("ptr_is_absent") else
                '<span style="font-size:10px;color:#888">—</span>'
            )

            # CNAME / NS indicators
            flags = []
            if s.get("is_takeover_vulnerable"):
                flags.append(f'<span style="background:#FCEBEB;color:#A32D2D;padding:1px 5px;'
                            f'border-radius:3px;font-size:10px;font-weight:600">'
                            f'TAKEOVER: {s.get("takeover_provider","?")}</span>')
            elif s.get("is_dangling_cname"):
                flags.append('<span style="background:#FCEBEB;color:#A32D2D;padding:1px 5px;'
                            'border-radius:3px;font-size:10px;font-weight:600">DANGLING</span>')
            if s.get("ns_delegation_risk") == "dangling_ns_delegation":
                flags.append('<span style="background:#FCEBEB;color:#A32D2D;padding:1px 5px;'
                            'border-radius:3px;font-size:10px;font-weight:600">NS TAKEOVER</span>')
            elif s.get("is_delegated"):
                flags.append('<span style="background:#E6F1FB;color:#185FA5;padding:1px 5px;'
                            'border-radius:3px;font-size:10px">DELEGATED</span>')
            if s.get("is_malicious_ip"):
                flags.append('<span style="background:#FCEBEB;color:#A32D2D;padding:1px 5px;'
                            'border-radius:3px;font-size:10px;font-weight:600">MALICIOUS IP</span>')
            if s.get("internal_ips"):
                flags.append('<span style="background:#FAEEDA;color:#854F0B;padding:1px 5px;'
                            'border-radius:3px;font-size:10px">INTERNAL IP</span>')

            flags_html = " ".join(flags) if flags else ""

            # Cert expiry
            days       = s.get("days_remaining")
            expired    = s.get("is_expired", False)
            cert_col   = "#A32D2D" if expired else "#854F0B" if days is not None and days < 30 else "#3B6D11"
            days_label = "EXPIRED ⚠" if expired else f"{days}d" if days is not None else "—"

            # Risk reasons
            reasons = s.get("risk_reasons", [])
            reason_html = (
                f'<div style="font-size:10px;color:{text};margin-top:2px">'
                + "; ".join(reasons[:1])
                + "</div>"
            ) if reasons else ""

            rows += f"""
            <tr style="background:{bg};border-bottom:1px solid {border}22">
            <td style="padding:5px 8px;font-family:monospace;font-size:11px;color:#222">
                {fqdn}
                {reason_html}
                {f'<div style="margin-top:2px">{flags_html}</div>' if flags_html else ''}
            </td>
            <td style="padding:5px 8px;white-space:nowrap">{risk_badge}</td>
            <td style="padding:5px 8px">{a_html}</td>
            <td style="padding:5px 8px">{ptr_html}</td>
            <td style="padding:5px 8px;font-size:11px;color:#666">
                {s.get("issuer_category","—")}
            </td>
            <td style="padding:5px 8px;font-size:11px;font-weight:500;color:{cert_col}">
                {days_label}
            </td>
            </tr>"""

        overflow = (
            f'<p style="font-size:11px;color:#888;margin:6px 0">'
            f'+ {len(self.subdomains) - limit} more subdomains not shown</p>'
            if len(self.subdomains) > limit else ""
        )

        return f"""
        <h2>Subdomain inventory ({total})</h2>
        {stat_cards}
        <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#f5f5f5">
            <th style="padding:6px 8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.04em">Subdomain</th>
            <th style="padding:6px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.04em">Risk</th>
            <th style="padding:6px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.04em">A records</th>
            <th style="padding:6px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.04em">PTR / provider</th>
            <th style="padding:6px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.04em">Issuer</th>
            <th style="padding:6px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.04em">Cert</th>
        </tr></thead>
        <tbody>{rows}</tbody>
        </table>
        </div>{overflow}"""

    def _technographics_html(self) -> str:
        t, ti, lbl, flags, dns = self.tech, self.txt_intel, self.labels, self.flags, self.dns

        PILL_STYLES = {
            "saas_platforms":     "background:#EEEDFE;color:#3C3489",
            "identity_providers": "background:#E6F1FB;color:#0C447C",
            "payment_processors": "background:#E1F5EE;color:#085041",
            "ai_infrastructure":  "background:#EAF3DE;color:#27500A",
            "security_tooling":   "background:#FAEEDA;color:#633806",
            "email_marketing":    "background:#FAECE7;color:#712B13",
        }
        pills_html = ""
        for category, style in PILL_STYLES.items():
            for svc in ti.get(category, []):
                is_risky = any(k in svc.lower() for k in ("lastpass","okta","twilio","mailchimp","circleci","dropbox sign"))
                final_style = "background:#FCEBEB;color:#791F1F" if is_risky else style
                pills_html += (
                    f'<span style="{final_style};padding:2px 8px;border-radius:4px;'
                    f'font-size:11px;font-weight:500;display:inline-block;margin:2px 3px 2px 0">{svc}</span>'
                )
        if not pills_html:
            pills_html = '<span style="color:#888;font-size:12px">None identified from TXT records</span>'

        anomalies_html = ""
        for a in ti.get("anomalous_records", []):
            anomalies_html += (
                f'<div style="font-family:monospace;font-size:11px;background:#FCEBEB;color:#791F1F;'
                f'padding:4px 8px;border-radius:3px;margin:3px 0;word-break:break-all">{a}</div>'
            )

        dns_rows = ""
        for rtype in ["a", "aaaa", "mx", "ns", "txt", "caa", "mail_a", "www_a"]:
            records = dns.get(rtype, [])
            if not records:
                dns_rows += (
                    f"<tr style='opacity:.4'>"
                    f"<td style='padding:5px 10px;font-weight:600;font-size:11px;text-transform:uppercase;"
                    f"color:#888;white-space:nowrap;vertical-align:top;width:70px'>{rtype.upper()}</td>"
                    f"<td style='padding:5px 10px;font-family:monospace;font-size:11px;color:#aaa'>—</td></tr>"
                )
                continue
            vals = [f"{r['priority']}  {r['host']}" for r in records] if rtype == "mx" else [str(r) for r in records]
            cell = "<br>".join(
                f'<span style="display:block;padding:1px 0;word-break:break-all">{v}</span>' for v in vals
            )
            dns_rows += (
                f"<tr style='border-bottom:1px solid #f0f0f0'>"
                f"<td style='padding:5px 10px;font-weight:600;font-size:11px;text-transform:uppercase;"
                f"color:#555;white-space:nowrap;vertical-align:top;width:70px'>{rtype.upper()}</td>"
                f"<td style='padding:5px 10px;font-family:monospace;font-size:11px;color:#222;line-height:1.6'>{cell}</td></tr>"
            )

        ea, certs = self.ea, self.certs

        def status_pill(ok, good_text, bad_text):
            if ok:
                return f'<span style="background:#EAF3DE;color:#27500A;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:500">{good_text}</span>'
            return f'<span style="background:#FCEBEB;color:#791F1F;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:500">{bad_text}</span>'

        spf_ok    = ea.get("spf") in ("-all", "~all")
        dmarc_ok  = ea.get("dmarc_policy") in ("reject", "quarantine")
        reject_ok = ea.get("dmarc_policy") == "reject"
        mta_ok    = ea.get("mta_sts") == "NOERROR"
        tls_ok    = ea.get("tls_rpt") == "NOERROR"
        bimi_ok   = ea.get("bimi") == "NOERROR"
        dnssec_ok = bool(ea.get("dnssec"))
        caa_ok    = flags.get("has_caa", False)
        sec_ok    = flags.get("has_security_txt", False)
        smtp_ok   = certs.get("provider_live", False)

        labels_html = "".join(
            f'<span style="background:#f0f0f0;color:#444;padding:3px 10px;border-radius:4px;'
            f'font-size:12px;display:inline-block;margin:2px 3px 2px 0">'
            f'<strong>{k.replace("_"," ").title()}:</strong> {v}</span>'
            for k, v in lbl.items() if v is not None
        )

        net_trust = float(t.get('net_trust_score', 0))
        net_colour = '#3B6D11' if net_trust > 0 else '#A32D2D'

        return f"""
        <h2>Security layer checklist</h2>
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <thead><tr style="background:#f5f5f5">
            <th style="padding:6px 10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em">Layer</th>
            <th style="padding:6px 10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em">Status</th>
            <th style="padding:6px 10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em">Detail</th>
            <th style="padding:6px 10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em">Impact if missing</th>
          </tr></thead>
          <tbody>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">SPF</td>
              <td style="padding:6px 10px">{status_pill(spf_ok, ea.get('spf') or 'present', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">{ea.get('spf_raw','Not found')[:80]}</td>
              <td style="padding:6px 10px;color:#888">Any server can send email as this domain</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">DMARC</td>
              <td style="padding:6px 10px">{status_pill(dmarc_ok, f"p={ea.get('dmarc_policy')}", 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">{f"pct={ea.get('dmarc_pct',0)} · aspf={ea.get('aspf','?')} · adkim={ea.get('adkim','?')}" if dmarc_ok else 'No DMARC record found'}</td>
              <td style="padding:6px 10px;color:#888">Spoofed mail delivered without policy enforcement</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">DMARC p=reject</td>
              <td style="padding:6px 10px">{status_pill(reject_ok, 'p=reject', 'not reject')}</td>
              <td style="padding:6px 10px;color:#555">{'Full enforcement — spoofed mail rejected' if reject_ok else f"Currently p={ea.get('dmarc_policy','missing')} — upgrade to reject"}</td>
              <td style="padding:6px 10px;color:#888">Spoofed mail quarantined or delivered depending on policy</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">MTA-STS</td>
              <td style="padding:6px 10px">{status_pill(mta_ok, 'configured', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">{'Mode: ' + (ea.get('mta_sts_mode') or 'unknown') if mta_ok else 'NXDOMAIN — policy not published'}</td>
              <td style="padding:6px 10px;color:#888">Inbound SMTP vulnerable to TLS downgrade attacks</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">TLS-RPT</td>
              <td style="padding:6px 10px">{status_pill(tls_ok, 'configured', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">{ea.get('tls_rpt_rua') or ('NXDOMAIN — no SMTP TLS reporting' if not tls_ok else 'Configured')}</td>
              <td style="padding:6px 10px;color:#888">No visibility into SMTP delivery failures or TLS issues</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">BIMI</td>
              <td style="padding:6px 10px">{status_pill(bimi_ok, 'configured', 'not configured')}</td>
              <td style="padding:6px 10px;color:#555">{'Brand logo in email clients' if bimi_ok else 'Requires DMARC p=reject first'}</td>
              <td style="padding:6px 10px;color:#888">Brand logo not displayed in Gmail, Apple Mail, Yahoo</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">DNSSEC</td>
              <td style="padding:6px 10px">{status_pill(dnssec_ok, 'enabled', 'not enabled')}</td>
              <td style="padding:6px 10px;color:#555">{'DNSSEC signatures present' if dnssec_ok else 'DNS responses are not cryptographically signed'}</td>
              <td style="padding:6px 10px;color:#888">DNS cache poisoning and response tampering possible</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">CAA records</td>
              <td style="padding:6px 10px">{status_pill(caa_ok, 'present', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">{', '.join(dns.get('caa', [])) or 'No CAA records — any CA can issue certificates'}</td>
              <td style="padding:6px 10px;color:#888">Unauthorised certificates can be issued for this domain</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">security.txt</td>
              <td style="padding:6px 10px">{status_pill(sec_ok, 'present', 'missing')}</td>
              <td style="padding:6px 10px;color:#555">{'Published at /.well-known/security.txt' if sec_ok else 'No responsible disclosure policy published'}</td>
              <td style="padding:6px 10px;color:#888">Security researchers have no formal disclosure channel</td></tr>
            <tr style="border-bottom:1px solid #f5f5f5"><td style="padding:6px 10px;font-weight:500">SMTP banner</td>
              <td style="padding:6px 10px">{status_pill(smtp_ok, 'verified', 'not verified')}</td>
              <td style="padding:6px 10px;color:#555;font-family:monospace;font-size:11px">{certs.get('smtp_banner') or 'No banner captured'}</td>
              <td style="padding:6px 10px;color:#888">MX provider identity unconfirmed from DNS alone</td></tr>
          </tbody>
        </table>

        <h2>Technographics</h2>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:12px 0">
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">MX provider</div>
            <div style="font-size:13px;font-weight:500">{t.get('mx_provider_name') or '—'}</div>
            <div style="font-size:11px;color:#888;margin-top:2px">
            {t.get('mx_mbp_category') or '—'} · nudge {t.get('mx_trust_nudge',0):+.1f} / bias {t.get('mx_risk_bias',0):+.1f}</div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">ASN / ISP</div>
            <div style="font-size:13px;font-weight:500">{t.get('isp_name') or '—'} (AS{t.get('asn') or '—'})</div>
            <div style="font-size:11px;color:#888;margin-top:2px">
            {t.get('isp_country') or '—'} · risk: {t.get('asn_risk_level') or '—'} · TLD: {t.get('tld_risk_level') or '—'}
            {'· <strong>Hosting CDN</strong>' if t.get('is_hosting_cdn') else ''}
            </div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">Net trust score</div>
            <div style="font-size:22px;font-weight:600;color:{net_colour}">{net_trust:+.1f}</div>
            <div style="font-size:11px;color:#888;margin-top:2px">CDN/UGC: {'Yes' if t.get('is_cdn_ugc') else 'No'}</div>
        </div>
        </div>

        <h2>SaaS stack — {ti.get('total_identified',0)} services identified from TXT records</h2>
        <div style="margin:10px 0 6px">{pills_html}</div>
        {f'<div style="margin-top:10px"><div style="font-size:11px;color:#A32D2D;font-weight:600;text-transform:uppercase;letter-spacing:.04em;margin-bottom:5px">Anomalous TXT records</div>{anomalies_html}</div>' if anomalies_html else ''}

        <h2>Full DNS records</h2>
        <table style="width:100%;border-collapse:collapse"><tbody>{dns_rows}</tbody></table>

        <h2>Labels</h2>
        <div style="margin:8px 0">{labels_html}</div>

        <h2>Certificates</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:10px 0">
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:5px">HTTPS</div>
            <div style="font-size:13px">{self.certs.get('https_issuer_org') or '—'} <span style="color:#888;font-size:11px">({self.certs.get('https_label') or '—'})</span></div>
            <div style="font-size:12px;margin-top:4px;color:{'#A32D2D' if self.certs.get('https_expiring') else '#3B6D11'}">
            {self.certs.get('https_days_left') or '—'} days remaining{' — EXPIRING SOON' if self.certs.get('https_expiring') else ''}</div>
            <div style="font-size:11px;color:#888;margin-top:3px">
            {self.certs.get('https_san_count') or '—'} SANs · Let's Encrypt: {'Yes' if self.certs.get('https_lets_encrypt') else 'No'}</div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-bottom:5px">SMTP</div>
            <div style="font-size:13px">{self.certs.get('smtp_issuer_org') or '—'}</div>
            <div style="font-size:12px;color:#3B6D11;margin-top:4px">{self.certs.get('smtp_days_left') or '—'} days remaining</div>
            <div style="font-family:monospace;font-size:11px;color:#555;margin-top:6px;word-break:break-all">
            {self.certs.get('smtp_banner') or 'No banner captured'}</div>
            <div style="font-size:11px;margin-top:4px;color:{'#3B6D11' if self.certs.get('provider_live') else '#888'}">
            Provider {'confirmed live via banner' if self.certs.get('provider_live') else 'not banner-verified'}</div>
        </div>
        </div>

        <h2>Change signals</h2>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0">
        {''.join(
            f'<span style="background:{"#FCEBEB" if v else "#EAF3DE"};color:{"#791F1F" if v else "#27500A"};'
            f'padding:3px 10px;border-radius:4px;font-size:12px;font-weight:{"600" if v else "400"}">'
            f'{k.replace("_"," ").title()}: {"YES ⚠" if v else "No"}</span>'
            for k, v in self.changes.items() if isinstance(v, bool)
        )}
        </div>"""

    def _risk_breakdown_html(self) -> str:
        re = self.risk_engine
        rows = ""
        for r in re.get("rules", []):
            pts    = r["points"]
            colour = "#A32D2D" if pts > 0 else "#3B6D11"
            sign   = f"+{pts}" if pts > 0 else str(pts)
            width  = min(100, abs(pts) * 8)
            rows += (
                f'<tr><td style="padding:5px 10px;font-size:12px;color:#444">{r["rule"]}</td>'
                f'<td style="padding:5px 10px;min-width:120px">'
                f'<div style="background:#f0f0f0;border-radius:3px;height:6px">'
                f'<div style="background:{colour};width:{width}%;height:100%;border-radius:3px"></div></div></td>'
                f'<td style="padding:5px 10px;font-weight:600;color:{colour};text-align:right;font-size:12px">{sign}</td></tr>'
            )
        return f"""
        <h2>Risk score breakdown
          <span style="font-weight:400;font-size:13px;color:#888;margin-left:8px">
            {re.get('score',0)}/100 · {re.get('bucket','?')} · config {re.get('config_version','?')}
          </span>
        </h2>
        <table style="width:100%;border-collapse:collapse">{rows}</table>"""


    # ---------------------------------------------------------------------------
    # Subdomain risk derivation
    # ---------------------------------------------------------------------------

    def _derive_subdomain_risk(self, fqdn: str) -> str:
        """Derive risk level from subdomain keyword when not provided."""
        sub = fqdn.split(".")[0].lower()
        if any(k in sub for k in (
            "vpn", "remote", "citrix", "rdp", "ssh", "bastion",
            "sso", "login", "auth", "idp",
        )):
            return "critical"
        if any(k in sub for k in (
            "staging", "stage", "dev", "test", "qa", "uat",
            "sandbox", "preprod", "admin", "portal", "dashboard",
            "console", "panel", "manage", "management",
        )):
            return "high"
        if any(k in sub for k in (
            "api", "gateway", "proxy", "internal", "corp", "intranet",
        )):
            return "medium"
        return "info"

    # ---------------------------------------------------------------------------
    # Certificate expiry findings from cert_analysis
    # ---------------------------------------------------------------------------

    def _cert_expiry_findings(self) -> list[dict]:
        """
        Generate findings from cert_analysis data.
        These should be prepended to findings list in renderers.
        """
        extra = []
        summary = self.cert_analysis.get("summary", {})
        if not summary:
            return extra

        # Don't duplicate the main cert expiry finding from passive_security_findings_v2
        existing_keys = {f.get("finding", "") for f in self.findings}

        missed  = self.cert_analysis.get("missed_renewals", [])
        expired = self.cert_analysis.get("expired", [])

        if missed:
            names = ", ".join(r["dns_name"] for r in missed[:5])
            extra.append({
                "finding":     "cert_missed_renewals",
                "severity":    "critical",
                "title":       f"{len(missed)} certificate{'s' if len(missed)>1 else ''} missed renewal — expiring within 30 days",
                "evidence":    f"Subdomains: {names}",
                "detail":      (
                    f"{len(missed)} certificate(s) across the domain portfolio are expiring "
                    f"within 30 days and appear to have missed auto-renewal. "
                    f"After expiry, browsers will display security warnings to all visitors. "
                    f"Affected: {names}."
                ),
                "remediation": (
                    "Trigger manual renewal for all listed certificates immediately. "
                    "Verify auto-renewal configuration on your certificate management platform. "
                    "Check Let's Encrypt certbot cron jobs or ACME client configuration."
                ),
            })

        if expired:
            names = ", ".join(r["dns_name"] for r in expired[:5])
            extra.append({
                "finding":     "cert_expired",
                "severity":    "critical",
                "title":       f"{len(expired)} certificate{'s' if len(expired)>1 else ''} already expired",
                "evidence":    f"Expired: {names}",
                "detail":      (
                    f"{len(expired)} certificate(s) have already expired. "
                    f"These subdomains are currently showing browser security warnings. "
                    f"Any HTTPS traffic to these subdomains may be blocked."
                ),
                "remediation": "Renew expired certificates immediately.",
            })

        exp_30 = summary.get("expiring_within_30d", 0)
        if exp_30 > 0 and "cert_expiring_soon" not in existing_keys and not missed:
            extra.append({
                "finding":     "certs_expiring_soon",
                "severity":    "high",
                "title":       f"{exp_30} certificate{'s' if exp_30>1 else ''} expiring within 30 days",
                "evidence":    f"expiring_within_30d: {exp_30}",
                "detail":      (
                    f"{exp_30} certificate(s) across the subdomain portfolio expire within 30 days. "
                    f"Verify auto-renewal is configured and working."
                ),
                "remediation": "Verify auto-renewal is active. Trigger manual renewal if in doubt.",
            })

        # VPN/staging subdomains not already in main findings
        existing_findings = {f.get("finding","") for f in self.findings}
        for sub in self.subdomains:
            fqdn = sub.get("dns_name","")
            risk = self._derive_subdomain_risk(fqdn)
            sub_part = fqdn.split(".")[0].lower()

            if risk == "critical" and "vpn_exposed" not in existing_findings:
                if any(k in sub_part for k in ("vpn","remote","citrix","rdp","ssh","bastion")):
                    existing_findings.add("vpn_exposed")
                    extra.append({
                        "finding":     "vpn_exposed",
                        "severity":    "high",
                        "title":       f"Remote access endpoint publicly accessible: {fqdn}",
                        "evidence":    f"Subdomain: {fqdn}, cert days: {sub.get('days_remaining','?')}",
                        "detail":      (
                            f"{fqdn} is a publicly accessible remote access endpoint. "
                            "These are the primary initial access vector in ransomware attacks — "
                            "over 70% of ransomware incidents involve an exposed remote access service. "
                            "Verify MFA is enforced and access is restricted to known IP ranges."
                        ),
                        "remediation": (
                            "Restrict access to VPN/remote endpoints by IP allowlist if possible. "
                            "Ensure MFA is enforced. Verify this subdomain is intentionally public."
                        ),
                    })

            if risk == "high" and "staging_exposed" not in existing_findings:
                if any(k in sub_part for k in ("staging","stage","dev","test","qa","uat","sandbox","preprod","normstagingsite")):
                    existing_findings.add("staging_exposed")
                    extra.append({
                        "finding":     "staging_exposed",
                        "severity":    "high",
                        "title":       f"Development/staging environment publicly accessible: {fqdn}",
                        "evidence":    f"Subdomain: {fqdn}",
                        "detail":      (
                            f"{fqdn} appears to be a development or staging environment that is "
                            "publicly accessible. Staging environments typically run older software "
                            "versions with weaker access controls and may contain sensitive test data."
                        ),
                        "remediation": (
                            "Restrict staging/dev environments behind VPN or IP allowlist. "
                            "They should not be publicly accessible from the internet."
                        ),
                    })

        return extra


    # ---------------------------------------------------------------------------
    # Corpus intelligence section
    # ---------------------------------------------------------------------------

    def _corpus_intelligence_html(self, brand: "BrandConfig") -> str:
        corr = self.o.get("infrastructure_correlation", {})
        bgp  = self.o.get("bgp_routing", {}) or self.o.get("bgp_intelligence", {})
        conc = self.o.get("infrastructure_concentration", {})
        bl   = self.o.get("blocklist_signals", {}) or self.o.get("ip_reputation", {})

        if not any([corr, bgp, conc, bl]):
            return ""

        # BGP/RPKI block
        rpki_state  = str(bgp.get("rpki_state", "unknown")).upper()
        moas        = bgp.get("moas_detected", False)
        rpki_colour = "#3B6D11" if rpki_state == "VALID" else "#A32D2D" if rpki_state == "INVALID" else "#64748B"
        bgp_label   = "MOAS DETECTED — possible hijack" if moas else f"RPKI {rpki_state}"
        bgp_colour  = "#A32D2D" if moas else rpki_colour

        # Blocklist
        spamhaus = bl.get("spamhaus_zen") or bl.get("spamhaus_xbl")
        urlhaus  = bl.get("urlhaus_listed") or bl.get("urlhaus")
        any_listed = bl.get("any_listed") or spamhaus or urlhaus or (bl.get("firehol_level", 0) > 0)
        feed_matches = bl.get("feed_matches", [])
        listing_count = bl.get("listing_count", len(feed_matches))

        # Concentration cards
        conc_cards = ""
        for label, key in [
            ("Domains on same IP",     "domains_on_ip"),
            ("Domains on prefix",      "domains_on_prefix"),
            ("Domains on ASN",         "domains_on_asn"),
            ("Domains using same NS",  "ns_domain_count"),
            ("Domains using same MX",  "mx_domain_count"),
        ]:
            val = conc.get(key)
            if val is None or val == 0:
                continue
            dedicated = key == "domains_on_ip" and val < 5
            colour = "#3B6D11" if dedicated else "#374151"
            conc_cards += f"""
            <div style="background:#f7f8f9;border-radius:8px;padding:12px 14px;
                        border-top:2px solid {brand.accent_colour}">
            <div style="font-size:20px;font-weight:700;color:{colour}">{val:,}</div>
            <div style="font-size:10px;color:#888;margin-top:3px;text-transform:uppercase;
                        letter-spacing:.05em">{label}</div>
            {f"<div style='font-size:10px;color:#3B6D11;margin-top:2px'>Dedicated infrastructure</div>" if dedicated else ""}
            </div>"""

        # Pivot findings (malicious co-hosts)
        pivot_rows = ""
        any_malicious = False
        for pivot in corr.get("pivot_findings", []):
            if pivot.get("malicious_count", 0) == 0:
                continue
            any_malicious = True
            count = pivot["malicious_count"]
            total = pivot.get("total_count", 0)
            severity = "critical" if count >= 5 else "high" if count >= 2 else "medium"
            bg, col = {
                "critical": ("#FCEBEB", "#A32D2D"),
                "high":     ("#FAEEDA", "#854F0B"),
                "medium":   ("#E6F1FB", "#185FA5"),
            }.get(severity, ("#F9FAFB", "#374151"))
            examples = ", ".join(pivot.get("examples", [])[:3])
            pivot_rows += f"""
            <tr style="background:{bg}">
            <td style="padding:8px 12px;font-weight:600;font-size:12px;color:{col}">{pivot['dimension'].upper()}</td>
            <td style="padding:8px 12px;font-family:monospace;font-size:11px">{pivot.get('value','')}</td>
            <td style="padding:8px 12px;font-size:22px;font-weight:800;color:{col}">{count}</td>
            <td style="padding:8px 12px;font-size:12px;color:#555">of {total:,} domains on same {pivot['dimension']}</td>
            <td style="padding:8px 12px;font-size:11px;color:#888;font-family:monospace">{examples}</td>
            </tr>"""

        # Prefix malicious ratio
        ratio = corr.get("prefix_malicious_ratio", 0)
        if not ratio and conc.get("domains_on_prefix"):
            ratio = 0
        ratio_pct = round(ratio * 100, 3)
        ratio_col = "#A32D2D" if ratio > 0.01 else "#854F0B" if ratio > 0.003 else "#3B6D11"

        # Feed pills
        feed_html = ""
        for feed in feed_matches:
            feed_html += (
                f'<span style="background:#FCEBEB;color:#791F1F;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;font-weight:500;'
                f'display:inline-block;margin:2px 3px">{feed}</span>'
            )

        if not conc_cards and not any_malicious and not any_listed and not moas:
            # All clean — show a positive summary
            return f"""
            <h2 style="display:flex;justify-content:space-between;align-items:baseline">
            <span>Corpus intelligence</span>
            <span style="font-size:11px;font-weight:400;color:#888;text-transform:none;letter-spacing:0">
                Cross-referenced against 320M domains · updated hourly
            </span>
            </h2>
            <div style="background:#EAF3DE;border-left:3px solid #3B6D11;padding:12px 16px;
                        border-radius:0 8px 8px 0;font-size:13px;color:#1a3d0f;line-height:1.6">
            <strong>No malicious co-hosts detected.</strong>
            Infrastructure cross-reference across IP, prefix, ASN, NS and MX dimensions
            shows no known-malicious domains sharing this domain's infrastructure.
            BGP routing is stable with no MOAS or hijack signals. All threat feeds clean.
            </div>
            <div style="margin-top:10px;font-size:11px;color:#888;line-height:1.6">
            Datazag corpus intelligence cross-references this domain's infrastructure
            against 320 million domains monitored in real time across 40+ threat feeds,
            updated hourly.
            </div>"""

        return f"""
        <h2 style="display:flex;justify-content:space-between;align-items:baseline">
        <span>Corpus intelligence</span>
        <span style="font-size:11px;font-weight:400;color:#888;text-transform:none;letter-spacing:0">
            Cross-referenced against 320M domains · updated hourly
        </span>
        </h2>

        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0">
        <div style="background:{'#FCEBEB' if moas else '#f7f8f9'};border-radius:8px;padding:12px 14px;
                    border-top:2px solid {bgp_colour}">
            <div style="font-size:13px;font-weight:700;color:{bgp_colour}">{bgp_label}</div>
            <div style="font-size:10px;color:#888;margin-top:2px;text-transform:uppercase">BGP / RPKI</div>
        </div>
        <div style="background:#f7f8f9;border-radius:8px;padding:12px 14px">
            <div style="font-size:20px;font-weight:700">{bgp.get('asn') or self.tech.get('asn') or '—'}</div>
            <div style="font-size:10px;color:#888;margin-top:2px;text-transform:uppercase">ASN</div>
        </div>
        <div style="background:#f7f8f9;border-radius:8px;padding:12px 14px">
            <div style="font-size:13px;font-weight:600">{bgp.get('prefix') or '—'}</div>
            <div style="font-size:10px;color:#888;margin-top:2px;text-transform:uppercase">Announced prefix</div>
        </div>
        <div style="background:{'#FCEBEB' if any_listed else '#EAF3DE'};border-radius:8px;padding:12px 14px">
            <div style="font-size:13px;font-weight:700;
                        color:{'#A32D2D' if any_listed else '#3B6D11'}">
            {'LISTED — ' + str(listing_count) + ' feed(s)' if any_listed else 'Clean — all feeds'}
            </div>
            <div style="font-size:10px;color:#888;margin-top:2px;text-transform:uppercase">Blocklist status</div>
        </div>
        </div>

        {f'''<div style="margin:10px 0">
        <div style="display:flex;justify-content:space-between;font-size:12px;color:#555;margin-bottom:4px">
            <span>Malicious domain ratio on this prefix</span>
            <span style="font-weight:700;color:{ratio_col}">{ratio_pct}%</span>
        </div>
        <div style="background:#f0f0f0;border-radius:3px;height:8px">
            <div style="background:{ratio_col};width:{min(100, ratio_pct * 20)}%;height:100%;border-radius:3px"></div>
        </div>
        <div style="font-size:11px;color:#888;margin-top:4px">
            Based on {conc.get("domains_on_prefix",0):,} domains on this prefix in the Datazag corpus
        </div>
        </div>''' if conc.get("domains_on_prefix") else ""}

        {f'''<h3 style="font-size:12px;font-weight:700;color:#A32D2D;margin:16px 0 8px">
        Malicious co-hosts detected</h3>
        <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#f5f5f5">
            <th style="padding:6px 12px;text-align:left;font-size:11px;text-transform:uppercase">Dimension</th>
            <th style="padding:6px 12px;text-align:left;font-size:11px;text-transform:uppercase">Value</th>
            <th style="padding:6px 12px;text-align:left;font-size:11px;text-transform:uppercase">Malicious</th>
            <th style="padding:6px 12px;text-align:left;font-size:11px;text-transform:uppercase">Context</th>
            <th style="padding:6px 12px;text-align:left;font-size:11px;text-transform:uppercase">Examples</th>
        </tr></thead>
        <tbody>{pivot_rows}</tbody>
        </table>''' if any_malicious else ""}

        {f'''<h3 style="font-size:12px;font-weight:700;color:#374151;margin:16px 0 8px">
        Infrastructure concentration</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:10px 0">
        {conc_cards}
        </div>''' if conc_cards else ""}

        {f'''<div style="margin-top:12px"><div style="font-size:12px;font-weight:600;color:#A32D2D;margin-bottom:6px">
        Active blocklist listings</div>{feed_html}</div>''' if feed_html else ""}

        <div style="margin-top:16px;padding:10px 14px;background:#f0f4ff;
                    border-radius:6px;font-size:11px;color:#555;line-height:1.6">
        Corpus intelligence is derived from Datazag's passive monitoring of 320 million domains
        across 40+ servers, updated hourly. Co-host analysis identifies domains sharing IP,
        prefix, ASN, NS and MX infrastructure with this domain and cross-references against
        live threat feed integrations.
        </div>"""


    # ---------------------------------------------------------------------------
    # Alerting CTA
    # ---------------------------------------------------------------------------

    def _alerting_cta_html(self, brand: "BrandConfig") -> str:
        subs = self.subdomains
        sub_count = len(subs) if subs else 0
        return f"""
        <div style="margin:32px 0;padding:20px 24px;
                    background:{brand.primary_colour};border-radius:10px;
                    display:grid;grid-template-columns:1fr auto;gap:20px;
                    align-items:center;break-inside:avoid">
        <div>
            <div style="color:{brand.accent_colour};font-size:11px;font-weight:700;
                        text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
            Real-time monitoring available
            </div>
            <div style="color:white;font-size:15px;font-weight:600;
                        margin-bottom:8px;line-height:1.4">
            This report is a point-in-time snapshot.
            {self.domain} changes — we detect it in seconds.
            </div>
            <div style="color:rgba(255,255,255,.65);font-size:12px;line-height:1.7">
            Branded threat alerts within 5–10 seconds of SSL issuance ·
            New subdomain detection across {sub_count or 'all'} known assets ·
            Infrastructure change alerting across IP, NS, MX and BGP ·
            Malicious co-host notifications updated hourly ·
            Active phishing campaign alerts relevant to your SaaS stack
            </div>
        </div>
        <div style="text-align:center;flex-shrink:0">
            <a href="{brand.cta_button_url}" target="_blank"
            style="display:block;background:{brand.accent_colour};
                    color:{brand.text_on_accent};padding:12px 20px;
                    border-radius:6px;font-size:13px;font-weight:700;
                    text-decoration:none;white-space:nowrap;margin-bottom:8px">
            Activate monitoring →
            </a>
            <div style="color:rgba(255,255,255,.45);font-size:11px">
            {brand.contact_email}
            </div>
        </div>
        </div>"""


    # ---------------------------------------------------------------------------
    # Security checklist markdown
    # ---------------------------------------------------------------------------

    def _security_checklist_md(self) -> str:
        ea    = self.ea
        flags = self.flags
        certs = self.certs

        def status(ok):
            return "✓" if ok else "✗ MISSING"

        spf_ok    = ea.get("spf") in ("-all", "~all")
        dmarc_ok  = ea.get("dmarc_policy") in ("reject", "quarantine")
        reject_ok = ea.get("dmarc_policy") == "reject"
        mta_ok    = ea.get("mta_sts") == "NOERROR"
        tls_ok    = ea.get("tls_rpt") == "NOERROR"
        bimi_ok   = ea.get("bimi") == "NOERROR"
        dnssec_ok = bool(ea.get("dnssec"))
        caa_ok    = flags.get("has_caa", False)
        sec_ok    = flags.get("has_security_txt", False)
        smtp_ok   = certs.get("provider_live", False)

        lines = [
            "## Security layer checklist", "",
            "| Layer | Status | Attack risk if missing |",
            "|-------|--------|------------------------|",
            f"| SPF | {status(spf_ok)} {ea.get('spf') or ''} | Any server can send as this domain |",
            f"| DMARC | {status(dmarc_ok)} {'p='+ea.get('dmarc_policy') if ea.get('dmarc_policy') else ''} | Spoofed mail delivered without enforcement |",
            f"| MTA-STS | {status(mta_ok)} | SMTP TLS downgrade attacks possible |",
            f"| TLS-RPT | {status(tls_ok)} | No visibility into SMTP TLS failures |",
            f"| BIMI | {status(bimi_ok)} | Brand logo not shown in email clients |",
            f"| DNSSEC | {status(dnssec_ok)} | DNS cache poisoning possible |",
            f"| CAA records | {status(caa_ok)} | Any CA can issue certificates |",
            f"| security.txt | {status(sec_ok)} | No responsible disclosure channel |",
            f"| SMTP banner verified | {status(smtp_ok)} | MX provider identity unconfirmed |",
        ]
        return "\n".join(lines)

    def render(self, fmt: str = "json", brand: "BrandConfig" = None) -> str:
        if fmt == "json":     return json.dumps(self.to_dict(), indent=2, default=str)
        if fmt == "markdown": return self.to_markdown(brand=brand)
        if fmt == "html":     return self.to_html(brand=brand)
        raise ValueError(f"Unknown format: {fmt}")

    def to_html(self, brand: "BrandConfig" = None) -> str:
        raise NotImplementedError

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        raise NotImplementedError

    def to_dict(self, brand: "BrandConfig" = None) -> dict:
        raise NotImplementedError

    # --- Shared helpers -----------------------------------------------------

    def _findings_by_severity(self, max_severity: str = "info") -> list[dict]:
        cutoff = _SEV_ORDER.get(max_severity, 5)
        return [f for f in self.findings if _SEV_ORDER.get(f.get("severity", "info"), 5) <= cutoff]

    def _sorted_findings(self) -> list[dict]:
        return sorted(self.findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 5))

    def _key_finding(self) -> str:       return self.narrative.get("key_finding", "")
    def _executive_summary(self) -> str: return self.narrative.get("executive_summary", "")
    def _threat_narrative(self) -> str:  return self.narrative.get("threat_narrative", "")
    def _positive_signals(self) -> str:  return self.narrative.get("positive_signals", "")
    def _remediation_priority(self) -> str: return self.narrative.get("remediation_priority", "")
    def _insurer_signals(self) -> str:   return self.narrative.get("insurer_signals", "")
    def _saas_stack_analysis(self) -> str: return self.narrative.get("saas_stack_analysis", "")


# ---------------------------------------------------------------------------
# 1. Insurer renderer
# ---------------------------------------------------------------------------

class InsurerRenderer(BaseRenderer):

    def to_dict(self) -> dict:
        return {
            "report_type":    "cyber_risk_underwriting",
            "domain":         self.domain,
            "subdomains":     self.subdomains,
            "cert_analysis":  self.cert_analysis,
            "rdap":           self.rdap,
            "generated_at":   self.o["generated_at"],
            "risk_score":     self.cs["score"],
            "risk_band":      self.cs["risk_band"],
            "confidence":     self.cs["confidence"],
            "primary_driver": self.cs["primary_driver"],
            "score_components": self.cs["components"],
            "exposure_summary": self._exposure_summary(),
            "key_risk_signals": self._key_signals(),
            "email_authentication": {
                "spf":            self.ea["spf"],
                "dmarc_policy":   self.ea["dmarc_policy"],
                "dmarc_pct":      self.ea["dmarc_pct"],
                "is_spoofable":   self.ea["is_spoofable"],
                "missing_layers": self.ea["missing_layers"],
            },
            "infrastructure": {
                "mx_provider":  self.infra["mx_provider"],
                "mx_category":  self.infra["mx_category"],
                "isp":          self.infra["isp"],
                "asn":          self.infra["asn"],
                "dual_stack":   self.infra["dual_stack"],
            },
            "certificates": {
                "https_days_left":        self.certs["https_days_left"],
                "smtp_provider_verified": self.certs["provider_live"],
            },
            "technographics":   self.tech,
            "txt_intelligence": self.txt_intel,
            "labels":           self.labels,
            "threat_flags":     self.flags,
            "change_signals":   self.changes,
            "risk_engine":      self.risk_engine,
            "narrative":        self.narrative,
            "critical_findings": [f for f in self.findings if f.get("severity") in ("critical", "high")],
        }

    def _exposure_summary(self) -> dict:
        critical = [f for f in self.findings if f.get("severity") == "critical"]
        high     = [f for f in self.findings if f.get("severity") == "high"]
        return {
            "total_findings":      len(self.findings),
            "critical":            len(critical),
            "high":                len(high),
            "spoofable":           self.ea["is_spoofable"],
            "spoofing_severity":   self.ea.get("spoofing_severity", "unknown"),
            "cert_expiring_soon":  self.certs.get("https_expiring", False),
            "any_change_signal":   self.changes.get("any_change", False),
            "any_threat_signal":   self.changes.get("any_threat", False),
            "missing_auth_layers": self.ea["missing_layers"],
        }

    def _key_signals(self) -> list[dict]:
        signals = []
        for f in [f for f in self.findings if f.get("severity") in ("critical", "high")]:
            signals.append({
                "signal":    f.get("finding", ""),
                "severity":  f.get("severity", "high"),
                "title":     f.get("title") or f.get("label", "Finding"),
                "evidence":  f.get("evidence", ""),
                "narrative": f.get("detail") or f.get("description", ""),
            })
        if self.ea["is_spoofable"]:
            signals.append({
                "signal":    "email_spoofing_exposure",
                "severity":  self.ea.get("spoofing_severity", "high"),
                "title":     f"Domain spoofable — {self.ea.get('spoofing_severity','').upper()}",
                "evidence":  f"SPF: {self.ea['spf']}, DMARC: {self.ea['dmarc_policy'] or 'missing'}",
                "narrative": (
                    f"{self.domain} can be impersonated by any actor. Spoofed email would appear "
                    f"to come from a legitimate address with no technical barrier to delivery."
                ),
            })
        return signals

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        # Include cert expiry findings in counts
        extra_findings = self._cert_expiry_findings()
        original_findings = self.findings
        self.findings = extra_findings + self.findings

        exp = self._exposure_summary()
        lines = [
            f"# Cyber risk underwriting report — {self.domain}",
            f"*Generated {self.o['generated_at']}*", "",
        ]
        if self._key_finding():
            lines += [f"> **Key finding:** {self._key_finding()}", ""]
        lines += [
            f"## Risk score: {self.display_score}/100 — {self.display_risk_band.upper()}",
f"Confidence: {self.cs['confidence']} · Primary driver: {self.cyber_profile.get('primary_claim_vector', self.cs['primary_driver'])}"
            "", "## Exposure summary", "",
            "| Metric | Value |", "|--------|-------|",
            f"| Critical findings | {exp['critical']} |",
            f"| High findings | {exp['high']} |",
            f"| Spoofable | {'YES — ' + exp['spoofing_severity'] if exp['spoofable'] else 'No'} |",
            f"| MX provider | {self.infra['mx_provider'] or 'None detected'} |",
            f"| DMARC policy | {self.ea['dmarc_policy'] or 'Missing'} |",
            f"| SPF | {self.ea['spf'] or 'Missing'} |",
            f"| HTTPS cert days left | {self.certs['https_days_left'] or 'Unknown'} |",
            f"| Any change signal | {'Yes' if exp['any_change_signal'] else 'No'} |",
            "", "## Score breakdown", "",
            "| Component | Score |", "|-----------|-------|",
        ]
        for k, v in self.cs["components"].items():
            lines.append(f"| {k.replace('_',' ').title()} | {v} |")
        lines += ["", "## Critical and high findings", ""]
        for f in self._findings_by_severity("high"):
            lines += [
                f"### [{f.get('severity','info').upper()}] {f.get('title','Finding')}",
                str(f.get("detail") or ""),
                f"*Evidence:* `{f.get('evidence','n/a')}`",
                f"*Fix:* {str(f.get('remediation') or 'n/a')}", "",
            ]
        for section, content in [
            ("## Executive summary", self._executive_summary()),
            ("## Threat narrative", self._threat_narrative()),
            ("## Underwriting signals", self._insurer_signals()),
            ("## Positive signals", self._positive_signals()),
            ("## Remediation priorities", self._remediation_priority()),
            ("## SaaS stack analysis", self._saas_stack_analysis()),
        ]:
            if content:
                lines += [section, "", content, ""]
        lines += ["", self._rdap_md(), "", self._cert_analysis_md(), "", self._subdomains_md()]
        lines += ["", self._risk_breakdown_md(), "", self._technographics_md()]
        lines += ["", self._certs_md(), "", self._dns_records_md()]
        lines += ["", self._changes_md(), "", self._labels_md()]
        
        return "\n".join(lines)

    def to_html(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        score_colour = RISK_BAND_COLOUR.get(self.cs["risk_band"], "#666")
        

        # Prepend cert expiry and subdomain risk findings
        extra_findings = self._cert_expiry_findings()
        all_findings_combined = extra_findings + self.findings
        # Temporarily override for this render
        original_findings = self.findings
        self.findings = all_findings_combined
        exp = self._exposure_summary()  
        key_finding_html = ""
        if self._key_finding():
            key_finding_html = f"""
            <div style="background:#FAEEDA;border-left:4px solid #854F0B;padding:12px 16px;
                        border-radius:0 8px 8px 0;font-size:14px;font-weight:500;color:#412402;
                        margin-bottom:20px;line-height:1.5">{self._key_finding()}</div>"""

        grid_cards = f"""
          <div class="card"><div class="num" style="color:{RISK_COLOURS['critical']['border']}">{exp['critical']}</div><div class="lbl">Critical findings</div></div>
          <div class="card"><div class="num" style="color:{RISK_COLOURS['high']['border']}">{exp['high']}</div><div class="lbl">High findings</div></div>
          <div class="card"><div class="num" style="color:{'#A32D2D' if exp['spoofable'] else '#3B6D11'}">{'YES' if exp['spoofable'] else 'No'}</div><div class="lbl">Spoofable</div></div>
          <div class="card"><div class="num">{self.infra['mx_provider'] or '—'}</div><div class="lbl">Email gateway</div></div>
          <div class="card"><div class="num">{self.certs['https_days_left'] or '—'}d</div><div class="lbl">HTTPS cert expiry</div></div>
          <div class="card"><div class="num">{'Yes' if self.infra['dual_stack'] else 'No'}</div><div class="lbl">IPv6 dual-stack</div></div>
          <div class="card"><div class="num" style="color:{'#A32D2D' if not self.flags.get('has_caa') else '#3B6D11'}">{'None' if not self.flags.get('has_caa') else 'Present'}</div><div class="lbl">CAA records</div></div>
        """
        grid = self._html_score_ring_layout(grid_cards)

        executive_html = ""
        if self._executive_summary():
            executive_html = f'<h2>Executive summary</h2><div style="background:#f9f9f9;border-radius:8px;padding:14px 18px;font-size:13px;line-height:1.8;color:#333">{self._executive_summary()}</div>'

        insurer_html = ""
        if self._insurer_signals():
            insurer_html = f'<h2>Underwriting signals</h2><div style="background:#f0f4ff;border-left:3px solid #185FA5;padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;line-height:1.8;color:#0c2d5e">{self._insurer_signals()}</div>'

        narrative_html = ""
        if self._threat_narrative():
            narrative_html = f'<h2>Threat narrative</h2><p style="font-size:13px;line-height:1.8;color:#333">{self._threat_narrative()}</p>'

        positive_html = ""
        if self._positive_signals():
            positive_html = f'<div style="background:#EAF3DE;border-left:3px solid #3B6D11;padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#1a3d0f;margin:16px 0;line-height:1.6"><strong>Positive signals:</strong> {self._positive_signals()}</div>'

        remediation_html = ""
        if self._remediation_priority():
            remediation_html = f'<h2>Remediation priorities</h2><div style="background:#f9f9f9;border-radius:8px;padding:14px 18px;font-size:13px;line-height:1.9;color:#333;white-space:pre-line">{self._remediation_priority()}</div>'

        saas_html = ""
        if self._saas_stack_analysis():
            saas_html = f'<h2>SaaS stack analysis</h2><p style="font-size:13px;line-height:1.8;color:#333">{self._saas_stack_analysis()}</p>'

        signals_html = ""
        for sig in self._key_signals():
            c  = RISK_BAND_COLOUR.get(sig["severity"], "#666")
            bg = RISK_COLOURS.get(sig["severity"], RISK_COLOURS["high"])
            signals_html += (
                f'<div class="signal" style="border-color:{c};background:{bg["bg"]};color:{bg["text"]}">'
                f'<strong>{sig["title"]}</strong><br>'
                f'<span style="opacity:.85">{sig["narrative"]}</span><br>'
                f'<code style="font-size:11px;opacity:.7">{sig.get("evidence","")[:100]}</code></div>'
            )

        table = _findings_table(
            self._findings_by_severity("high"),
            [
                ("Asset / Finding", lambda f: f.get("title", "Finding")),
                ("Severity",        lambda f: _badge(f.get("severity","info"))),
                ("Evidence",        lambda f: f'<code>{f.get("evidence","")[:60]}</code>'),
                ("Fix",             lambda f: str(f.get("remediation","—"))[:80]),
            ],
        )

        # body is defined ONCE here, then appended to below
        body = f"""
        {key_finding_html}
        <h2>Risk overview</h2>
        {grid}
        {self._corpus_intelligence_html(brand)}
        {executive_html}
        {insurer_html}
        {narrative_html}
        {positive_html}
        <h2>Key risk signals</h2>
        {signals_html if signals_html else '<p style="color:#888;font-size:13px">No critical signals detected.</p>'}
        <h2>Critical and high findings</h2>
        {table}
        {remediation_html}
        {saas_html}
        {self._alerting_cta_html(brand)}
        {self._infrastructure_routing_html()}
        {self._risk_breakdown_html()}
        {self._technographics_html()}
        """

        # Append RDAP, cert analysis, subdomains AFTER body is defined
        body += self._rdap_html()
        body += self._cert_analysis_html()
        body += self._subdomains_html()

        # Restore original findings after rendering
        self.findings = original_findings

        return self._html_shell_branded(brand=brand, report_type="Cyber Risk Underwriting Report", body=body)


# ---------------------------------------------------------------------------
# 2. Consultant renderer
# ---------------------------------------------------------------------------

class ConsultantRenderer(BaseRenderer):

    REMEDIATION_GUIDES = {
        "no_mta_sts": (
            "1. Create DNS TXT record: `_mta-sts.{domain}` → `v=STSv1; id=<timestamp>`\n"
            "2. Serve policy at `https://mta-sts.{domain}/.well-known/mta-sts.txt`\n"
            "   Content: `version: STSv1\\nmode: enforce\\nmx: *.yourmx.com\\nmax_age: 86400`"
        ),
        "no_caa": (
            "Add CAA records for each CA you use:\n"
            "`0 issue \"letsencrypt.org\"`\n"
            "`0 issuewild \"letsencrypt.org\"`"
        ),
        "dmarc_quarantine_strict_alignment": (
            "Change `p=quarantine` to `p=reject` in your DMARC record.\n"
            "Run at pct=10 first to verify no legitimate mail is rejected, then increase to pct=100."
        ),
    }

    def to_dict(self) -> dict:
        return {
            "report_type":    "technical_security_assessment",
            "domain":         self.domain,
            "subdomains":     self.subdomains,
            "cert_analysis":  self.cert_analysis,
            "rdap":           self.rdap,
            "generated_at":   self.o["generated_at"],
            "score":          self.cs["score"],
            "risk_band":      self.cs["risk_band"],
            "email_auth":     self.ea,
            "infrastructure": self.infra,
            "certificates":   self.certs,
            "change_signals": self.changes,
            "findings": [{**f, "remediation_detail": self._remediation_detail(f)} for f in self._sorted_findings()],
            "missing_layers": self.ea["missing_layers"],
            "score_breakdown": self.score_breakdown,
            "narrative":      self.narrative,
        }

    def _remediation_detail(self, finding: dict) -> str:
        guide = self.REMEDIATION_GUIDES.get(finding.get("finding", ""))
        if guide:
            return guide.format(domain=self.domain)
        return finding.get("remediation") or ""

    #The findings loop is misplaced — it comes after the narrative sections instead of directly under ## Findings. Here's the corrected order:
    
    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()

        # Prepend cert expiry + subdomain risk findings
        extra_findings = self._cert_expiry_findings()
        original_findings = self.findings
        self.findings = extra_findings + self.findings

        lines = [
            f"# Technical security assessment — {self.domain}",
            f"*{self.o['generated_at']}*", "",
            f"Score: **{self.cs['score']}/100** ({self.cs['risk_band']}) · "
            f"Primary driver: {self.cs['primary_driver']}",
            "",
        ]

        # Key finding banner
        if self._key_finding():
            lines += [f"> **Key finding:** {self._key_finding()}", ""]

        # Email authentication summary table
        lines += [
            "## Email authentication", "",
            "| Layer | Status | Detail |",
            "|-------|--------|--------|",
            f"| SPF | {self.ea['spf'] or 'MISSING'} | "
            f"{'Hard fail' if self.ea['spf'] == '-all' else 'Soft fail' if self.ea['spf'] == '~all' else 'Not configured'} |",
            f"| DMARC | {'p=' + self.ea['dmarc_policy'] if self.ea['dmarc_policy'] else 'MISSING'} | "
            f"pct={self.ea['dmarc_pct']}, aspf={self.ea.get('aspf','?')}, adkim={self.ea.get('adkim','?')} |",
            f"| MTA-STS | {self.ea['mta_sts']} | — |",
            f"| TLS-RPT | {self.ea['tls_rpt']} | — |",
            f"| BIMI | {self.ea['bimi']} | — |",
            "",
        ]

        # Security layer checklist
        lines += [self._security_checklist_md(), ""]

        # Narrative sections
        if self._executive_summary():
            lines += ["## Executive summary", "", self._executive_summary(), ""]
        if self._threat_narrative():
            lines += ["## Threat analysis", "", self._threat_narrative(), ""]
        if self._positive_signals():
            lines += ["## Positive signals", "", self._positive_signals(), ""]
        if self._remediation_priority():
            lines += ["## Remediation priorities", "", self._remediation_priority(), ""]

        # Findings — directly under heading, deduplicated
        lines += ["## Findings", ""]
        for f in self._sorted_findings():
            lines += [
                f"### [{f['severity'].upper()}] {f['title']}",
                "",
                str(f.get("detail", "") or ""),
                "",
                f"**Evidence:** `{f.get('evidence', 'n/a')}`",
                "",
                f"**Remediation:** {self._remediation_detail(f)}",
                "",
            ]

        if self._saas_stack_analysis():
            lines += ["## SaaS stack analysis", "", self._saas_stack_analysis(), ""]

        # Supporting detail sections
        lines += ["", self._rdap_md()]
        lines += ["", self._cert_analysis_md()]
        lines += ["", self._subdomains_md()]
        lines += ["", self._risk_breakdown_md()]
        lines += ["", self._technographics_md()]
        lines += ["", self._certs_md()]
        lines += ["", self._dns_records_md()]
        lines += ["", self._changes_md()]
        lines += ["", self._labels_md()]

        # Restore original findings
        self.findings = original_findings

        return "\n".join(lines)

    def to_html(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()

        # --- Prepend cert expiry + subdomain risk findings ---
        extra_findings = self._cert_expiry_findings()
        original_findings = self.findings
        self.findings = extra_findings + self.findings

        # --- Email auth layers table ---
        auth_rows = ""
        for layer, status, detail in [
            ("SPF",
            self.ea["spf"] or "MISSING",
            "Hard fail (-all)" if self.ea["spf"] == "-all"
            else "Soft fail (~all)" if self.ea["spf"] == "~all"
            else "Not configured"),
            ("DMARC",
            ("p=" + self.ea["dmarc_policy"]) if self.ea["dmarc_policy"] else "MISSING",
            f"pct={self.ea['dmarc_pct']} · aspf={self.ea.get('aspf','?')} · adkim={self.ea.get('adkim','?')}"),
            ("MTA-STS", self.ea["mta_sts"],  "Inbound TLS enforcement"),
            ("TLS-RPT", self.ea["tls_rpt"],  "SMTP delivery failure reporting"),
            ("BIMI",    self.ea["bimi"],      "Brand logo in email clients"),
            ("CAA",
            "Present" if not any(f.get("finding") == "no_caa" for f in self.findings)
            else "MISSING",
            "Certificate authority restriction"),
        ]:
            ok = status not in ("MISSING", "NXDOMAIN", "NOT_FOUND")
            colour = "#3B6D11" if ok else "#A32D2D"
            auth_rows += (
                f"<tr><td style='padding:6px 10px;font-size:12px'>{layer}</td>"
                f"<td style='padding:6px 10px'>"
                f"<code style='color:{colour};font-size:11px'>{status}</code></td>"
                f"<td style='padding:6px 10px;font-size:12px;color:#666'>{detail}</td></tr>"
            )

        # --- All findings blocks ---
        findings_html = ""
        for f in self._sorted_findings():
            c = RISK_COLOURS.get(f.get("severity", "info"), RISK_COLOURS["info"])
            findings_html += (
                f'<div style="border:1px solid {c["border"]};'
                f'border-left:3px solid {c["border"]};'
                f'border-radius:0 6px 6px 0;padding:12px 16px;'
                f'margin:8px 0;background:{c["bg"]}">'
                f'<div style="display:flex;justify-content:space-between;'
                f'align-items:flex-start;margin-bottom:6px">'
                f'<strong style="font-size:13px;color:{c["text"]}">'
                f'{f.get("title","Finding")}</strong>'
                f'{_badge(f.get("severity","info"))}</div>'
                f'<div style="font-size:12px;color:#333;margin-bottom:6px;line-height:1.6">'
                f'{f.get("detail","")}</div>'
                f'<code style="font-size:11px;background:rgba(0,0,0,.05);'
                f'padding:2px 6px;border-radius:3px;display:block;margin:4px 0">'
                f'{f.get("evidence","")[:100]}</code>'
                f'<div style="font-size:11px;color:#555;margin-top:6px;font-style:italic">'
                f'Fix: {(self._remediation_detail(f) or "")[:120]}</div>'
                f'</div>'
            )

        # --- Score ring + summary cards ---
        grid_cards = f"""
        <div class="card">
            <div class="num" style="color:{RISK_COLOURS['critical']['border']}">
            {len([f for f in self.findings if f.get('severity')=='critical'])}
            </div>
            <div class="lbl">Critical findings</div>
        </div>
        <div class="card">
            <div class="num" style="color:{RISK_COLOURS['high']['border']}">
            {len([f for f in self.findings if f.get('severity')=='high'])}
            </div>
            <div class="lbl">High findings</div>
        </div>
        <div class="card">
            <div class="num" style="font-size:14px;line-height:1.2;margin-top:8px">
            {self.cs['primary_driver']}
            </div>
            <div class="lbl">Primary driver</div>
        </div>
        <div class="card">
            <div class="num" style="color:{'#A32D2D' if self.ea['is_spoofable'] else '#3B6D11'}">
            {'YES' if self.ea['is_spoofable'] else 'No'}
            </div>
            <div class="lbl">Spoofable</div>
        </div>
        <div class="card">
            <div class="num" style="color:{'#A32D2D' if not self.flags.get('has_caa') else '#3B6D11'}">
            {'None' if not self.flags.get('has_caa') else 'Present'}
            </div>
            <div class="lbl">CAA records</div>
        </div>
        <div class="card">
            <div class="num" style="color:{'#A32D2D' if self.cert_analysis.get('summary',{}).get('missed_renewals',0) > 0 else '#3B6D11'}">
            {self.cert_analysis.get('summary',{}).get('missed_renewals',0)}
            </div>
            <div class="lbl">Missed renewals</div>
        </div>
        """
        body = self._html_score_ring_layout(grid_cards)

        # --- Key finding banner ---
        if self._key_finding():
            body += f"""
            <div style="background:#FAEEDA;border-left:4px solid #854F0B;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:14px;font-weight:500;color:#412402;
                        margin-bottom:20px;line-height:1.5">
            {self._key_finding()}
            </div>"""

        # --- Corpus intelligence ---
        body += self._corpus_intelligence_html(brand)

        # --- Executive summary ---
        if self._executive_summary():
            body += f"""
            <h2>Executive summary</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
            {self._executive_summary()}
            </p>"""

        # --- Threat analysis ---
        if self._threat_narrative():
            body += f"""
            <h2>Threat analysis</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
            {self._threat_narrative()}
            </p>"""

        # --- Positive signals ---
        if self._positive_signals():
            body += f"""
            <div style="background:#EAF3DE;border-left:3px solid #3B6D11;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:13px;color:#1a3d0f;margin:16px 0;line-height:1.6">
            <strong>Positive signals:</strong> {self._positive_signals()}
            </div>"""

        # --- Email authentication layers ---
        body += f"""
        <h2>Email authentication layers</h2>
        <table style="width:100%;border-collapse:collapse;background:#fafafa;
                    border-radius:8px;overflow:hidden">
        <thead><tr style="background:#f0f0f0">
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em">Layer</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em">Status</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em">Detail</th>
        </tr></thead>
        <tbody>{auth_rows}</tbody>
        </table>"""

        # --- Remediation priorities ---
        if self._remediation_priority():
            body += f"""
            <h2>Remediation priorities</h2>
            <div style="background:#f9f9f9;border-radius:8px;padding:14px 18px;
                        font-size:13px;line-height:1.9;color:#333;white-space:pre-line">
            {self._remediation_priority()}
            </div>"""

        # --- All findings ---
        body += f"<h2>All findings</h2>{findings_html}"

        # --- SaaS stack analysis ---
        if self._saas_stack_analysis():
            body += f"""
            <h2>SaaS stack analysis</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
            {self._saas_stack_analysis()}
            </p>"""

        # --- Alerting CTA ---
        body += self._alerting_cta_html(brand)

        # --- Supporting sections ---
        body += self._infrastructure_routing_html()
        body += self._risk_breakdown_html()
        body += self._technographics_html()
        body += self._rdap_html()
        body += self._cert_analysis_html()
        body += self._subdomains_html()

        # --- Restore original findings ---
        self.findings = original_findings

        return self._html_shell_branded(brand, "Technical Security Assessment", body)


# ---------------------------------------------------------------------------
# 3. IT renderer
# ---------------------------------------------------------------------------

class ITRenderer(BaseRenderer):

    PRIORITY = {
        "critical": ("Fix immediately",  "#A32D2D"),
        "high":     ("Fix this sprint",  "#854F0B"),
        "medium":   ("Fix this quarter", "#185FA5"),
        "info":     ("Review / backlog", "#3B6D11"),
    }

    OWNER_MAP = {
        "no_mta_sts":                        "Email / platform team",
        "no_tls_rpt":                        "Email / platform team",
        "no_bimi":                           "Marketing + email team",
        "no_caa":                            "DNS / infrastructure team",
        "no_security_txt":                   "Security team",
        "mixed_cert_authorities":            "Platform / DevOps team",
        "cert_expiring_soon":                "Platform / DevOps team",
        "spoofable_domain":                  "DNS / email team",
        "dmarc_quarantine_strict_alignment": "Email / security team",
        "mx_provider_banner_confirmed":      "Email team (informational)",
        "fast_flux_ttl_penalty":             "DNS / infrastructure team",
        "network_risk":                      "Infrastructure team",
        "asn_risk_critical":                 "Infrastructure team",
        "asn_risk_high":                     "Infrastructure team",
    }

    def _owner(self, finding: dict) -> str:
        return self.OWNER_MAP.get(finding.get("finding", ""), "Infrastructure team")

    def _action(self, finding: dict) -> str:
        remediation = finding.get("remediation", "")
        return remediation[:120] if remediation else "Review and action"

    def to_dict(self) -> dict:
        return {
            "report_type":    "it_action_list",
            "domain":         self.domain,
            "subdomains":     self.subdomains,
            "cert_analysis":  self.cert_analysis,
            "rdap":           self.rdap,
            "generated_at":   self.o["generated_at"],
            "risk_score":     self.cs["score"],
            "risk_band":      self.cs["risk_band"],
            "primary_driver": self.cs["primary_driver"],
            "action_items": [
                {
                    "priority": self.PRIORITY[f.get("severity","info")][0],
                    "severity": f.get("severity","info"),
                    "title":    f["title"],
                    "owner":    self._owner(f),
                    "action":   self._action(f),
                    "evidence": f.get("evidence",""),
                    "detail":   f.get("detail",""),
                }
                for f in self._sorted_findings()
                if f.get("severity") != "info"
            ],
            "backlog": [
                {"title": f["title"], "owner": self._owner(f), "action": self._action(f)}
                for f in self.findings if f.get("severity") == "info"
            ],
            "email_auth":     self.ea,
            "infrastructure": self.infra,
            "technographics": self.tech,
            "certificates":   self.certs,
            "dns_records":    self.dns,
            "labels":         self.labels,
            "change_signals": self.changes,
            "risk_engine":    self.risk_engine,
            "narrative":      self.narrative,
        }

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        lines = [
            f"# IT action list — {self.domain}",
            f"*{self.o['generated_at']}*", "",
            f"Score: {self.cs['score']}/100 ({self.cs['risk_band']}) · Primary driver: {self.cs['primary_driver']}",
            "",
        ]
        if self._key_finding():
            lines += [f"> {self._key_finding()}", ""]
        if self._threat_narrative():
            lines += ["## Context", "", self._threat_narrative(), ""]
        if self._remediation_priority():
            lines += ["## Remediation priorities", "", self._remediation_priority(), ""]
        for sev in ["critical", "high", "medium"]:
            label, _ = self.PRIORITY[sev]
            items = [f for f in self.findings if f.get("severity") == sev]
            if not items:
                continue
            lines += [f"## {label} ({len(items)})", ""]
            for f in items:
                lines += [
                    f"- **{f['title']}**",
                    f"  - Owner: {self._owner(f)}",
                    f"  - Action: {self._action(f)}",
                    f"  - Evidence: `{f.get('evidence','')[:80]}`",
                    f"  - Detail: {f.get('detail','')[:120]}",
                    "",
                ]
        if self._positive_signals():
            lines += ["## What is configured correctly", "", self._positive_signals(), ""]
        lines += ["", self._rdap_md(), "", self._cert_analysis_md(), "", self._subdomains_md()]
        lines += ["", self._risk_breakdown_md(), "", self._technographics_md()]
        lines += ["", self._certs_md(), "", self._dns_records_md()]
        lines += ["", self._changes_md(), "", self._labels_md()]
        return "\n".join(lines)

    def to_html(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()

        # --- Prepend cert expiry + subdomain risk findings ---
        extra_findings = self._cert_expiry_findings()
        original_findings = self.findings
        self.findings = extra_findings + self.findings

        # --- Counts after merging extra findings ---
        counts = {
            sev: sum(1 for f in self.findings if f.get("severity") == sev)
            for sev in ["critical", "high", "medium", "info"]
        }

        # --- Key finding banner ---
        key_finding_html = ""
        if self._key_finding():
            key_finding_html = f"""
            <div style="background:#FAEEDA;border-left:4px solid #854F0B;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:14px;font-weight:500;color:#412402;
                        margin-bottom:20px;line-height:1.5">
            {self._key_finding()}
            </div>"""

        # --- Score ring + action summary cards ---
        grid_cards = f"""
        <div class="card" style="border-left:3px solid #A32D2D">
            <div class="num" style="color:#A32D2D">{counts['critical']}</div>
            <div class="lbl">Fix immediately</div>
        </div>
        <div class="card" style="border-left:3px solid #854F0B">
            <div class="num" style="color:#854F0B">{counts['high']}</div>
            <div class="lbl">Fix this sprint</div>
        </div>
        <div class="card" style="border-left:3px solid #185FA5">
            <div class="num" style="color:#185FA5">{counts['medium']}</div>
            <div class="lbl">Fix this quarter</div>
        </div>
        <div class="card">
            <div class="num">{counts['info']}</div>
            <div class="lbl">Backlog</div>
        </div>
        <div class="card">
            <div class="num" style="color:{'#A32D2D' if self.cert_analysis.get('summary',{}).get('missed_renewals',0) > 0 else '#3B6D11'}">
            {self.cert_analysis.get('summary',{}).get('missed_renewals',0)}
            </div>
            <div class="lbl">Missed renewals</div>
        </div>
        <div class="card">
            <div class="num" style="color:{'#A32D2D' if not self.flags.get('has_caa') else '#3B6D11'}">
            {'None' if not self.flags.get('has_caa') else 'Present'}
            </div>
            <div class="lbl">CAA records</div>
        </div>
        """
        grid = self._html_score_ring_layout(grid_cards)

        # --- Action list table ---
        rows = ""
        for f in self._sorted_findings():
            label, colour = self.PRIORITY.get(f.get("severity", "info"), ("Review", "#666"))
            rows += (
                f"<tr>"
                f"<td style='padding:8px 10px;white-space:nowrap'>"
                f"<span style='color:{colour};font-weight:600;font-size:11px;"
                f"text-transform:uppercase'>{label}</span></td>"
                f"<td style='padding:8px 10px;font-size:12px'>"
                f"<strong>{f.get('title','')}</strong>"
                f"<div style='color:#666;font-size:11px;margin-top:2px'>"
                f"{f.get('detail','')[:100]}</div></td>"
                f"<td style='padding:8px 10px;font-size:12px;color:#555;white-space:nowrap'>"
                f"{self._owner(f)}</td>"
                f"<td style='padding:8px 10px;font-size:12px'>"
                f"{self._action(f)[:100]}</td>"
                f"<td style='padding:8px 10px;font-family:monospace;font-size:11px;"
                f"color:#666;max-width:180px;word-break:break-all'>"
                f"{f.get('evidence','')[:60]}</td>"
                f"</tr>"
            )

        action_table = f"""
        <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#f5f5f5">
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em;
                    white-space:nowrap">Priority</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em">Finding</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em">Owner</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em">Action</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px;
                    text-transform:uppercase;letter-spacing:.04em">Evidence</th>
        </tr></thead>
        <tbody>{rows}</tbody>
        </table>"""

        # --- Context / threat narrative ---
        context_html = ""
        if self._threat_narrative():
            context_html = f"""
            <h2>Context</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
            {self._threat_narrative()}
            </p>"""

        # --- Remediation priorities ---
        remediation_html = ""
        if self._remediation_priority():
            remediation_html = f"""
            <h2>Remediation priorities</h2>
            <div style="background:#f9f9f9;border-radius:8px;padding:14px 18px;
                        font-size:13px;line-height:1.9;color:#333;white-space:pre-line">
            {self._remediation_priority()}
            </div>"""

        # --- Positive signals ---
        positive_html = ""
        if self._positive_signals():
            positive_html = f"""
            <div style="background:#EAF3DE;border-left:3px solid #3B6D11;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:13px;color:#1a3d0f;margin:16px 0;line-height:1.6">
            <strong>What is configured correctly:</strong> {self._positive_signals()}
            </div>"""

        # --- Assemble body ---
        body = f"""
        {key_finding_html}
        <h2>Action summary</h2>
        {grid}
        """

        # Corpus intelligence — shows co-host risk and blocklist status
        # directly relevant to IT teams making infrastructure decisions
        body += self._corpus_intelligence_html(brand)

        body += f"""
        {context_html}
        {remediation_html}
        <h2>Full action list</h2>
        {action_table}
        {positive_html}
        """

        # Alerting CTA — positioned after the action list where IT team
        # is primed to think about continuous monitoring
        body += self._alerting_cta_html(brand)

        # Supporting detail sections
        body += self._infrastructure_routing_html()
        body += self._risk_breakdown_html()
        body += self._technographics_html()
        body += self._rdap_html()
        body += self._cert_analysis_html()
        body += self._subdomains_html()

        # --- Restore original findings ---
        self.findings = original_findings

        return self._html_shell_branded(brand, "IT Security Action List", body)


# ---------------------------------------------------------------------------
# 4. Sales renderer
# ---------------------------------------------------------------------------

class SalesRenderer(BaseRenderer):

    def _hook(self) -> str:
        parts = []
        critical = [f for f in self.findings if f.get("severity") == "critical"]
        if critical:
            parts.append(f"We found {len(critical)} critical issue{'s' if len(critical) > 1 else ''} in {self.domain}'s infrastructure that an attacker could exploit today.")
        if self.ea["is_spoofable"]:
            parts.append(f"Anyone can currently send email that appears to come from @{self.domain} — with no technical access to your systems required.")
        high = [f for f in self.findings if f.get("severity") == "high"]
        if high and not parts:
            parts.append(f"We identified {len(high)} high-priority security gaps in {self.domain}'s public infrastructure.")
        return " ".join(parts) or f"We have a security brief prepared for {self.domain}."

    def _plain_english(self, finding: dict) -> str:
        mapping = {
            "no_mta_sts":                        "Email in transit can be intercepted — no TLS enforcement on inbound mail",
            "no_caa":                            "Any certificate authority could issue a fake TLS certificate for your domain",
            "dmarc_quarantine_strict_alignment": "Spoofed emails go to spam instead of being blocked — one config change away from full protection",
            "no_security_txt":                   "No public contact point for security researchers to report vulnerabilities",
            "spoofable_domain":                  "Your domain can be impersonated in email — no technical barrier for attackers",
            "cert_expiring_soon":                f"HTTPS certificate expires in {self.certs.get('https_days_left','?')} days — site will show security warnings if not renewed",
            "mixed_cert_authorities":            "Two different certificate authorities in use — increases cert management risk",
            "fast_flux_ttl_penalty":             "DNS configuration pattern associated with unstable or rapidly-changing infrastructure",
            "network_risk":                      "Hosting network has elevated risk classification",
            "mx_provider_banner_confirmed":      "Email security gateway confirmed live and operational",
        }
        return mapping.get(finding.get("finding", ""), finding.get("detail", "")[:120])

    def _talking_points(self) -> list[str]:
        points = []
        if self.ea["is_spoofable"]:
            points.append(f"The most immediate risk is email impersonation. Right now, anyone can send email that looks like it's from {self.domain}. That's a phishing platform you're unintentionally providing — and it takes three DNS records to close.")
        missing = self.ea.get("missing_layers", [])
        if len(missing) >= 3:
            points.append(f"There are {len(missing)} missing security layers: {', '.join(missing[:3])}{'...' if len(missing) > 3 else ''}. Each one is a gap that attackers actively probe for.")
        if self.certs.get("https_expiring"):
            points.append(f"Your HTTPS certificate expires in {self.certs.get('https_days_left')} days. After that, every visitor to your site sees a security warning.")
        if self.changes.get("any_change_signal"):
            points.append("We detected recent infrastructure changes — NS, IP, or country records have changed. These are worth investigating in the context of recent threat activity.")
        if self.txt_intel.get("high_risk_saas") or any(k in str(self.txt_intel.get("all_identified", [])).lower() for k in ("lastpass", "okta", "twilio")):
            points.append("We identified SaaS services in your stack with confirmed breach history. Credentials stored in these services may have been exposed and should be treated as a priority rotation.")
        if not points:
            points.append(f"Your overall risk score is {self.cs['score']}/100 ({self.cs['risk_band']}). We can walk through specific recommendations to bring that down.")
        return points

    def to_dict(self) -> dict:
        return {
            "report_type":  "sales_prospect_brief",
            "domain":       self.domain,
            "generated_at": self.o["generated_at"],
            "hook":         self._hook(),
            "headline_numbers": {
                "total_findings": len(self.findings),
                "critical":       sum(1 for f in self.findings if f.get("severity") == "critical"),
                "high":           sum(1 for f in self.findings if f.get("severity") == "high"),
                "spoofable":      self.ea["is_spoofable"],
                "missing_layers": len(self.ea.get("missing_layers", [])),
                "saas_count":     self.txt_intel.get("total_identified", 0),
            },
            "talking_points": self._talking_points(),
            "top_findings": [
                {"title": f["title"], "plain_english": self._plain_english(f), "severity": f.get("severity")}
                for f in self._sorted_findings()[:5]
            ],
            "saas_stack": self.txt_intel.get("all_identified", []),
            "narrative":  self.narrative,
        }

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        lines = [
            f"# Infrastructure brief — {self.domain}",
            f"*Prepared {self.o['generated_at']}*", "",
            "## What we found", "", self._hook(), "",
        ]
        if self._key_finding():
            lines += [f"> {self._key_finding()}", ""]
        lines += [
            "## The numbers", "",
            f"- **{len(self.findings)}** security issues identified",
            f"- **{sum(1 for f in self.findings if f.get('severity') in ('critical','high'))}** require priority attention",
            f"- Spoofable: **{'Yes' if self.ea['is_spoofable'] else 'No'}**",
            f"- Missing auth layers: **{', '.join(self.ea.get('missing_layers',[]) or ['None'])}**",
            f"- SaaS platforms identified: **{self.txt_intel.get('total_identified',0)}**",
            "", "## Talking points", "",
        ]
        for p in self._talking_points():
            lines += [f"- {p}", ""]
        lines += ["## Top findings", ""]
        for f in self._sorted_findings()[:5]:
            lines.append(f"- **{f['title']}** — {self._plain_english(f)}")
        if self._threat_narrative():
            lines += ["", "## Context", "", self._threat_narrative()]
        if self._saas_stack_analysis():
            lines += ["", "## SaaS stack", "", self._saas_stack_analysis()]
        return "\n".join(lines)

    def to_html(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()

        # --- Prepend cert expiry + subdomain risk findings ---
        extra_findings = self._cert_expiry_findings()
        original_findings = self.findings
        self.findings = extra_findings + self.findings

        # --- Recalculate nums with merged findings ---
        nums = {
            "total_findings": len(self.findings),
            "critical":       sum(1 for f in self.findings if f.get("severity") == "critical"),
            "high":           sum(1 for f in self.findings if f.get("severity") == "high"),
            "spoofable":      self.ea["is_spoofable"],
            "missing_layers": len(self.ea.get("missing_layers", [])),
            "saas_count":     self.txt_intel.get("total_identified", 0),
        }

        # --- Hook banner ---
        hook_html = f"""
        <div style="background:#FAEEDA;border-left:4px solid #854F0B;
                    padding:14px 18px;border-radius:0 8px 8px 0;
                    margin-bottom:24px;font-size:14px;color:#412402;line-height:1.6">
        {self._hook()}
        </div>"""

        # --- Key finding ---
        key_finding_html = ""
        if self._key_finding():
            key_finding_html = f"""
            <div style="font-size:14px;font-weight:500;color:#111;
                        margin-bottom:20px;line-height:1.5;
                        padding:12px 16px;background:#f9f9f9;border-radius:8px">
            {self._key_finding()}
            </div>"""

        # --- Score ring + headline cards ---
        grid_cards = f"""
        <div class="card">
            <div class="num">{nums['total_findings']}</div>
            <div class="lbl">Issues found</div>
        </div>
        <div class="card">
            <div class="num" style="color:#A32D2D">
            {nums['critical'] + nums['high']}
            </div>
            <div class="lbl">Priority issues</div>
        </div>
        <div class="card">
            <div class="num" style="color:{'#A32D2D' if nums['spoofable'] else '#3B6D11'}">
            {'Yes' if nums['spoofable'] else 'No'}
            </div>
            <div class="lbl">Spoofable now</div>
        </div>
        <div class="card">
            <div class="num">{nums['missing_layers']}</div>
            <div class="lbl">Missing auth layers</div>
        </div>
        <div class="card">
            <div class="num">{nums['saas_count']}</div>
            <div class="lbl">SaaS platforms</div>
        </div>
        <div class="card">
            <div class="num" style="color:{'#A32D2D' if nums['critical'] > 0 else '#854F0B' if nums['high'] > 0 else '#3B6D11'}">
            {nums['critical'] if nums['critical'] > 0 else nums['high']}
            </div>
            <div class="lbl">{'Critical' if nums['critical'] > 0 else 'High'} findings</div>
        </div>
        """
        grid = self._html_score_ring_layout(grid_cards)

        # --- Talking points ---
        talking_html = "".join(
            f'<li style="margin-bottom:10px;line-height:1.6">{p}</li>'
            for p in self._talking_points()
        )

        # --- Top 5 findings in plain English ---
        top5_html = "".join(
            f'<div style="padding:10px 0;border-bottom:1px solid #f0f0f0">'
            f'{_badge(f.get("severity","info"))} '
            f'<strong style="font-size:13px;margin-left:6px">{f.get("title","")}</strong>'
            f'<div style="font-size:12px;color:#555;margin-top:4px;padding-left:2px">'
            f'{self._plain_english(f)}</div></div>'
            for f in self._sorted_findings()[:5]
        )

        # --- Threat narrative / context ---
        narrative_html = ""
        if self._threat_narrative():
            narrative_html = f"""
            <h2>Context</h2>
            <p style="font-size:13px;line-height:1.8;color:#444">
            {self._threat_narrative()}
            </p>"""

        # --- SaaS stack analysis ---
        saas_analysis_html = ""
        if self._saas_stack_analysis():
            saas_analysis_html = f"""
            <h2>SaaS stack analysis</h2>
            <p style="font-size:13px;line-height:1.8;color:#444">
            {self._saas_stack_analysis()}
            </p>"""

        # --- SaaS pills ---
        saas_pills = ""
        for svc in self.txt_intel.get("all_identified", []):
            is_risky = any(
                k in svc.lower()
                for k in ("lastpass","okta","twilio","mailchimp","circleci")
            )
            style = (
                "background:#FCEBEB;color:#791F1F"
                if is_risky else
                "background:#EEEDFE;color:#3C3489"
            )
            saas_pills += (
                f'<span style="{style};padding:2px 8px;border-radius:4px;'
                f'font-size:11px;font-weight:500;display:inline-block;'
                f'margin:2px 3px 2px 0">{svc}</span>'
            )

        # --- Corpus intelligence teaser ---
        # For sales, this is a value demonstration not a deep technical section.
        # Show the headline numbers only — the full section is for technical audiences.
        
        corr = self.o.get("infrastructure_correlation") or {}
        bgp  = self.o.get("bgp_routing") or self.o.get("bgp_intelligence") or {}
        conc = self.o.get("infrastructure_concentration") or {}
        bl   = self.o.get("blocklist_signals") or self.o.get("ip_reputation") or {}
        domains_on_ip = conc.get('domains_on_ip')
        domains_on_ip_display = f"{domains_on_ip:,}" if isinstance(domains_on_ip, int) else '—'
        any_malicious = any(
            p.get("malicious_count", 0) > 0
            for p in corr.get("pivot_findings", [])
        )
        any_listed = bl.get("any_listed") or bl.get("spamhaus_zen") or bl.get("urlhaus_listed")
        moas = bgp.get("moas_detected", False)

        corpus_teaser = f"""
        <h2 style="display:flex;justify-content:space-between;align-items:baseline">
        <span>Infrastructure intelligence</span>
        <span style="font-size:11px;font-weight:400;color:#888;
                    text-transform:none;letter-spacing:0">
            320M domain corpus · updated hourly
        </span>
        </h2>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0">
        <div style="background:{'#FCEBEB' if any_malicious else '#EAF3DE'};
                    border-radius:8px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:800;
                        color:{'#A32D2D' if any_malicious else '#3B6D11'}">
            {sum(p.get('malicious_count',0) for p in corr.get('pivot_findings',[]))}
            </div>
            <div style="font-size:10px;color:#555;margin-top:4px;
                        text-transform:uppercase;letter-spacing:.05em">
            Malicious co-hosts
            </div>
        </div>
        <div style="background:{'#FCEBEB' if any_listed else '#EAF3DE'};
                    border-radius:8px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:800;
                        color:{'#A32D2D' if any_listed else '#3B6D11'}">
            {'Listed' if any_listed else 'Clean'}
            </div>
            <div style="font-size:10px;color:#555;margin-top:4px;
                        text-transform:uppercase;letter-spacing:.05em">
            Blocklist status
            </div>
        </div>
        <div style="background:{'#FCEBEB' if moas else '#EAF3DE'};
                    border-radius:8px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:800;
                        color:{'#A32D2D' if moas else '#3B6D11'}">
            {'MOAS' if moas else 'Clean'}
            </div>
            <div style="font-size:10px;color:#555;margin-top:4px;
                        text-transform:uppercase;letter-spacing:.05em">
            BGP / routing
            </div>
        </div>
        <div style="background:#f7f8f9;border-radius:8px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:800;color:#374151">
            {domains_on_ip_display}
            </div>
            <div style="font-size:10px;color:#555;margin-top:4px;
                        text-transform:uppercase;letter-spacing:.05em">
            Domains on same IP
            </div>
        </div>
        </div>
        <div style="font-size:11px;color:#888;line-height:1.6;margin-bottom:8px">
        Intelligence derived from Datazag's passive corpus of 320M domains, updated
        hourly across 40+ threat feeds — a level of context not available from any
        single-domain scanner.
        </div>"""

        # --- Assemble body ---
        body = f"""
        {hook_html}
        {key_finding_html}
        <h2>Headline numbers</h2>
        {grid}
        <h2>Talking points</h2>
        <ul style="padding-left:18px;font-size:13px">{talking_html}</ul>
        <h2>Top findings</h2>
        {top5_html}
        {narrative_html}
        {corpus_teaser}
        {saas_analysis_html}
        {f'<h2>Identified SaaS platforms ({self.txt_intel.get("total_identified",0)})</h2>'
        f'<div style="margin:10px 0">{saas_pills}</div>' if saas_pills else ''}
        {self._infrastructure_routing_html()}
        """

        # CTA is the goal of the entire sales report —
        # place it last so it's the final thing they read
        body += self._alerting_cta_html(brand)

        # --- Restore original findings ---
        self.findings = original_findings

        return self._html_shell_branded(brand, "Infrastructure Intelligence Brief", body)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

RENDERERS = {
    "insurer":    InsurerRenderer,
    "consultant": ConsultantRenderer,
    "it":         ITRenderer,
    "sales":      SalesRenderer,
}


def render_all(
    output: dict,
    formats: list[str] = ("json", "markdown", "html"),
    audiences: list[str] = ("insurer", "consultant", "it", "sales"),
    brand: "BrandConfig" = None,
) -> dict[str, dict[str, str]]:
    brand = brand or BrandConfig.load()
    return {
        audience: {
            fmt: RENDERERS[audience](output).render(fmt, brand=brand)
            for fmt in formats
        }
        for audience in audiences
    }
