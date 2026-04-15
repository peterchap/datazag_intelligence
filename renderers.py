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

RISK_BAND_COLOUR = {
    "critical": "#A32D2D",
    "high":     "#854F0B",
    "medium":   "#185FA5",
    "low":      "#3B6D11",
}


def _badge(severity: str) -> str:
    c = RISK_COLOURS.get(severity, RISK_COLOURS["info"])
    return (
        f'<span style="background:{c["bg"]};color:{c["text"]};'
        f'padding:2px 8px;border-radius:4px;font-size:11px;'
        f'font-weight:600;text-transform:uppercase">{severity}</span>'
    )


def _score_bar(score: int, invert: bool = True) -> str:
    """Visual 0–100 bar. invert=True means higher = more red."""
    if invert:
        colour = "#A32D2D" if score >= 75 else "#854F0B" if score >= 40 else "#3B6D11"
    else:
        colour = "#3B6D11" if score >= 75 else "#854F0B" if score >= 40 else "#A32D2D"
    return (
        f'<div style="background:#eee;border-radius:3px;'
        f'height:6px;width:100%;margin:4px 0">'
        f'<div style="background:{colour};width:{score}%;'
        f'height:100%;border-radius:3px"></div></div>'
    )


def _findings_table(
    findings: list[dict],
    columns: list[tuple],
    max_rows: int = 50,
) -> str:
    th = ('style="text-align:left;padding:8px 12px;font-size:11px;'
          'font-weight:600;border-bottom:1px solid #e0e0e0;'
          'color:#666;text-transform:uppercase;letter-spacing:.04em;'
          'white-space:nowrap"')
    td = ('style="padding:7px 12px;font-size:12px;'
          'border-bottom:1px solid #f5f5f5;vertical-align:top"')

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


def _html_shell(title: str, subtitle: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  body  {{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
          font-size:14px;color:#1a1a1a;margin:0;padding:32px 40px;
          background:#fff;max-width:960px;margin:0 auto}}
  h1    {{font-size:24px;font-weight:600;margin:0 0 4px;letter-spacing:-.02em}}
  h2    {{font-size:15px;font-weight:600;margin:32px 0 12px;
          border-bottom:1px solid #ebebeb;padding-bottom:8px;color:#111}}
  h3    {{font-size:13px;font-weight:600;margin:18px 0 8px;color:#333}}
  .meta {{font-size:12px;color:#888;margin:0 0 28px}}
  .grid {{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
          gap:12px;margin:16px 0}}
  .card {{background:#f7f7f7;border-radius:8px;padding:14px 16px}}
  .card .num {{font-size:26px;font-weight:600;line-height:1.1}}
  .card .lbl {{font-size:11px;color:#666;margin-top:4px;text-transform:uppercase;
               letter-spacing:.04em}}
  .signal {{border-left:3px solid;padding:10px 14px;margin:8px 0;
            border-radius:0 6px 6px 0;font-size:13px;line-height:1.6}}
  code  {{font-family:ui-monospace,monospace;font-size:11px;
          background:#f0f0f0;padding:1px 5px;border-radius:3px}}
  table {{font-size:12px}}
  @media print {{body{{padding:16px}} .noprint{{display:none}}}}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="meta">{subtitle}</p>
{body}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Base renderer
# ---------------------------------------------------------------------------

class BaseRenderer:
    def __init__(self, output: dict):
        """
        output: the dict returned by run.py's run() function.
        Keys: domain, composite_score, email_auth, infrastructure,
              certificates, findings, narrative, risk_score_breakdown,
              change_signals, scanned_at, generated_at, audience
        """
        self.o = output
        self.domain      = output["domain"]
        self.cs          = output["composite_score"]
        self.ea          = output["email_auth"]
        self.infra       = output["infrastructure"]
        self.certs       = output["certificates"]
        self.findings    = output.get("findings", [])
        self.narrative   = output.get("narrative", {})
        self.changes     = output.get("change_signals", {})
        self.score_breakdown = output.get("risk_score_breakdown", [])

        # New full-fidelity fields
        self.dns      = output.get("dns_records", {})
        self.tech     = output.get("technographics", {})
        self.labels   = output.get("labels", {})
        self.flags    = output.get("threat_flags", {})
        self.txt_intel = output.get("txt_intelligence", {})
        self.risk_engine = output.get("risk_score_engine", {})

    # --- Branding and narrative -------------------------------------------

    def _html_header(self, brand: "BrandConfig", report_type: str) -> str:
        """
        Professional branded header with logo, report type, domain, and date.
        """
        return f"""
        <div style="background:{brand.primary_colour};margin:-32px -40px 32px;
                    padding:24px 40px;display:flex;justify-content:space-between;
                    align-items:flex-start">
        <div style="display:flex;align-items:center;gap:16px">
            {brand.wordmark_svg(height=36)}
            <div style="border-left:1px solid rgba(255,255,255,.2);
                        padding-left:16px;margin-left:4px">
            <div style="color:rgba(255,255,255,.6);font-size:11px;
                        text-transform:uppercase;letter-spacing:.08em;
                        margin-bottom:2px">{brand.report_prefix}</div>
            <div style="color:{brand.text_on_primary};font-size:13px;
                        font-weight:500">{report_type}</div>
            </div>
        </div>
        <div style="text-align:right">
            <div style="color:{brand.accent_colour};font-size:20px;
                        font-weight:700;letter-spacing:-.02em">{self.domain}</div>
            <div style="color:rgba(255,255,255,.5);font-size:11px;margin-top:3px">
            {self.o.get('generated_at','')[:10]}
            </div>
        </div>
        </div>"""


    def _html_contact_block(self, brand: "BrandConfig") -> str:
        """
        Contact and query section — professional, actionable.
        """
        phone_html = ""
        if brand.contact_phone:
            phone_html = f"""
            <div style="margin-top:6px">
            <span style="color:#888;font-size:12px">Phone </span>
            <a href="tel:{brand.contact_phone}"
                style="color:#333;font-size:12px;text-decoration:none">
                {brand.contact_phone}
            </a>
            </div>"""

        powered_by = ""
        if brand.is_white_label and brand.powered_by_text:
            powered_by = f"""
            <div style="margin-top:16px;padding-top:12px;
                        border-top:1px solid #f0f0f0;text-align:center">
            <span style="color:#ccc;font-size:10px">{brand.powered_by_text}</span>
            </div>"""

        return f"""
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;
                    margin-top:40px;padding-top:24px;
                    border-top:2px solid {brand.accent_colour}">

        <!-- Contact details -->
        <div>
            <div style="font-size:13px;font-weight:600;color:#111;margin-bottom:12px">
            Questions about this report?
            </div>
            <div>
            <span style="color:#888;font-size:12px">Email </span>
            <a href="mailto:{brand.contact_email}"
                style="color:{brand.primary_colour};font-size:12px;font-weight:500;
                        text-decoration:none">
                {brand.contact_email}
            </a>
            </div>
            {phone_html}
            <div style="margin-top:6px">
            <span style="color:#888;font-size:12px">Web </span>
            <a href="{brand.contact_web}" target="_blank"
                style="color:{brand.primary_colour};font-size:12px;text-decoration:none">
                {brand.contact_web}
            </a>
            </div>
            <div style="margin-top:8px;font-size:11px;color:#aaa">
            {brand.contact_address}
            </div>
        </div>

        <!-- CTA -->
        <div style="background:#f8f9fa;border-radius:10px;padding:16px 18px;
                    border-left:3px solid {brand.accent_colour}">
            <div style="font-size:13px;font-weight:600;color:#111;margin-bottom:6px">
            {brand.cta_heading}
            </div>
            <div style="font-size:12px;color:#555;line-height:1.6;margin-bottom:12px">
            {brand.cta_body}
            </div>
            <a href="{brand.cta_button_url}" target="_blank"
            style="display:inline-block;background:{brand.primary_colour};
                    color:{brand.text_on_primary};padding:8px 16px;
                    border-radius:5px;font-size:12px;font-weight:600;
                    text-decoration:none;letter-spacing:.01em">
            {brand.cta_button_text} →
            </a>
            <div style="margin-top:8px;font-size:11px;color:#888">
            {brand.cta_secondary_text}
            <a href="{brand.cta_secondary_url}"
                style="color:{brand.primary_colour};text-decoration:none">
                {brand.contact_email}
            </a>
            </div>
        </div>
        </div>
        {powered_by}"""


    def _html_footer(self, brand: "BrandConfig") -> str:
        """
        Confidentiality notice and report footer.
        """
        footer_text = "" if brand.is_white_label else brand.report_footer

        return f"""
        <div style="margin-top:40px;padding:16px 0;
                    border-top:1px solid #ebebeb">
        <div style="font-size:10px;color:#aaa;line-height:1.6;margin-bottom:8px">
            {brand.confidentiality_notice}
        </div>
        {f'<div style="font-size:10px;color:#ccc;line-height:1.6">{footer_text}</div>'
            if footer_text else ''}
        </div>"""


    def _html_shell_branded(
        self,
        brand: "BrandConfig",
        report_type: str,
        body: str,
    ) -> str:
        """
        Full HTML shell with branding. Replaces _html_shell() for all renderers.
        """
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{brand.report_prefix} — {self.domain}</title>
    <style>
    * {{ box-sizing: border-box }}
    body  {{
        font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        font-size: 14px; color: #1a1a1a; margin: 0;
        padding: 32px 40px; background: #fff;
        max-width: 1000px; margin: 0 auto;
    }}
    h1   {{ font-size: 24px; font-weight: 600; margin: 0 0 4px; letter-spacing: -.02em }}
    h2   {{
        font-size: 14px; font-weight: 700; margin: 28px 0 10px;
        text-transform: uppercase; letter-spacing: .06em;
        color: {brand.primary_colour};
        border-bottom: 2px solid {brand.accent_colour};
        padding-bottom: 6px;
    }}
    h3   {{ font-size: 13px; font-weight: 600; margin: 16px 0 8px; color: #333 }}
    .meta {{ font-size: 12px; color: #888; margin: 0 0 24px }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 10px; margin: 12px 0 20px;
    }}
    .card {{
        background: #f7f8f9; border-radius: 8px;
        padding: 12px 14px;
        border-top: 2px solid {brand.accent_colour};
    }}
    .card .num {{ font-size: 24px; font-weight: 700; line-height: 1.1 }}
    .card .lbl {{
        font-size: 10px; color: #888; margin-top: 4px;
        text-transform: uppercase; letter-spacing: .05em;
    }}
    .signal {{
        border-left: 3px solid; padding: 10px 14px; margin: 8px 0;
        border-radius: 0 6px 6px 0; font-size: 13px; line-height: 1.6;
    }}
    code {{
        font-family: ui-monospace,monospace; font-size: 11px;
        background: #f0f0f0; padding: 1px 5px; border-radius: 3px;
    }}
    a {{ color: {brand.primary_colour} }}
    table {{ font-size: 12px; border-collapse: collapse; width: 100% }}
    th {{ text-align: left }}
    @media print {{
        body {{ padding: 16px }}
        .noprint {{ display: none }}
    }}
    </style>
    </head>
    <body>
    {self._html_header(brand, report_type)}
    {body}
    {self._html_contact_block(brand)}
    {self._html_footer(brand)}
    </body>
    </html>"""

    # --- Shared section builders -------------------------------------------

    def _dns_records_md(self) -> str:
        lines = ["## DNS records", ""]
        for rtype, records in self.dns.items():
            if not records:
                continue
            if rtype == "mx":
                vals = [f"{r['priority']}:{r['host']}" for r in records]
            else:
                vals = records
            lines.append(f"**{rtype.upper()}**")
            for v in vals:
                lines.append(f"  - `{v}`")
            lines.append("")
        return "\n".join(lines)

    def _technographics_md(self) -> str:
        t = self.tech
        ti = self.txt_intel
        lines = [
            "## Technographics",
            "",
            "| Signal | Value |",
            "|--------|-------|",
            f"| MX provider | {t.get('mx_provider_name') or '—'} ({t.get('mx_mbp_category') or '—'}) |",
            f"| MX trust nudge | {t.get('mx_trust_nudge',0):+.1f} |",
            f"| MX risk bias | {t.get('mx_risk_bias',0):+.1f} |",
            f"| NS provider | {t.get('ns_provider_name') or '—'} ({t.get('ns_provider_category') or '—'}) |",
            f"| ISP | {t.get('isp_name') or '—'} ({t.get('isp_country') or '—'}) |",
            f"| ASN | AS{t.get('asn') or '—'} — risk: {t.get('asn_risk_level') or '—'} |",
            f"| TLD risk | {t.get('tld_risk_level') or '—'} |",
            f"| Net trust score | {t.get('net_trust_score',0):+.1f} |",
            f"| CDN/UGC | {'Yes' if t.get('is_cdn_ugc') else 'No'} |",
            "",
            "### SaaS stack",
            "",
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
            "## Risk score breakdown",
            "",
            f"Score: **{re.get('score',0)}/100** ({re.get('bucket','?')}) — "
            f"config {re.get('config_version','?')}",
            "",
            "| Rule | Points |",
            "|------|--------|",
        ]
        for r in re.get("rules", []):
            sign = f"+{r['points']}" if r["points"] > 0 else str(r["points"])
            lines.append(f"| {r['rule']} | {sign} |")
        return "\n".join(lines)

    def _labels_md(self) -> str:
        lbl = self.labels
        flags = self.flags
        lines = [
            "## Labels and flags",
            "",
            "| Label | Value |",
            "|-------|-------|",
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
            "## Certificates",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| HTTPS issuer | {c.get('https_issuer_org') or '—'} (`{c.get('https_label') or '—'}`) |",
            f"| HTTPS days left | {c.get('https_days_left') or '—'} "
            f"{'⚠ EXPIRING SOON' if c.get('https_expiring') else ''} |",
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
            "## Change signals",
            "",
            "| Signal | Status |",
            "|--------|--------|",
            f"| NS changed | {'YES ⚠' if ch.get('ns_changed') else 'No'} |",
            f"| IP changed | {'YES ⚠' if ch.get('ip_changed') else 'No'} |",
            f"| Country changed | {'YES ⚠' if ch.get('country_changed') else 'No'} |",
            f"| TTL big drop | {'YES ⚠' if ch.get('ttl_drop_big') else 'No'} |",
            f"| Dynamic DNS | {'YES ⚠' if ch.get('is_dynamic_dns') else 'No'} |",
            f"| MX misconfigured | {'YES ⚠' if ch.get('mx_misconfigured') else 'No'} |",
            f"| Parking points | {ch.get('parking_points', 0)} |",
        ]
        return "\n".join(lines)

    def _technographics_html(self) -> str:
        t     = self.tech
        ti    = self.txt_intel
        lbl   = self.labels
        flags = self.flags
        dns   = self.dns

        # --- SaaS pills by category ---
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
                is_risky = any(
                    k in svc.lower()
                    for k in ("lastpass","okta","twilio","mailchimp","circleci","dropbox sign")
                )
                final_style = "background:#FCEBEB;color:#791F1F" if is_risky else style
                pills_html += (
                    f'<span style="{final_style};padding:2px 8px;border-radius:4px;'
                    f'font-size:11px;font-weight:500;display:inline-block;'
                    f'margin:2px 3px 2px 0">{svc}</span>'
                )
        if not pills_html:
            pills_html = '<span style="color:#888;font-size:12px">None identified from TXT records</span>'

        # --- Anomalous TXT ---
        anomalies_html = ""
        for a in ti.get("anomalous_records", []):
            anomalies_html += (
                f'<div style="font-family:monospace;font-size:11px;'
                f'background:#FCEBEB;color:#791F1F;padding:4px 8px;'
                f'border-radius:3px;margin:3px 0;word-break:break-all">{a}</div>'
            )

        # --- Full DNS records table — every record type, every value ---
        dns_rows = ""
        RECORD_ORDER = ["a", "aaaa", "mx", "ns", "txt", "caa", "mail_a", "www_a"]
        for rtype in RECORD_ORDER:
            records = dns.get(rtype, [])
            if not records:
                dns_rows += (
                    f"<tr style='opacity:.4'>"
                    f"<td style='padding:5px 10px;font-weight:600;font-size:11px;"
                    f"text-transform:uppercase;color:#888;white-space:nowrap;"
                    f"vertical-align:top;width:70px'>{rtype.upper()}</td>"
                    f"<td style='padding:5px 10px;font-family:monospace;font-size:11px;"
                    f"color:#aaa'>—</td></tr>"
                )
                continue
            if rtype == "mx":
                vals = [f"{r['priority']}  {r['host']}" for r in records]
            else:
                vals = [str(r) for r in records]
            # Each value on its own line
            cell = "<br>".join(
                f'<span style="display:block;padding:1px 0;word-break:break-all">{v}</span>'
                for v in vals
            )
            dns_rows += (
                f"<tr style='border-bottom:1px solid var(--color-border-tertiary,#f0f0f0)'>"
                f"<td style='padding:5px 10px;font-weight:600;font-size:11px;"
                f"text-transform:uppercase;color:#555;white-space:nowrap;"
                f"vertical-align:top;width:70px'>{rtype.upper()}</td>"
                f"<td style='padding:5px 10px;font-family:monospace;font-size:11px;"
                f"color:#222;line-height:1.6'>{cell}</td></tr>"
            )
    
        # --- Security layer checklist ---
        ea = self.ea
        certs = self.certs
    
        def status_pill(ok: bool, good_text: str, bad_text: str) -> str:
            if ok:
                return (f'<span style="background:#EAF3DE;color:#27500A;padding:2px 8px;'
                        f'border-radius:4px;font-size:11px;font-weight:500">{good_text}</span>')
            return (f'<span style="background:#FCEBEB;color:#791F1F;padding:2px 8px;'
                    f'border-radius:4px;font-size:11px;font-weight:500">{bad_text}</span>')
    
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
    
        checklist = f"""
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <thead><tr style="background:#f5f5f5">
            <th style="padding:6px 10px;text-align:left;font-size:11px;
                       text-transform:uppercase;letter-spacing:.04em">Layer</th>
            <th style="padding:6px 10px;text-align:left;font-size:11px;
                       text-transform:uppercase;letter-spacing:.04em">Status</th>
            <th style="padding:6px 10px;text-align:left;font-size:11px;
                       text-transform:uppercase;letter-spacing:.04em">Detail</th>
            <th style="padding:6px 10px;text-align:left;font-size:11px;
                       text-transform:uppercase;letter-spacing:.04em">Impact if missing</th>
          </tr></thead>
          <tbody>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">SPF</td>
              <td style="padding:6px 10px">{status_pill(spf_ok, ea.get('spf') or 'present', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">{ea.get('spf_raw','Not found')[:80]}</td>
              <td style="padding:6px 10px;color:#888">Any server can send email as this domain</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">DMARC</td>
              <td style="padding:6px 10px">{status_pill(dmarc_ok, f"p={ea.get('dmarc_policy')}", 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">
                {f"pct={ea.get('dmarc_pct',0)} · aspf={ea.get('aspf','?')} · adkim={ea.get('adkim','?')}" if dmarc_ok else 'No DMARC record found'}
              </td>
              <td style="padding:6px 10px;color:#888">Spoofed mail delivered without policy enforcement</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">DMARC p=reject</td>
              <td style="padding:6px 10px">{status_pill(reject_ok, 'p=reject', 'not reject')}</td>
              <td style="padding:6px 10px;color:#555">
                {'Full enforcement — spoofed mail rejected' if reject_ok else f"Currently p={ea.get('dmarc_policy','missing')} — upgrade to reject for full protection"}
              </td>
              <td style="padding:6px 10px;color:#888">Spoofed mail quarantined or delivered depending on policy</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">MTA-STS</td>
              <td style="padding:6px 10px">{status_pill(mta_ok, 'configured', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">
                {'Mode: ' + (ea.get('mta_sts_mode') or 'unknown') if mta_ok else 'NXDOMAIN — policy not published'}
              </td>
              <td style="padding:6px 10px;color:#888">Inbound SMTP vulnerable to TLS downgrade attacks</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">TLS-RPT</td>
              <td style="padding:6px 10px">{status_pill(tls_ok, 'configured', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">
                {ea.get('tls_rpt_rua') or ('NXDOMAIN — no SMTP TLS reporting' if not tls_ok else 'Configured')}
              </td>
              <td style="padding:6px 10px;color:#888">No visibility into SMTP delivery failures or TLS issues</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">BIMI</td>
              <td style="padding:6px 10px">{status_pill(bimi_ok, 'configured', 'not configured')}</td>
              <td style="padding:6px 10px;color:#555">
                {'Brand logo in email clients' if bimi_ok else 'Requires DMARC p=reject first, then default._bimi TXT record'}
              </td>
              <td style="padding:6px 10px;color:#888">Brand logo not displayed in Gmail, Apple Mail, Yahoo</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">DNSSEC</td>
              <td style="padding:6px 10px">{status_pill(dnssec_ok, 'enabled', 'not enabled')}</td>
              <td style="padding:6px 10px;color:#555">
                {'DNSSEC signatures present' if dnssec_ok else 'DNS responses are not cryptographically signed'}
              </td>
              <td style="padding:6px 10px;color:#888">DNS cache poisoning and response tampering possible</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">CAA records</td>
              <td style="padding:6px 10px">{status_pill(caa_ok, 'present', 'MISSING')}</td>
              <td style="padding:6px 10px;color:#555">
                {', '.join(dns.get('caa', [])) or 'No CAA records — any CA can issue certificates'}
              </td>
              <td style="padding:6px 10px;color:#888">Unauthorised certificates can be issued for this domain</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">security.txt</td>
              <td style="padding:6px 10px">{status_pill(sec_ok, 'present', 'missing')}</td>
              <td style="padding:6px 10px;color:#555">
                {'Published at /.well-known/security.txt' if sec_ok else 'No responsible disclosure policy published'}
              </td>
              <td style="padding:6px 10px;color:#888">Security researchers have no formal disclosure channel</td>
            </tr>
            <tr style="border-bottom:1px solid #f5f5f5">
              <td style="padding:6px 10px;font-weight:500">SMTP banner</td>
              <td style="padding:6px 10px">{status_pill(smtp_ok, 'verified', 'not verified')}</td>
              <td style="padding:6px 10px;color:#555;font-family:monospace;font-size:11px">
                {certs.get('smtp_banner') or 'No banner captured'}
              </td>
              <td style="padding:6px 10px;color:#888">MX provider identity unconfirmed from DNS alone</td>
            </tr>
          </tbody>
        </table>"""
    
        # --- Labels ---
        labels_html = "".join(
            f'<span style="background:#f0f0f0;color:#444;padding:3px 10px;'
            f'border-radius:4px;font-size:12px;display:inline-block;margin:2px 3px 2px 0">'
            f'<strong>{k.replace("_"," ").title()}:</strong> {v}</span>'
            for k, v in lbl.items() if v is not None
        )
    
        return f"""
        <h2>Security layer checklist</h2>
        {checklist}
    
        <h2>Technographics</h2>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:12px 0">
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;
                        letter-spacing:.04em;margin-bottom:4px">MX provider</div>
            <div style="font-size:13px;font-weight:500">
            {t.get('mx_provider_name') or '—'}
            </div>
            <div style="font-size:11px;color:#888;margin-top:2px">
            {t.get('mx_mbp_category') or '—'} ·
            nudge {t.get('mx_trust_nudge',0):+.1f} /
            bias {t.get('mx_risk_bias',0):+.1f}
            </div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;
                        letter-spacing:.04em;margin-bottom:4px">ASN / ISP</div>
            <div style="font-size:13px;font-weight:500">
            {t.get('isp_name') or '—'} (AS{t.get('asn') or '—'})
            </div>
            <div style="font-size:11px;color:#888;margin-top:2px">
            {t.get('isp_country') or '—'} ·
            risk: {t.get('asn_risk_level') or '—'} ·
            TLD: {t.get('tld_risk_level') or '—'}
            </div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;
                        letter-spacing:.04em;margin-bottom:4px">Net trust score</div>
            <div style="font-size:22px;font-weight:600;
                        color:{'#3B6D11' if float(t.get('net_trust_score',0))>0 else '#A32D2D'}">
            {float(t.get('net_trust_score',0)):+.1f}
            </div>
            <div style="font-size:11px;color:#888;margin-top:2px">
            CDN/UGC: {'Yes' if t.get('is_cdn_ugc') else 'No'}
            </div>
        </div>
        </div>
    
        <h2>SaaS stack — {ti.get('total_identified',0)} services identified from TXT records</h2>
        <div style="margin:10px 0 6px">{pills_html}</div>
        {f'<div style="margin-top:10px"><div style="font-size:11px;color:#A32D2D;font-weight:600;text-transform:uppercase;letter-spacing:.04em;margin-bottom:5px">Anomalous TXT records</div>{anomalies_html}</div>' if anomalies_html else ''}
    
        {'<h2>Unrecognised TXT tokens</h2><div style="font-size:12px;color:#555">' + '<br>'.join(f'<code>{u}</code>' for u in ti.get('unrecognised',[])[:10]) + '</div>' if ti.get('unrecognised') else ''}
    
        <h2>Full DNS records</h2>
        <table style="width:100%;border-collapse:collapse">
        <tbody>{dns_rows}</tbody>
        </table>
    
        <h2>Labels</h2>
        <div style="margin:8px 0">{labels_html}</div>
    
        <h2>Certificates</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:10px 0">
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;
                        letter-spacing:.04em;margin-bottom:5px">HTTPS</div>
            <div style="font-size:13px">{self.certs.get('https_issuer_org') or '—'}
            <span style="color:#888;font-size:11px"> ({self.certs.get('https_label') or '—'})</span>
            </div>
            <div style="font-size:12px;margin-top:4px;
                        color:{'#A32D2D' if self.certs.get('https_expiring') else '#3B6D11'}">
            {self.certs.get('https_days_left') or '—'} days remaining
            {' — EXPIRING SOON' if self.certs.get('https_expiring') else ''}
            </div>
            <div style="font-size:11px;color:#888;margin-top:3px">
            {self.certs.get('https_san_count') or '—'} SANs ·
            Let's Encrypt: {'Yes' if self.certs.get('https_lets_encrypt') else 'No'}
            </div>
        </div>
        <div style="background:#f7f7f7;border-radius:7px;padding:11px 13px">
            <div style="font-size:11px;color:#888;text-transform:uppercase;
                        letter-spacing:.04em;margin-bottom:5px">SMTP</div>
            <div style="font-size:13px">{self.certs.get('smtp_issuer_org') or '—'}</div>
            <div style="font-size:12px;color:#3B6D11;margin-top:4px">
            {self.certs.get('smtp_days_left') or '—'} days remaining
            </div>
            <div style="font-family:monospace;font-size:11px;color:#555;
                        margin-top:6px;word-break:break-all">
            {self.certs.get('smtp_banner') or 'No banner captured'}
            </div>
            <div style="font-size:11px;margin-top:4px;
                        color:{'#3B6D11' if self.certs.get('provider_live') else '#888'}">
            Provider {'confirmed live via banner' if self.certs.get('provider_live') else 'not banner-verified'}
            </div>
        </div>
        </div>
    
        <h2>Change signals</h2>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0">
        {''.join(
            f'<span style="background:{"#FCEBEB" if v else "#EAF3DE"};'
            f'color:{"#791F1F" if v else "#27500A"};'
            f'padding:3px 10px;border-radius:4px;font-size:12px;'
            f'font-weight:{"600" if v else "400"}">'
            f'{k.replace("_"," ").title()}: {"YES ⚠" if v else "No"}</span>'
            for k, v in self.changes.items() if isinstance(v, bool)
        )}
        </div>"""
    
    
    def _risk_breakdown_html(self) -> str:
        re = self.risk_engine
        rows = ""
        for r in re.get("rules", []):
            pts = r["points"]
            colour = "#A32D2D" if pts > 0 else "#3B6D11"
            sign   = f"+{pts}" if pts > 0 else str(pts)
            width  = min(100, abs(pts) * 8)
            rows += (
                f'<tr>'
                f'<td style="padding:5px 10px;font-size:12px;color:#444">{r["rule"]}</td>'
                f'<td style="padding:5px 10px;min-width:120px">'
                f'<div style="background:#f0f0f0;border-radius:3px;height:6px">'
                f'<div style="background:{colour};width:{width}%;height:100%;'
                f'border-radius:3px"></div></div></td>'
                f'<td style="padding:5px 10px;font-weight:600;color:{colour};'
                f'text-align:right;font-size:12px">{sign}</td>'
                f'</tr>'
            )
        return f"""
        <h2>Risk score breakdown
          <span style="font-weight:400;font-size:13px;color:#888;margin-left:8px">
            {re.get('score',0)}/100 · {re.get('bucket','?')} ·
            config {re.get('config_version','?')}
          </span>
        </h2>
        <table style="width:100%;border-collapse:collapse">{rows}</table>"""

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
        order = ["critical", "high", "medium", "info"]
        cutoff = order.index(max_severity)
        return [
            f for f in self.findings
            if order.index(f.get("severity", "info")) <= cutoff
        ]

    def _sorted_findings(self) -> list[dict]:
        order = ["critical", "high", "medium", "info"]
        return sorted(
            self.findings,
            key=lambda f: order.index(f.get("severity", "info"))
        )

    def _key_finding(self) -> str:
        return self.narrative.get("key_finding", "")

    def _executive_summary(self) -> str:
        return self.narrative.get("executive_summary", "")

    def _threat_narrative(self) -> str:
        return self.narrative.get("threat_narrative", "")

    def _positive_signals(self) -> str:
        return self.narrative.get("positive_signals", "")

    def _remediation_priority(self) -> str:
        return self.narrative.get("remediation_priority", "")

    def _insurer_signals(self) -> str:
        return self.narrative.get("insurer_signals", "")

    def _saas_stack_analysis(self) -> str:
        return self.narrative.get("saas_stack_analysis", "")

# ---------------------------------------------------------------------------
# 1. Insurer renderer
# ---------------------------------------------------------------------------

class InsurerRenderer(BaseRenderer):
    """
    Audience: cyber insurance underwriters.
    Focus: risk scores, exposure aggregates, actuarial language,
           directly underwritable signals.
    """

    def to_dict(self) -> dict:
        return {
            "report_type":    "cyber_risk_underwriting",
            "domain":         self.domain,
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
            "technographics":  self.tech,
            "txt_intelligence": self.txt_intel,
            "labels":          self.labels,
            "threat_flags":    self.flags,
            "change_signals":  self.changes,
            "risk_engine":     self.risk_engine,
            "narrative":       self.narrative,
            "critical_findings": [
                f for f in self.findings
                if f.get("severity") in ("critical", "high")
            ],
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
        critical = [f for f in self.findings if f.get("severity") == "critical"]
        for f in critical:
            signals.append({
                "signal":    f["finding"],
                "severity":  "critical",
                "title":     f["title"],
                "evidence":  f.get("evidence", ""),
                "narrative": f.get("detail", ""),
            })
        if self.ea["is_spoofable"]:
            signals.append({
                "signal":    "email_spoofing_exposure",
                "severity":  self.ea.get("spoofing_severity", "high"),
                "title":     f"Domain spoofable — {self.ea.get('spoofing_severity','').upper()}",
                "evidence":  f"SPF: {self.ea['spf']}, DMARC: {self.ea['dmarc_policy'] or 'missing'}",
                "narrative": (
                    f"{self.domain} can be impersonated by any actor. "
                    f"Spoofed email would appear to come from a legitimate address "
                    f"with no technical barrier to delivery."
                ),
            })
        return signals

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        exp = self._exposure_summary()
        lines = [
            f"# Cyber risk underwriting report — {self.domain}",
            f"*Generated {self.o['generated_at']}*",
            "",
        ]

        if self._key_finding():
            lines += [f"> **Key finding:** {self._key_finding()}", ""]

        lines += [
            f"## Risk score: {self.cs['score']}/100 — {self.cs['risk_band'].upper()}",
            f"Confidence: {self.cs['confidence']} · Primary driver: {self.cs['primary_driver']}",
            "",
            "## Exposure summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Critical findings | {exp['critical']} |",
            f"| High findings | {exp['high']} |",
            f"| Spoofable | {'YES — ' + exp['spoofing_severity'] if exp['spoofable'] else 'No'} |",
            f"| MX provider | {self.infra['mx_provider'] or 'None detected'} |",
            f"| DMARC policy | {self.ea['dmarc_policy'] or 'Missing'} |",
            f"| SPF | {self.ea['spf'] or 'Missing'} |",
            f"| HTTPS cert days left | {self.certs['https_days_left'] or 'Unknown'} |",
            f"| Any change signal | {'Yes' if exp['any_change_signal'] else 'No'} |",
            "",
            "## Score breakdown",
            "",
            "| Component | Score | Weight |",
            "|-----------|-------|--------|",
        ]
        for k, v in self.cs["components"].items():
            lines.append(f"| {k.replace('_',' ').title()} | {v} | included |")

        lines += ["", "## Critical and high findings", ""]
        for f in self._findings_by_severity("high"):
            lines += [
                f"### [{f['severity'].upper()}] {f['title']}",
                f.get("detail", ""),
                f"*Evidence:* `{f.get('evidence','n/a')}`",
                f"*Fix:* {f.get('remediation','n/a')}",
                "",
            ]

        if self._executive_summary():
            lines += ["## Executive summary", "", self._executive_summary(), ""]

        if self._threat_narrative():
            lines += ["## Threat narrative", "", self._threat_narrative(), ""]

        if self._insurer_signals():
            lines += ["## Underwriting signals", "", self._insurer_signals(), ""]

        if self._positive_signals():
            lines += ["## Positive signals", "", self._positive_signals(), ""]

        if self._remediation_priority():
            lines += ["## Remediation priorities", "", self._remediation_priority(), ""]

        if self._saas_stack_analysis():
            lines += ["## SaaS stack analysis", "", self._saas_stack_analysis(), ""]

        lines += [
            "",
            self._risk_breakdown_md(),
            "",
            self._technographics_md(),
            "",
            self._certs_md(),
            "",
            self._dns_records_md(),
            "",
            self._changes_md(),
            "",
            self._labels_md(),
        ]

        return "\n".join(lines)

    def to_html(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        score_colour = RISK_BAND_COLOUR.get(self.cs["risk_band"], "#666")
        exp = self._exposure_summary()

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

        # --- Summary cards grid ---
        grid = f"""
        <div class="grid">
          <div class="card">
            <div class="num" style="color:{score_colour}">{self.cs['score']}</div>
            <div class="lbl">Risk score (0–100)</div>
          </div>
          <div class="card">
            <div class="num" style="color:{RISK_COLOURS['critical']['border']}">{exp['critical']}</div>
            <div class="lbl">Critical findings</div>
          </div>
          <div class="card">
            <div class="num" style="color:{RISK_COLOURS['high']['border']}">{exp['high']}</div>
            <div class="lbl">High findings</div>
          </div>
          <div class="card">
            <div class="num" style="color:{'#A32D2D' if exp['spoofable'] else '#3B6D11'}">
              {'YES' if exp['spoofable'] else 'No'}
            </div>
            <div class="lbl">Spoofable</div>
          </div>
          <div class="card">
            <div class="num">{self.infra['mx_provider'] or '—'}</div>
            <div class="lbl">Email gateway</div>
          </div>
          <div class="card">
            <div class="num">{self.certs['https_days_left'] or '—'}d</div>
            <div class="lbl">HTTPS cert expiry</div>
          </div>
          <div class="card">
            <div class="num">{'Yes' if self.infra['dual_stack'] else 'No'}</div>
            <div class="lbl">IPv6 dual-stack</div>
          </div>
          <div class="card">
            <div class="num" style="color:{'#A32D2D' if not self.flags.get('has_caa') else '#3B6D11'}">
              {'None' if not self.flags.get('has_caa') else 'Present'}
            </div>
            <div class="lbl">CAA records</div>
          </div>
        </div>"""

        # --- Executive summary ---
        executive_html = ""
        if self._executive_summary():
            executive_html = f"""
            <h2>Executive summary</h2>
            <div style="background:#f9f9f9;border-radius:8px;padding:14px 18px;
                        font-size:13px;line-height:1.8;color:#333">
              {self._executive_summary()}
            </div>"""

        # --- Underwriting signals ---
        insurer_html = ""
        if self._insurer_signals():
            insurer_html = f"""
            <h2>Underwriting signals</h2>
            <div style="background:#f0f4ff;border-left:3px solid #185FA5;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:13px;line-height:1.8;color:#0c2d5e">
              {self._insurer_signals()}
            </div>"""

        # --- Threat narrative ---
        narrative_html = ""
        if self._threat_narrative():
            narrative_html = f"""
            <h2>Threat narrative</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
              {self._threat_narrative()}
            </p>"""

        # --- Positive signals ---
        positive_html = ""
        if self._positive_signals():
            positive_html = f"""
            <div style="background:#EAF3DE;border-left:3px solid #3B6D11;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:13px;color:#1a3d0f;margin:16px 0;line-height:1.6">
              <strong>Positive signals:</strong> {self._positive_signals()}
            </div>"""

        # --- Remediation priorities ---
        remediation_html = ""
        if self._remediation_priority():
            remediation_html = f"""
            <h2>Remediation priorities</h2>
            <div style="background:#f9f9f9;border-radius:8px;padding:14px 18px;
                        font-size:13px;line-height:1.9;color:#333;white-space:pre-line">
              {self._remediation_priority()}
            </div>"""

        # --- SaaS stack analysis ---
        saas_html = ""
        if self._saas_stack_analysis():
            saas_html = f"""
            <h2>SaaS stack analysis</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
              {self._saas_stack_analysis()}
            </p>"""

        # --- Key risk signals ---
        signals_html = ""
        for sig in self._key_signals():
            c  = RISK_BAND_COLOUR.get(sig["severity"], "#666")
            bg = RISK_COLOURS.get(sig["severity"], RISK_COLOURS["high"])
            signals_html += (
                f'<div class="signal" style="border-color:{c};'
                f'background:{bg["bg"]};color:{bg["text"]}">'
                f'<strong>{sig["title"]}</strong><br>'
                f'<span style="opacity:.85">{sig["narrative"]}</span><br>'
                f'<code style="font-size:11px;opacity:.7">{sig.get("evidence","")[:100]}</code>'
                f'</div>'
            )

        # --- Critical / high findings table ---
        table = _findings_table(
            self._findings_by_severity("high"),
            [
                ("Asset / Finding", lambda f: f["title"]),
                ("Severity",        lambda f: _badge(f.get("severity","info"))),
                ("Evidence",        lambda f: f'<code>{f.get("evidence","")[:60]}</code>'),
                ("Fix",             lambda f: f.get("remediation","—")[:80]),
            ],
        )

        # --- Assemble body ---
        body = f"""
        {key_finding_html}

        <h2>Risk overview</h2>
        {grid}

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

        {self._risk_breakdown_html()}
        {self._technographics_html()}
        """

        return self._html_shell_branded(      # ← replaces _html_shell()
            brand=brand,
            report_type="Cyber Risk Underwriting Report",
            body=body,
        )


# ---------------------------------------------------------------------------
# 2. Consultant renderer
# ---------------------------------------------------------------------------

class ConsultantRenderer(BaseRenderer):
    """
    Audience: security consultants preparing client briefings.
    Focus: technical evidence, full finding detail, remediation steps.
    """

    REMEDIATION_GUIDES = {
        "no_mta_sts": (
            "1. Create DNS TXT record: `_mta-sts.{domain}` → "
            "`v=STSv1; id=<timestamp>`\n"
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
            "Run at pct=10 first to verify no legitimate mail is rejected,\n"
            "then increase to pct=100."
        ),
    }

    def to_dict(self) -> dict:
        return {
            "report_type":   "technical_security_assessment",
            "domain":        self.domain,
            "generated_at":  self.o["generated_at"],
            "score":         self.cs["score"],
            "risk_band":     self.cs["risk_band"],
            "email_auth":    self.ea,
            "infrastructure": self.infra,
            "certificates":   self.certs,
            "change_signals": self.changes,
            "findings": [
                {**f, "remediation_detail": self._remediation_detail(f)}
                for f in self._sorted_findings()
            ],
            "missing_layers":    self.ea["missing_layers"],
            "score_breakdown":   self.score_breakdown,
            "narrative":         self.narrative,
        }

    def _remediation_detail(self, finding: dict) -> str:
        guide = self.REMEDIATION_GUIDES.get(finding.get("finding", ""))
        if guide:
            return guide.format(domain=self.domain)
        return finding.get("remediation") or ""

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        lines = [
            f"# Technical security assessment — {self.domain}",
            f"*{self.o['generated_at']}*",
            "",
            f"Score: **{self.cs['score']}/100** ({self.cs['risk_band']}) · "
            f"Primary driver: {self.cs['primary_driver']}",
            "",
            "## Email authentication",
            "",
            f"| Layer | Status | Detail |",
            f"|-------|--------|--------|",
            f"| SPF | {self.ea['spf'] or 'MISSING'} | "
            f"{'Hard fail' if self.ea['spf'] == '-all' else 'Soft fail' if self.ea['spf'] == '~all' else 'Not configured'} |",
            f"| DMARC | {'p=' + self.ea['dmarc_policy'] if self.ea['dmarc_policy'] else 'MISSING'} | "
            f"pct={self.ea['dmarc_pct']}, aspf={self.ea.get('aspf','?')}, adkim={self.ea.get('adkim','?')} |",
            f"| MTA-STS | {self.ea['mta_sts']} | — |",
            f"| TLS-RPT | {self.ea['tls_rpt']} | — |",
            f"| BIMI | {self.ea['bimi']} | — |",
            "",
            "## Findings",
            "",
        ]
        for f in self._sorted_findings():
            lines += [
                f"### [{f['severity'].upper()}] {f['title']}",
                "",
                f.get("detail", ""),
                "",
                f"**Evidence:** `{f.get('evidence','n/a')}`",
                "",
                f"**Remediation:** {self._remediation_detail(f)}",
                "",
            ]

        if self.score_breakdown:
            lines += ["## Risk score rule breakdown", ""]
            lines += ["| Rule | Points |", "|------|--------|"]
            for r in self.score_breakdown:
                sign = f"+{r['points']}" if r["points"] > 0 else str(r["points"])
                lines.append(f"| {r['rule']} | {sign} |")

        return "\n".join(lines)

    def to_html(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        # Email auth layers table
        auth_rows = ""
        for layer, status, detail in [
            ("SPF",      self.ea["spf"] or "MISSING",
             "Hard fail (-all)" if self.ea["spf"] == "-all"
             else "Soft fail (~all)" if self.ea["spf"] == "~all"
             else "Not configured"),
            ("DMARC",    ("p=" + self.ea["dmarc_policy"]) if self.ea["dmarc_policy"] else "MISSING",
             f"pct={self.ea['dmarc_pct']} · aspf={self.ea.get('aspf','?')} · adkim={self.ea.get('adkim','?')}"),
            ("MTA-STS",  self.ea["mta_sts"], "Inbound TLS enforcement"),
            ("TLS-RPT",  self.ea["tls_rpt"], "SMTP delivery failure reporting"),
            ("BIMI",     self.ea["bimi"],     "Brand logo in email clients"),
            ("CAA",      "Present" if not any(f["finding"]=="no_caa" for f in self.findings)
             else "MISSING", "Certificate authority restriction"),
        ]:
            ok = status not in ("MISSING", "NXDOMAIN", "NOT_FOUND")
            colour = "#3B6D11" if ok else "#A32D2D"
            auth_rows += (
                f"<tr><td style='padding:6px 10px;font-size:12px'>{layer}</td>"
                f"<td style='padding:6px 10px'>"
                f"<code style='color:{colour};font-size:11px'>{status}</code></td>"
                f"<td style='padding:6px 10px;font-size:12px;color:#666'>{detail}</td></tr>"
            )

        findings_html = ""
        for f in self._sorted_findings():
            c = RISK_COLOURS.get(f.get("severity","info"), RISK_COLOURS["info"])
            findings_html += (
                f'<div style="border:1px solid {c["border"]};'
                f'border-left:3px solid {c["border"]};'
                f'border-radius:0 6px 6px 0;padding:12px 16px;'
                f'margin:8px 0;background:{c["bg"]}">'
                f'<div style="display:flex;justify-content:space-between;'
                f'align-items:flex-start;margin-bottom:6px">'
                f'<strong style="font-size:13px;color:{c["text"]}">'
                f'{f["title"]}</strong>'
                f'{_badge(f.get("severity","info"))}</div>'
                f'<div style="font-size:12px;color:#333;margin-bottom:6px;'
                f'line-height:1.6">{f.get("detail","")}</div>'
                f'<code style="font-size:11px;background:rgba(0,0,0,.05);'
                f'padding:2px 6px;border-radius:3px;display:block;margin:4px 0">'
                f'{f.get("evidence","")[:100]}</code>'
                f'<div style="font-size:11px;color:#555;margin-top:6px;font-style:italic">'
                f'Fix: {(self._remediation_detail(f) or "")[:120]}</div>'
                f'</div>'
            )



        body = f"""
        <div style="background:#f8f8f8;border-radius:8px;padding:14px 18px;margin-bottom:20px;font-size:13px;line-height:1.7">
          Score: <strong>{self.cs['score']}/100</strong> ({self.cs['risk_band']}) ·
          {len([f for f in self.findings if f.get('severity')=='critical'])} critical ·
          {len([f for f in self.findings if f.get('severity')=='high'])} high ·
          Primary driver: {self.cs['primary_driver']}
        </div>"""

        # Key finding banner
        if self._key_finding():
            body += f"""
            <div style="background:#FAEEDA;border-left:4px solid #854F0B;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:14px;font-weight:500;color:#412402;
                        margin-bottom:20px;line-height:1.5">
            {self._key_finding()}
            </div>"""

        # Executive summary
        if self._executive_summary():
            body += f"""
            <h2>Executive summary</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
            {self._executive_summary()}
            </p>"""

        # Threat narrative
        if self._threat_narrative():
            body += f"""
            <h2>Threat analysis</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
            {self._threat_narrative()}
            </p>"""

        # Positive signals
        if self._positive_signals():
            body += f"""
            <div style="background:#EAF3DE;border-left:3px solid #3B6D11;
                        padding:12px 16px;border-radius:0 8px 8px 0;
                        font-size:13px;color:#1a3d0f;margin:16px 0;line-height:1.6">
            <strong>Positive signals:</strong> {self._positive_signals()}
            </div>"""

        # Email auth table
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

        # Remediation priority list
        if self._remediation_priority():
            body += f"""
            <h2>Remediation priorities</h2>
            <div style="background:#f9f9f9;border-radius:8px;padding:14px 18px;
                        font-size:13px;line-height:1.9;color:#333;
                        white-space:pre-line">
            {self._remediation_priority()}
            </div>"""

        # All findings
        body += f"<h2>All findings</h2>{findings_html}"

        # SaaS stack analysis
        if self._saas_stack_analysis():
            body += f"""
            <h2>SaaS stack analysis</h2>
            <p style="font-size:13px;line-height:1.8;color:#333">
            {self._saas_stack_analysis()}
            </p>"""        

        body += self._risk_breakdown_html()
        body += self._technographics_html()

        return self._html_shell_branded(brand, "Technical Security Assessment", body)


# ---------------------------------------------------------------------------
# 3. IT renderer
# ---------------------------------------------------------------------------

class ITRenderer(BaseRenderer):
    """
    Audience: IT / security operations teams.
    Focus: actionable task list, clear ownership, specific commands,
           full technical context so engineers can act without follow-up.
    """

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
        return self.OWNER_MAP.get(
            finding.get("finding", ""),
            "Infrastructure team"
        )

    def _action(self, finding: dict) -> str:
        remediation = finding.get("remediation", "")
        return remediation[:120] if remediation else "Review and action"

    def to_dict(self) -> dict:
        return {
            "report_type":    "it_action_list",
            "domain":         self.domain,
            "generated_at":   self.o["generated_at"],
            "risk_score":     self.cs["score"],
            "risk_band":      self.cs["risk_band"],
            "primary_driver": self.cs["primary_driver"],
            "action_items": [
                {
                    "priority":  self.PRIORITY[f.get("severity","info")][0],
                    "severity":  f.get("severity","info"),
                    "title":     f["title"],
                    "owner":     self._owner(f),
                    "action":    self._action(f),
                    "evidence":  f.get("evidence",""),
                    "detail":    f.get("detail",""),
                }
                for f in self._sorted_findings()
                if f.get("severity") != "info"
            ],
            "backlog": [
                {
                    "title":  f["title"],
                    "owner":  self._owner(f),
                    "action": self._action(f),
                }
                for f in self.findings
                if f.get("severity") == "info"
            ],
            "email_auth":      self.ea,
            "infrastructure":  self.infra,
            "technographics":  self.tech,
            "certificates":    self.certs,
            "dns_records":     self.dns,
            "labels":          self.labels,
            "change_signals":  self.changes,
            "risk_engine":     self.risk_engine,
            "narrative":       self.narrative,
        }

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        lines = [
            f"# IT action list — {self.domain}",
            f"*{self.o['generated_at']}*",
            "",
            f"Score: {self.cs['score']}/100 ({self.cs['risk_band']}) · "
            f"Primary driver: {self.cs['primary_driver']}",
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

        lines += [
            "",
            self._risk_breakdown_md(),
            "",
            self._technographics_md(),
            "",
            self._certs_md(),
            "",
            self._dns_records_md(),
            "",
            self._changes_md(),
            "",
            self._labels_md(),
        ]

        return "\n".join(lines)

    def to_html(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
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

        # --- Summary cards ---
        grid = f"""
        <div class="grid">
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
        </div>"""

        # --- Context narrative ---
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

        # --- Action list table ---
        rows = ""
        for f in self._sorted_findings():
            label, colour = self.PRIORITY.get(
                f.get("severity", "info"),
                ("Review", "#666")
            )
            rows += (
                f"<tr>"
                f"<td style='padding:8px 10px;white-space:nowrap'>"
                f"<span style='color:{colour};font-weight:600;font-size:11px;"
                f"text-transform:uppercase'>{label}</span></td>"
                f"<td style='padding:8px 10px;font-size:12px'>"
                f"<strong>{f['title']}</strong>"
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

        body = f"""
        {key_finding_html}

        <h2>Action summary</h2>
        {grid}

        {context_html}
        {remediation_html}

        <h2>Full action list</h2>
        {action_table}

        {positive_html}

        {self._risk_breakdown_html()}
        {self._technographics_html()}
        """

        return self._html_shell_branded(brand, "IT Security Action List", body)

# ---------------------------------------------------------------------------
# 4. Sales renderer
# 

class SalesRenderer(BaseRenderer):
    """
    Audience: sales teams preparing prospect outreach.
    Focus: business impact language, talking points, hook findings.
    No raw DNS tables or rule engine details — too technical for this audience.
    Designed to be sent as a cold outreach attachment.
    """

    def _hook(self) -> str:
        parts = []
        critical = [f for f in self.findings if f.get("severity") == "critical"]
        if critical:
            parts.append(
                f"We found {len(critical)} critical "
                f"issue{'s' if len(critical) > 1 else ''} "
                f"in {self.domain}'s infrastructure that an attacker could exploit today."
            )
        if self.ea["is_spoofable"]:
            parts.append(
                f"Anyone can currently send email that appears to come from "
                f"@{self.domain} — with no technical access to your systems required."
            )
        high = [f for f in self.findings if f.get("severity") == "high"]
        if high and not parts:
            parts.append(
                f"We identified {len(high)} high-priority security gaps in "
                f"{self.domain}'s public infrastructure."
            )
        return " ".join(parts) or \
               f"We have a security brief prepared for {self.domain}."

    def _plain_english(self, finding: dict) -> str:
        mapping = {
            "no_mta_sts":
                "Email in transit can be intercepted — no TLS enforcement on inbound mail",
            "no_caa":
                "Any certificate authority could issue a fake TLS certificate for your domain",
            "dmarc_quarantine_strict_alignment":
                "Spoofed emails go to spam instead of being blocked — one config change away from full protection",
            "no_security_txt":
                "No public contact point for security researchers to report vulnerabilities",
            "spoofable_domain":
                "Your domain can be impersonated in email — no technical barrier for attackers",
            "cert_expiring_soon":
                f"HTTPS certificate expires in {self.certs.get('https_days_left','?')} days "
                f"— site will show security warnings if not renewed",
            "mixed_cert_authorities":
                "Two different certificate authorities in use — increases cert management risk",
            "fast_flux_ttl_penalty":
                "DNS configuration pattern associated with unstable or rapidly-changing infrastructure",
            "network_risk":
                "Hosting network has elevated risk classification",
            "mx_provider_banner_confirmed":
                "Email security gateway confirmed live and operational",
        }
        return mapping.get(
            finding.get("finding", ""),
            finding.get("detail", "")[:120]
        )

    def _talking_points(self) -> list[str]:
        points = []
        if self.ea["is_spoofable"]:
            points.append(
                f"The most immediate risk is email impersonation. Right now, anyone can "
                f"send email that looks like it's from {self.domain}. That's a phishing "
                f"platform you're unintentionally providing — and it takes three DNS "
                f"records to close."
            )
        missing = self.ea.get("missing_layers", [])
        if len(missing) >= 3:
            points.append(
                f"There are {len(missing)} missing security layers: "
                f"{', '.join(missing[:3])}"
                f"{'...' if len(missing) > 3 else ''}. "
                f"Each one is a gap that attackers actively probe for."
            )
        if self.certs.get("https_expiring"):
            points.append(
                f"Your HTTPS certificate expires in "
                f"{self.certs.get('https_days_left')} days. "
                f"After that, every visitor to your site sees a security warning."
            )
        if self.changes.get("any_change_signal"):
            points.append(
                "We detected recent infrastructure changes — NS, IP, or country records "
                "have changed. These are worth investigating in the context of "
                "recent threat activity."
            )
        if self.txt_intel.get("high_risk_saas") or any(
            k in str(self.txt_intel.get("all_identified", [])).lower()
            for k in ("lastpass", "okta", "twilio")
        ):
            points.append(
                "We identified SaaS services in your stack with confirmed breach "
                "history. Credentials stored in these services may have been "
                "exposed and should be treated as a priority rotation."
            )
        if not points:
            points.append(
                f"Your overall risk score is {self.cs['score']}/100 "
                f"({self.cs['risk_band']}). "
                f"We can walk through specific recommendations to bring that down."
            )
        return points

    def to_dict(self) -> dict:
        return {
            "report_type":  "sales_prospect_brief",
            "domain":       self.domain,
            "generated_at": self.o["generated_at"],
            "hook":         self._hook(),
            "headline_numbers": {
                "total_findings":  len(self.findings),
                "critical":        sum(1 for f in self.findings if f.get("severity") == "critical"),
                "high":            sum(1 for f in self.findings if f.get("severity") == "high"),
                "spoofable":       self.ea["is_spoofable"],
                "missing_layers":  len(self.ea.get("missing_layers", [])),
                "saas_count":      self.txt_intel.get("total_identified", 0),
            },
            "talking_points": self._talking_points(),
            "top_findings": [
                {
                    "title":         f["title"],
                    "plain_english": self._plain_english(f),
                    "severity":      f.get("severity"),
                }
                for f in self._sorted_findings()[:5]
            ],
            "saas_stack":  self.txt_intel.get("all_identified", []),
            "narrative":   self.narrative,
        }

    def to_markdown(self, brand: "BrandConfig" = None) -> str:
        brand = brand or BrandConfig.default()
        lines = [
            f"# Infrastructure brief — {self.domain}",
            f"*Prepared {self.o['generated_at']}*",
            "",
            "## What we found",
            "",
            self._hook(),
            "",
        ]

        if self._key_finding():
            lines += [f"> {self._key_finding()}", ""]

        lines += [
            "## The numbers",
            "",
            f"- **{len(self.findings)}** security issues identified",
            f"- **{sum(1 for f in self.findings if f.get('severity') in ('critical','high'))}**"
            f" require priority attention",
            f"- Spoofable: **{'Yes' if self.ea['is_spoofable'] else 'No'}**",
            f"- Missing auth layers: **{', '.join(self.ea.get('missing_layers',[]) or ['None'])}**",
            f"- SaaS platforms identified: **{self.txt_intel.get('total_identified',0)}**",
            "",
            "## Talking points",
            "",
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
        nums = self.to_dict()["headline_numbers"]

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
                        padding:12px 16px;background:#f9f9f9;
                        border-radius:8px">
              {self._key_finding()}
            </div>"""

        # --- Headline numbers ---
        grid = f"""
        <div class="grid">
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
        </div>"""

        # --- Talking points ---
        talking_html = "".join(
            f'<li style="margin-bottom:10px;line-height:1.6">{p}</li>'
            for p in self._talking_points()
        )

        # --- Top findings ---
        top5_html = "".join(
            f'<div style="padding:10px 0;border-bottom:1px solid #f0f0f0">'
            f'{_badge(f.get("severity","info"))} '
            f'<strong style="font-size:13px;margin-left:6px">{f["title"]}</strong>'
            f'<div style="font-size:12px;color:#555;margin-top:4px;padding-left:2px">'
            f'{self._plain_english(f)}</div></div>'
            for f in self._sorted_findings()[:5]
        )

        # --- Threat narrative ---
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
            <h2>SaaS stack</h2>
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
        {saas_analysis_html}

        {f'<h2>Identified SaaS platforms ({self.txt_intel.get("total_identified",0)})</h2><div style="margin:10px 0">{saas_pills}</div>' if saas_pills else ''}
        """

        return self._html_shell_branded(brand, "Infrastructure Intelligence Brief", body)

# ---------------------------------------------------------------------------
# Factory — renders all four from one output dict
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