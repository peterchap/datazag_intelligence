import math
from datetime import datetime

# Import BaseRenderer and BrandConfig
from renderers import BaseRenderer, status_pill, status, RISK_COLOURS, RISK_COLOURS_SUB
from branding import BrandConfig

class HealthRenderer(BaseRenderer):
    """
    Renders the 10-section Datazag Health Report, focusing on Platform and Brand impersonation
    for a business audience.
    """

    def _get_trust_grade(self, risk_score: float) -> str:
        if risk_score <= 15: return "A"
        if risk_score <= 30: return "B"
        if risk_score <= 50: return "C"
        if risk_score <= 70: return "D"
        if risk_score <= 85: return "E"
        return "F"

    def _get_platform_risk_score(self) -> int:
        # Heuristic based on tech stack and active campaigns
        base = len(self.tech.get("saas_platforms", [])) * 2 + len(self.tech.get("identity_providers", [])) * 5
        # cap at 100
        return min(int(base + self.overall_risk / 2), 100)

    def _get_infra_risk_score(self) -> int:
        return min(int(self.overall_risk), 100)

    def _html_shell_branded(self, brand: "BrandConfig", report_type: str, body: str) -> str:
        # A custom shell specifically matching the Health Report PDF mockup
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{brand.report_prefix} — {self.domain}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
* {{ box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
body {{
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    color: #334155;
    margin: 0;
    background: #F8FAFC;
    line-height: 1.6;
}}
.page-container {{
    background: #FFFFFF;
    margin: 0 auto;
    padding: 0;
    width: 100%;
}}
.cover {{
    background: #0F172A;
    color: #FFFFFF;
    padding: 60px;
    min-height: 297mm;
}}
h1, h2, h3, h4 {{ color: #0F172A; margin: 0; }}
.cover h1 {{
    color: #FFFFFF;
    font-size: 42px;
    font-weight: 700;
    line-height: 1.1;
    margin: 30px 0;
    letter-spacing: -0.02em;
}}
.cover .accent {{ color: #00A3FF; }}
.section {{ padding: 60px; page-break-before: always; }}
.section-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #E2E8F0;
    padding-bottom: 20px;
    margin-bottom: 30px;
}}
.section-title {{ font-size: 28px; font-weight: 700; letter-spacing: -0.02em; }}
.pill {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}
.pill-context {{ background: #F1F5F9; color: #475569; }}
.pill-findings {{ background: #E0F2FE; color: #0369A1; }}
.pill-action {{ background: #FFEDD5; color: #C2410C; }}
</style>
</head>
<body>
<div class="page-container">
    {body}
</div>
</body>
</html>"""

    def _render_cover_html(self) -> str:
        platform_score = self._get_platform_risk_score()
        infra_score = self._get_infra_risk_score()
        overall_score = max(platform_score, infra_score)
        grade = self._get_trust_grade(overall_score)
        
        return f"""
        <div class="cover">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #334155; padding-bottom:20px;">
                <div style="font-size:24px; font-weight:800; letter-spacing:-0.02em;">DATAZAG <span style="font-weight:400; color:#94A3B8; margin-left:10px;">HEALTH REPORT</span></div>
                <div style="font-size:12px; font-weight:500; color:#00A3FF;">{self.domain}</div>
            </div>
            
            <div style="margin-top:80px;">
                <div style="display:inline-block; border:1px solid #00A3FF; color:#00A3FF; border-radius:20px; padding:6px 16px; font-size:11px; font-weight:700; letter-spacing:0.05em;">
                    Q2 2026 · ATTACK SURFACE ASSESSMENT
                </div>
                
                <h1>Trusted-platform and brand-impersonation attack<br>surface for <span class="accent">{self.domain}</span>.</h1>
                
                <p style="font-size:16px; color:#94A3B8; max-width:800px; margin-top:24px;">
                    Every digital estate has an attack surface — the parts of it that an attacker can leverage. This report
                    maps yours from <strong>public DNS, certificate, and registration data</strong> — no access to your systems
                    required. <strong>The same data is available to bad actors performing reconnaissance.</strong> Two slices follow,
                    and a roadmap to minimise both.
                </p>
            </div>
            
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:24px; margin-top:60px;">
                <div style="background:#1E293B; border-radius:12px; border:1px solid #334155; padding:30px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div style="color:#F43F5E; font-size:11px; font-weight:700; letter-spacing:0.05em; text-transform:uppercase;">Platform Attack Surface</div>
                        <div style="background:#0F172A; padding:4px 10px; border-radius:12px; font-size:11px; font-weight:600;">{self._get_trust_grade(platform_score)} · {platform_score}/100</div>
                    </div>
                    <div style="font-size:22px; font-weight:700; color:#FFFFFF; margin:16px 0 8px;">Standard — {len(self.tech.get("saas_platforms", []))} trusted platforms</div>
                    <p style="color:#94A3B8; font-size:14px; margin-bottom:20px;">Typical for a business of your shape.</p>
                </div>
                
                <div style="background:#1E293B; border-radius:12px; border:1px solid #334155; padding:30px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div style="color:#00A3FF; font-size:11px; font-weight:700; letter-spacing:0.05em; text-transform:uppercase;">Infrastructure Attack Surface</div>
                        <div style="background:#0F172A; padding:4px 10px; border-radius:12px; font-size:11px; font-weight:600;">{self._get_trust_grade(infra_score)} · {infra_score}/100</div>
                    </div>
                    <div style="font-size:22px; font-weight:700; color:#FFFFFF; margin:16px 0 8px;">Moderate exposure</div>
                    <p style="color:#94A3B8; font-size:14px; margin-bottom:20px;">What attackers can exploit if not configured — DMARC, SPF, BIMI, CAA.</p>
                </div>
            </div>
            
            <div style="background:#1E293B; border-radius:12px; border:1px solid #334155; padding:30px; margin-top:24px; display:flex; gap:30px; align-items:center;">
                <div style="background:#00A3FF; color:#0F172A; font-size:42px; font-weight:800; width:80px; height:80px; border-radius:16px; display:flex; align-items:center; justify-content:center;">
                    {grade}
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:11px; font-weight:700; letter-spacing:0.05em; text-transform:uppercase; margin-bottom:8px;">OVERALL TRUST GRADE</div>
                    <div style="font-size:20px; font-weight:700; color:#FFFFFF;">Moderate exposure.</div>
                    <div style="color:#94A3B8; font-size:14px; margin-top:4px;">Both sides of your attack surface warrant attention. Section 09 sequences the minimisation work.</div>
                </div>
            </div>
        </div>
        """

    def _render_at_a_glance_html(self) -> str:
        return """
        <div class="section">
            <div class="section-header">
                <div>
                    <div style="color:#00A3FF; font-weight:700; font-size:12px; letter-spacing:0.1em; text-transform:uppercase; margin-bottom:8px;">Section 01</div>
                    <div class="section-title">At a glance.</div>
                </div>
                <div class="pill pill-context">Context</div>
            </div>
            <p style="font-size:16px; max-width:800px; color:#475569;">
                The platform side — the trusted technology platforms your staff log into — is largely a function of normal SaaS
                dependence; the infrastructure side has several short-effort improvements available.
            </p>
            <div style="margin-top: 40px; display:grid; grid-template-columns:1fr 1fr 1fr; gap:20px;">
                <div style="border:1px solid #E2E8F0; border-top:3px solid #F43F5E; padding:24px; border-radius:8px;">
                    <div style="font-weight:700; color:#F43F5E; font-size:11px; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px;">Trusted Platform Impersonation</div>
                    <div style="font-size:24px; font-weight:800; color:#0F172A; margin-bottom:12px;">Elevated</div>
                    <div style="color:#475569; font-size:13px;">Platforms detected are routinely targeted by active attacker campaigns.</div>
                </div>
                <div style="border:1px solid #E2E8F0; border-top:3px solid #F59E0B; padding:24px; border-radius:8px;">
                    <div style="font-weight:700; color:#F59E0B; font-size:11px; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px;">Brand Impersonation</div>
                    <div style="font-size:24px; font-weight:800; color:#0F172A; margin-bottom:12px;">Moderate</div>
                    <div style="color:#475569; font-size:13px;">Lookalike domains actively monitored in certificate logs.</div>
                </div>
                <div style="border:1px solid #E2E8F0; border-top:3px solid #00A3FF; padding:24px; border-radius:8px;">
                    <div style="font-weight:700; color:#00A3FF; font-size:11px; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px;">Outbound Posture</div>
                    <div style="font-size:24px; font-weight:800; color:#0F172A; margin-bottom:12px;">Mixed</div>
                    <div style="color:#475569; font-size:13px;">DMARC enforcement and certificate controls require attention.</div>
                </div>
            </div>
        </div>
        """

    def _render_vendor_footprint_html(self) -> str:
        platforms = self.tech.get("saas_platforms", []) + self.tech.get("identity_providers", []) + self.tech.get("email_marketing", [])
        platform_html = ""
        for i, p in enumerate(platforms[:5]):
            platform_html += f"""
            <div style="border:1px solid #E2E8F0; border-left:3px solid #F43F5E; padding:24px; border-radius:8px; margin-bottom:16px;">
                <div style="display:flex; justify-content:space-between;">
                    <div>
                        <div style="font-size:20px; font-weight:700; color:#0F172A;">{p}</div>
                        <div style="color:#64748B; font-size:13px; margin-top:4px;">Primary work environment</div>
                    </div>
                    <div style="background:#FCEBEB; color:#E11D48; padding:4px 12px; border-radius:20px; font-size:11px; font-weight:700; height:fit-content;">HIGH DESIRABILITY</div>
                </div>
                <div style="margin-top:16px; background:#F8FAFC; padding:12px; border-radius:6px; font-family:monospace; font-size:11px; color:#475569;">
                    Detected via DNS TXT / MX records
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <div>
                    <div style="color:#00A3FF; font-weight:700; font-size:12px; letter-spacing:0.1em; text-transform:uppercase; margin-bottom:8px;">Section 03</div>
                    <div class="section-title">Your stack, ordered by attacker preference.</div>
                </div>
                <div class="pill pill-findings">Findings</div>
            </div>
            <p style="font-size:16px; max-width:800px; color:#475569; margin-bottom:40px;">
                Attackers don’t imitate platforms at random. They imitate the ones that work — platforms
                with universal staff recognition. Below: the SaaS we detected in your stack.
            </p>
            {platform_html if platform_html else "<p>No major platforms detected via DNS signatures.</p>"}
        </div>
        """

    def _render_outbound_posture_html(self) -> str:
        dmarc = self.ea.get("dmarc_policy") or "MISSING"
        spf = self.ea.get("spf") or "MISSING"
        return f"""
        <div class="section">
            <div class="section-header">
                <div>
                    <div style="color:#00A3FF; font-weight:700; font-size:12px; letter-spacing:0.1em; text-transform:uppercase; margin-bottom:8px;">Section 06</div>
                    <div class="section-title">Defensive controls — what we can see externally.</div>
                </div>
                <div class="pill pill-findings">Findings</div>
            </div>
            <div style="border:1px solid #E2E8F0; border-radius:8px; overflow:hidden;">
                <table style="width:100%; border-collapse:collapse; text-align:left;">
                    <tr style="background:#F8FAFC; border-bottom:1px solid #E2E8F0;">
                        <th style="padding:16px; font-weight:600; color:#0F172A;">Control</th>
                        <th style="padding:16px; font-weight:600; color:#0F172A;">Status</th>
                        <th style="padding:16px; font-weight:600; color:#0F172A;">Recommendation</th>
                    </tr>
                    <tr style="border-bottom:1px solid #E2E8F0;">
                        <td style="padding:16px; font-weight:600;">DMARC enforcement</td>
                        <td style="padding:16px; color:#64748B;">p={dmarc}</td>
                        <td style="padding:16px; color:#D97706;">Move to p=quarantine, then p=reject.</td>
                    </tr>
                    <tr style="border-bottom:1px solid #E2E8F0;">
                        <td style="padding:16px; font-weight:600;">SPF strict mode</td>
                        <td style="padding:16px; color:#64748B;">{spf}</td>
                        <td style="padding:16px; color:#D97706;">Ensure all sending domains have SPF -all.</td>
                    </tr>
                    <tr style="border-bottom:1px solid #E2E8F0;">
                        <td style="padding:16px; font-weight:600;">BIMI</td>
                        <td style="padding:16px; color:#64748B;">{self.ea.get("bimi") or "MISSING"}</td>
                        <td style="padding:16px; color:#D97706;">Publish BIMI record for brand logo in inboxes.</td>
                    </tr>
                </table>
            </div>
        </div>
        """

    def _render_hidden_infra_html(self) -> str:
        subs = self.subdomains[:8]
        sub_html = ""
        for s in subs:
            fqdn = s.get("dns_name", "")
            risk = s.get("risk_level", "info").upper()
            col = "#E11D48" if risk in ("CRITICAL", "HIGH") else "#64748B"
            sub_html += f"""
            <tr style="border-bottom:1px solid #E2E8F0;">
                <td style="padding:12px 16px; font-family:monospace; font-size:12px;">{fqdn}</td>
                <td style="padding:12px 16px; font-weight:600; font-size:11px; color:{col};">{risk}</td>
            </tr>
            """
            
        return f"""
        <div class="section">
            <div class="section-header">
                <div>
                    <div style="color:#00A3FF; font-weight:700; font-size:12px; letter-spacing:0.1em; text-transform:uppercase; margin-bottom:8px;">Section 07</div>
                    <div class="section-title">The assets attackers find that you may not know exist.</div>
                </div>
                <div class="pill pill-findings">Findings</div>
            </div>
            
            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:20px; margin-bottom:40px;">
                <div style="background:#F8FAFC; border:1px solid #E2E8F0; padding:24px; border-radius:8px; text-align:center;">
                    <div style="font-size:36px; font-weight:800; color:#0F172A;">{len(self.subdomains)}</div>
                    <div style="font-size:11px; font-weight:700; color:#64748B; text-transform:uppercase; letter-spacing:0.05em; margin-top:8px;">Total Subdomains</div>
                </div>
                <div style="background:#FCEBEB; border:1px solid #FECDD3; padding:24px; border-radius:8px; text-align:center;">
                    <div style="font-size:36px; font-weight:800; color:#E11D48;">{sum(1 for s in self.subdomains if s.get("risk_level") in ("high", "critical"))}</div>
                    <div style="font-size:11px; font-weight:700; color:#E11D48; text-transform:uppercase; letter-spacing:0.05em; margin-top:8px;">High-Risk</div>
                </div>
            </div>
            
            <table style="width:100%; border-collapse:collapse; text-align:left; border:1px solid #E2E8F0; border-radius:8px; overflow:hidden;">
                <tr style="background:#F8FAFC; border-bottom:1px solid #E2E8F0;">
                    <th style="padding:12px 16px; font-size:10px; text-transform:uppercase; letter-spacing:0.05em; color:#64748B;">Subdomain</th>
                    <th style="padding:12px 16px; font-size:10px; text-transform:uppercase; letter-spacing:0.05em; color:#64748B;">Risk</th>
                </tr>
                {sub_html}
            </table>
        </div>
        """

    def _render_minimisation_html(self) -> str:
        return """
        <div class="section">
            <div class="section-header">
                <div>
                    <div style="color:#00A3FF; font-weight:700; font-size:12px; letter-spacing:0.1em; text-transform:uppercase; margin-bottom:8px;">Section 09</div>
                    <div class="section-title">Minimising your attack surface.</div>
                </div>
                <div class="pill pill-action">Action</div>
            </div>
            <p style="font-size:16px; max-width:800px; color:#475569; margin-bottom:40px;">
                Everything from the previous sections, sequenced by impact. <strong>This fortnight</strong> is what you
                should not wait on; <strong>this quarter</strong> is the substantive minimisation work.
            </p>
            
            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:20px;">
                <div style="border:1px solid #E2E8F0; border-top:3px solid #E11D48; border-radius:8px; padding:24px; background:#FAFAFA;">
                    <div style="font-weight:800; font-size:16px; margin-bottom:20px; color:#0F172A;">This fortnight</div>
                    <div style="background:#FFF; padding:16px; border-radius:6px; border:1px solid #E2E8F0; margin-bottom:12px;">
                        <div style="font-weight:700; font-size:13px; color:#0F172A;">Address high-risk subdomains</div>
                        <div style="font-size:11px; color:#64748B; margin-top:4px;">Infra &middot; &lt; 1 day</div>
                    </div>
                </div>
                <div style="border:1px solid #E2E8F0; border-top:3px solid #F59E0B; border-radius:8px; padding:24px; background:#FAFAFA;">
                    <div style="font-weight:800; font-size:16px; margin-bottom:20px; color:#0F172A;">This quarter</div>
                    <div style="background:#FFF; padding:16px; border-radius:6px; border:1px solid #E2E8F0; margin-bottom:12px;">
                        <div style="font-weight:700; font-size:13px; color:#0F172A;">Move DMARC to p=quarantine</div>
                        <div style="font-size:11px; color:#64748B; margin-top:4px;">Brand &middot; 30 min</div>
                    </div>
                </div>
                <div style="border:1px solid #E2E8F0; border-top:3px solid #0EA5E9; border-radius:8px; padding:24px; background:#FAFAFA;">
                    <div style="font-weight:800; font-size:16px; margin-bottom:20px; color:#0F172A;">This year</div>
                    <div style="background:#FFF; padding:16px; border-radius:6px; border:1px solid #E2E8F0; margin-bottom:12px;">
                        <div style="font-weight:700; font-size:13px; color:#0F172A;">Implement CAA records</div>
                        <div style="font-size:11px; color:#64748B; margin-top:4px;">Infra &middot; varies</div>
                    </div>
                </div>
            </div>
        </div>
        """

    def render_html(self, brand: "BrandConfig") -> str:
        body = (
            self._render_cover_html() +
            self._render_at_a_glance_html() +
            self._render_vendor_footprint_html() +
            self._render_outbound_posture_html() +
            self._render_hidden_infra_html() +
            self._render_minimisation_html()
        )
        return self._html_shell_branded(brand, "Health Report", body)

    def render_md(self, brand: "BrandConfig") -> str:
        # A simple markdown rendering for presentation injection
        return f"""# Datazag Health Report: {self.domain}

## At a glance
- **Trust Grade:** {self._get_trust_grade(max(self._get_platform_risk_score(), self._get_infra_risk_score()))}
- **Platform Exposure:** {self._get_platform_risk_score()}/100
- **Infrastructure Exposure:** {self._get_infra_risk_score()}/100

## Vendor Footprint
Detected Platforms: {", ".join(self.tech.get("saas_platforms", []) + self.tech.get("identity_providers", []))}

## Outbound Posture
- **DMARC:** {self.ea.get("dmarc_policy") or "MISSING"}
- **SPF:** {self.ea.get("spf") or "MISSING"}

## Subdomains
- Total Subdomains: {len(self.subdomains)}
- High Risk: {sum(1 for s in self.subdomains if s.get("risk_level") in ("high", "critical"))}

## Minimisation Roadmap
1. Address high-risk subdomains (This fortnight)
2. Move DMARC to p=quarantine (This quarter)
3. Implement CAA records (This year)
"""
