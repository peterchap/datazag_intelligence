"""Teaser renderer — standalone HTML artefact + notification email.

Reuses the report design tokens and the funnel/tier visual vocabulary so
teaser → report continuity is visual (WU20 rule 2). The artefact is expected
to be forwarded internally — it is watermarked with the requesting email and
carries its expiry. No platform-global figures are bound here (renderer guard:
this module receives ONLY the TeaserViewModel — counts, proofs, band).
"""
from __future__ import annotations

import html as _html

from design.generated.tokens import CSS_LOGO, CSS_ROOT
from scopeteaser.bands import PARTNER_DISCOUNT_URL, band_range_label, band_subscription_label
from scopeteaser.contract import TeaserViewModel

_TIER_META = (
    ("declared", "Declared", "The domains you told us about"),
    ("strong", "Strongly associated", "High-confidence: you own these"),
    ("possible", "Possible", "Medium-confidence: named in the full report"),
    ("defensive", "Defensive / acquisition", "Named in the full report"),
)

_CSS = (
    CSS_ROOT
    + CSS_LOGO
    + r"""
*{margin:0;padding:0;box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{background:var(--tint);font-family:Inter,system-ui,sans-serif;color:var(--ink);padding:26px}
.sheet{max-width:640px;margin:0 auto;background:var(--paper);border:1px solid var(--rule);border-radius:12px;overflow:hidden}
.runner{display:flex;justify-content:space-between;align-items:center;padding:13px 22px;border-bottom:1px solid var(--rule);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3)}
.runner b{font-size:13px;letter-spacing:-.01em;text-transform:none}
.dz-logo{font-family:var(--logo-font);font-weight:800;letter-spacing:var(--logo-tracking)}
.dz-logo-data{color:var(--logo-data-on-light)}
.dz-logo-zag{background:linear-gradient(90deg,var(--logo-zag-light-from),var(--logo-zag-light-to));-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent}
.body{padding:22px}
.kick{display:inline-block;padding:5px 12px;border:1px solid var(--rule);border-radius:100px;font-size:9px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--cyan-deep);margin-bottom:14px}
h1{font-size:22px;letter-spacing:-.02em;line-height:1.2;margin-bottom:6px}
.sub{font-size:12.5px;line-height:1.55;color:var(--ink-2);margin-bottom:18px}
.funnel{display:flex;border:1px solid var(--rule);border-radius:10px;overflow:hidden;margin-bottom:14px}
.funnel .cell{flex:1;padding:14px 16px}
.funnel .declared{background:linear-gradient(135deg,var(--navy),var(--navy-2));color:#fff}
.funnel .fn{font-size:30px;font-weight:900;letter-spacing:-.03em;line-height:1}
.funnel .fl{font-size:10px;margin-top:6px;opacity:.75}
.funnel .found{background:var(--cyan-wash)}
.funnel .found .fn{color:var(--cyan-deep)}.funnel .found .fl{color:var(--ink-2);opacity:1}
.tiers{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px}
.tier{border:1px solid var(--rule);border-radius:8px;padding:10px 12px;border-left:3px solid var(--ink-4)}
.tier.declared{border-left-color:var(--ink-3)}.tier.strong{border-left-color:var(--good)}
.tier.possible{border-left-color:var(--warn)}.tier.defensive{border-left-color:var(--cyan-deep)}
.tier .tk{font-size:9px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-3)}
.tier .td{font-size:10px;line-height:1.45;color:var(--ink-2);margin-top:3px}
.proof{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:16px}
.proof th{text-align:left;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);border-bottom:1px solid var(--rule);padding:6px 8px}
.proof td{border-bottom:1px solid var(--rule-2);padding:7px 8px;vertical-align:top}
.proof .dom{font-family:'JetBrains Mono',monospace;font-size:10.5px;white-space:nowrap}
.band{border:1px solid var(--rule);border-left:3px solid var(--cyan-deep);border-radius:8px;background:var(--tint);padding:13px 15px;margin-bottom:16px}
.band .bk{font-size:9px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:var(--cyan-deep)}
.band .bl{font-size:15px;font-weight:800;letter-spacing:-.01em;margin:4px 0 2px}
.band .bsub{font-size:11px;font-weight:600;color:var(--cyan-deep);margin-bottom:5px}
.band .bn{font-size:10.5px;line-height:1.5;color:var(--ink-2)}
.band .bn a{color:var(--cyan-deep);font-weight:600;text-decoration:none}
.cta{display:inline-block;background:var(--cyan);color:var(--navy);font-weight:800;font-size:12px;padding:11px 18px;border-radius:8px;text-decoration:none;margin-right:8px}
.foot{padding:11px 22px;border-top:1px solid var(--rule);display:flex;justify-content:space-between;font-size:8.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-4)}
"""
)


def render_teaser_html(vm: TeaserViewModel, result_url: str) -> str:
    e = _html.escape
    tier_cards = "".join(
        f'<div class="tier {key}"><div class="tk">{label} · {vm.tier_counts.get(key, 0)}</div>'
        f'<div class="td">{desc}</div></div>'
        for key, label, desc in _TIER_META
    )
    proof_rows = "".join(
        f'<tr><td class="dom">{e(p.domain)}</td><td>{e(p.evidence_line)}</td></tr>'
        for p in vm.proof_domains
    )
    proof_table = (
        f'<table class="proof"><tr><th>Strongly-associated domain</th><th>Connection evidence</th></tr>{proof_rows}</table>'
        if proof_rows else ""
    )
    band = vm.band
    band_html = ""
    if band:
        band_html = (
            f'<div class="band"><div class="bk">Indicative price band</div>'
            f'<div class="bl">{e(band_range_label(band))}</div>'
            f'<div class="bsub">{e(band_subscription_label(band))}</div>'
            f'<div class="bn">The final quote follows scope confirmation — possible-tier domains you '
            f'claim can move the band, and that conversation is the call. '
            f'<a href="{e(PARTNER_DISCOUNT_URL)}">Partner? Ask about channel pricing.</a></div></div>'
        )
    expires = vm.expires.isoformat() if vm.expires else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Datazag estate scope — {vm.evidenced_count} domains evidenced</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&family=Manrope:wght@800&display=swap" rel="stylesheet">
<style>{_CSS}</style></head><body>
<div class="sheet">
  <div class="runner"><b><span class="dz-logo"><span class="dz-logo-data">Data</span><span class="dz-logo-zag">zag</span></span></b><div>Estate scope · prepared for {e(vm.requested_by)}</div></div>
  <div class="body">
    <div class="kick">Cross-Estate Domain Risk Report · scope result</div>
    <h1>You told us {vm.declared_count}. We can evidence {vm.evidenced_count}.</h1>
    <p class="sub">Discovery walked certificate, mail and registration relationships from your declared
    domains. Counts below are the estate we can already see; possible and defensive-tier domains are
    named in the full report, with the connection evidence for every one.</p>
    <div class="funnel">
      <div class="cell declared"><div class="fn">{vm.declared_count}</div><div class="fl">domains you declared</div></div>
      <div class="cell found"><div class="fn">{vm.evidenced_count}</div><div class="fl">evidenced — declared + strongly associated</div></div>
    </div>
    <div class="tiers">{tier_cards}</div>
    {proof_table}
    {band_html}
    <a class="cta" href="{e(result_url)}">Open your scope result →</a>
  </div>
  <div class="foot"><div>Datazag · Confidential — prepared for {e(vm.requested_by)}</div><div>Valid until {expires}</div></div>
</div>
</body></html>"""


def render_email_html(vm: TeaserViewModel, result_url: str) -> str:
    e = _html.escape
    return (
        f"<p>Your Datazag estate scope is ready.</p>"
        f"<p><strong>You told us {vm.declared_count}. We can evidence {vm.evidenced_count}.</strong></p>"
        f'<p><a href="{e(result_url)}">Open your scope result</a> — tier counts, proof domains and '
        f"your indicative price band. Valid until {vm.expires.isoformat() if vm.expires else 'expiry'}.</p>"
    )
