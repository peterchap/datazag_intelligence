"""
freereport/renderer.py
----------------------
`FreeReportRenderer` — renders the 5-page Free Single-Domain Cyber Exposure
Report from a `ReportViewModel`, reproducing `free_report_v1_3.html`.

The CSS is carried verbatim from the prototype (the shared design system); the
body is a Jinja port whose dynamic content comes from `compose.compose_context`.
jinja2 is imported lazily (inside `to_html`) so `to_markdown`/`to_dict` work in
environments without it installed.

Priority pill map: now → "Now", soon → "Soon", plan → "Maturity".
"""

from __future__ import annotations

import json
from typing import Any, Optional

from freereport.compose import compose_context

_PRI_LABEL = {"now": "Now", "soon": "Soon", "plan": "Maturity"}


class FreeReportRenderer:
    def __init__(self, vm, generated_at: Optional[str] = None, now=None, brand: Any = None):
        self.vm = vm
        self.brand = brand
        self.ctx = compose_context(vm, generated_at=generated_at, now=now)

    # ----- JSON / dict -----
    def to_dict(self) -> dict:
        c = dict(self.ctx)
        # Controls are dataclasses; flatten for JSON.
        c["maturity_controls"] = [{"key": x.key, "label": x.label, "tier": x.tier,
                                   "priority": x.priority, "note": x.note}
                                  for x in self.ctx["maturity_controls"]]
        return {"report_type": "free_single_domain_cyber_exposure", "version": "v1.3", **c}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    # ----- Markdown (section parity, text workflows) -----
    def to_markdown(self) -> str:
        c = self.ctx
        L: list[str] = []
        A = L.append
        A(f"# Single-Domain Cyber Exposure Report · Free Edition — {c['org']} ({c['domain']})")
        A(f"\n*{c['date']}*\n")
        A("## Dashboard\n")
        for card in c["dashboard"]:
            A(f"- **{card['key']}: {card['state']}** — {card['note']}")
        A(f"\n{_strip(c['synthesis'])}\n")
        A("### What a cyber insurer would note\n")
        A(_strip(c["lens_body"]))
        A(f"\n_{c['scope_caveat']}_\n")
        A("## The cyber attack economy\n")
        A(f"The attacker decided to target everyone who uses **{c['top_platform']}** — and you do.\n")
        A("**Platforms that put you in the target set:**")
        for p in c["confirmed_platforms"]:
            A(f"- **{p['name']}** (confirmed) — {p['note']} · `{p['evidence']}`")
        A(f"\n{_strip(c['observed_event'])}\n")
        A("## Your attack surface\n")
        for s in c["surfaces"]:
            A(f"### Surface {s['n']} — {_strip(s['name'])}")
            for it in s["items"]:
                A(f"- {_strip(it['html'])}")
            A("")
        A("**Genuine strengths:**")
        for s in c["strengths"]:
            A(f"- {_strip(s['html'])}")
        A("\n**Genuine weaknesses:**")
        for w in c["weaknesses"]:
            A(f"- {_strip(w['html'])}")
        if c["maturity_controls"]:
            A("\n_Maturity opportunities (not weaknesses): "
              + ", ".join(f"{x.label} ({x.note})" for x in c["maturity_controls"]) + "._")
        A("\n## What to do\n")
        for f in c["fixes"]:
            A(f"### {f['num']}. {f['title']} — {_PRI_LABEL[f['priority']]}")
            A(_strip(f["why"]))
            A("```\n" + _strip(f["cmd"]) + "\n```\n")
        if c["monitor_note"]:
            A(f"> Worth a glance: {_strip(c['monitor_note'])}\n")
        A("## What one domain can't show you\n")
        A("Estate discovery (four confidence tiers) and systemic risk — the Cross-Estate Report. "
          "**Find the domains your teams forgot — before attackers do.**")
        return "\n".join(L).rstrip() + "\n"

    # ----- HTML (lazy jinja) -----
    def to_html(self, brand: Any = None) -> str:
        from jinja2 import BaseLoader, Environment, select_autoescape
        env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]),
                          trim_blocks=True, lstrip_blocks=True)
        ctx = dict(self.ctx)
        ctx["pri_label"] = _PRI_LABEL
        ctx["brand"] = brand or self.brand
        return env.from_string(FREE_REPORT_TEMPLATE).render(**ctx)


def _strip(html: str) -> str:
    """Crude tag strip for the markdown/text renditions."""
    import re
    return re.sub(r"<[^>]+>", "", html or "").replace("&nbsp;", " ").replace("&amp;", "&").strip()


# The CSS block below is carried VERBATIM from free_report_v1_3.html (the shared
# design system). Only the <body> is templatised.
FREE_REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Datazag Single-Domain Cyber Exposure Report — {{ org }} ({{ domain }})</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --navy:#0F1923;--navy-2:#16263A;--navy-deep:#0A121C;
  --ink:#0F172A;--ink-2:#33415A;--ink-3:#64748B;--ink-4:#94A3B8;
  --paper:#FFFFFF;--tint:#F6F8FB;--tint-2:#EEF3F8;
  --rule:#E2E8F0;--rule-2:#F0F4F8;
  --cyan:#00C2FF;--cyan-deep:#0091C7;--cyan-wash:#E8F8FF;
  --good:#0E9F6E;--good-wash:#E7F7F0;--good-line:#A8E6CC;
  --warn:#D97706;--warn-wash:#FEF4E6;--warn-line:#F6D9A8;
  --bad:#E02424;--bad-wash:#FDECEC;--bad-line:#F5C6C6;
  --w:#FFFFFF;--w2:rgba(255,255,255,.82);--w3:rgba(255,255,255,.58);--w4:rgba(255,255,255,.34);
  --rd:rgba(255,255,255,.12);
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
@page{size:A4;margin:0}
html,body{background:#D9DEE5;font-family:'Inter',sans-serif;-webkit-font-smoothing:antialiased;color:var(--ink)}
.page{width:794px;min-height:1123px;margin:22px auto;background:var(--paper);position:relative;display:flex;flex-direction:column;page-break-after:always;box-shadow:0 8px 22px -8px rgba(15,25,35,.22)}
.page:last-child{page-break-after:auto}
.runner{display:flex;justify-content:space-between;align-items:center;padding:14px 44px;border-bottom:1px solid var(--rule);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3)}
.runner .r-brand{font-weight:800;color:var(--ink);letter-spacing:-.01em;text-transform:none;font-size:13px}
.runner .r-brand span{color:var(--cyan-deep)}
.runner .r-id{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:0}
.foot{margin-top:auto;padding:11px 44px;border-top:1px solid var(--rule);display:flex;justify-content:space-between;font-size:8.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-4)}
.cover{background:var(--navy);color:var(--w);overflow:hidden}
.cover::after{content:"";position:absolute;inset:0;background:radial-gradient(circle at 85% 5%,rgba(0,194,255,.12),transparent 40%),radial-gradient(circle at 5% 92%,rgba(0,194,255,.06),transparent 42%);pointer-events:none}
.cover>*{position:relative;z-index:1}
.cover .runner{border-bottom-color:var(--rd);color:var(--w3)}
.cover .runner .r-brand{color:var(--w)}.cover .runner .r-brand span{color:var(--cyan)}
.cover-main{flex:1;padding:34px 44px 22px;display:flex;flex-direction:column}
.kick{display:inline-flex;align-items:center;gap:8px;align-self:flex-start;padding:6px 13px;border:1px solid rgba(0,194,255,.3);background:rgba(0,194,255,.08);border-radius:100px;font-size:9.5px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--cyan);margin-bottom:18px}
.kick .d{width:5px;height:5px;border-radius:50%;background:var(--cyan);box-shadow:0 0 7px var(--cyan)}
.cover .org{font-size:30px;font-weight:800;letter-spacing:-.025em;line-height:1.08}
.cover .org .dom{color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:500;letter-spacing:0;display:block;margin-top:7px}
.synthesis{font-size:13.5px;line-height:1.6;color:var(--w2);max-width:600px;margin:16px 0 22px;border-left:2px solid var(--cyan);padding-left:16px}
.synthesis b{color:var(--w);font-weight:600}
.dash{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:20px}
.dcard{background:rgba(255,255,255,.04);border:1px solid var(--rd);border-radius:11px;padding:15px 15px 14px;border-top:3px solid var(--ink-4)}
.dcard.ok{border-top-color:var(--good)}.dcard.warn{border-top-color:var(--warn)}.dcard.bad{border-top-color:var(--bad)}
.dcard .dk{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--w3)}
.dcard .dstate{font-size:18px;font-weight:800;letter-spacing:-.02em;margin:9px 0 7px}
.dcard.ok .dstate{color:#7DE3B6}.dcard.warn .dstate{color:#FFD27A}.dcard.bad .dstate{color:#FF9A9A}
.dcard .dnote{font-size:10.5px;line-height:1.45;color:var(--w2)}
.lens{background:linear-gradient(135deg,rgba(0,194,255,.07),rgba(0,194,255,.02));border:1px solid rgba(0,194,255,.22);border-radius:12px;padding:18px 20px;margin-bottom:0}
.lens .lh{display:flex;align-items:center;gap:9px;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--cyan);margin-bottom:10px}
.lens .lh .li{width:15px;height:15px}
.lens .lbody{font-size:12px;line-height:1.6;color:var(--w2)}
.lens .lbody b{color:var(--w);font-weight:600}
.lens .lscope{font-size:10px;line-height:1.5;color:var(--w3);margin-top:10px;padding-top:10px;border-top:1px solid var(--rd);font-style:italic}
.cover-foot{padding:14px 44px;border-top:1px solid var(--rd);display:flex;justify-content:space-between;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--w4)}
.body{padding:26px 44px 0;flex:1;display:flex;flex-direction:column}
.shead{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;border-bottom:2px solid var(--navy);padding-bottom:13px;margin-bottom:18px}
.shead .stitle{font-size:23px;font-weight:800;letter-spacing:-.022em;line-height:1.12;max-width:490px}
.shead .ssub{font-size:11.5px;color:var(--ink-3);line-height:1.5;max-width:480px;margin-top:6px}
.shead .smeta{text-align:right;flex-shrink:0}
.shead .smeta .sm-k{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-4)}
.shead .smeta .sm-v{font-size:25px;font-weight:900;letter-spacing:-.03em;line-height:1;margin-top:4px}
.sm-v.bad{color:var(--bad)}.sm-v.warn{color:var(--warn)}.sm-v.good{color:var(--good)}
.lead{font-size:13px;line-height:1.62;color:var(--ink-2);margin-bottom:16px;max-width:625px}
.lead b{color:var(--ink);font-weight:600}
.warning-strip{background:var(--navy);color:var(--w);border-radius:10px;padding:16px 20px;margin-bottom:18px;font-size:12.5px;line-height:1.6}
.warning-strip b{color:var(--cyan)}
.prow{display:flex;align-items:center;gap:13px;padding:12px 15px;border:1px solid var(--rule);border-radius:9px;margin-bottom:8px;background:var(--paper)}
.prow.confirmed{border-left:3px solid var(--good)}
.prow .pmark{width:34px;height:34px;border-radius:8px;background:var(--tint-2);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;color:var(--cyan-deep);flex-shrink:0}
.prow .pmain{flex:1;min-width:0}
.prow .pn{font-size:13.5px;font-weight:700;letter-spacing:-.01em}
.prow .pn .tag{font-size:9px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--good);background:var(--good-wash);padding:2px 7px;border-radius:100px;margin-left:8px;vertical-align:1px}
.prow .pr{font-size:11px;color:var(--ink-3);margin-top:1px}
.prow .pev{font-family:'JetBrains Mono',monospace;font-size:9.5px;color:var(--ink-3);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:340px}
.discovery-note{background:var(--tint);border:1px solid var(--rule);border-radius:8px;padding:12px 15px;margin:6px 0 16px;font-size:11.5px;line-height:1.55;color:var(--ink-2)}
.discovery-note b{color:var(--ink);font-weight:600}
.evidence{background:var(--tint);border:1px solid var(--rule);border-radius:9px;padding:14px 16px;font-size:11.5px;line-height:1.6;color:var(--ink-2);margin-bottom:14px}
.evidence b{color:var(--ink);font-weight:600}
.evidence .src{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--ink-3);margin-top:8px;border-top:1px solid var(--rule);padding-top:7px}
.solution{display:flex;align-items:center;gap:18px;background:linear-gradient(135deg,var(--navy),var(--navy-2));color:var(--w);border-radius:12px;padding:18px 22px;margin-top:4px}
.solution .sol-mark{flex:0 0 auto;width:46px;height:46px;border-radius:11px;background:rgba(0,194,255,.14);border:1px solid rgba(0,194,255,.3);display:flex;align-items:center;justify-content:center}
.solution .sol-mark svg{width:24px;height:24px}
.solution .sol-text{flex:1}
.solution .sol-h{font-size:14px;font-weight:700;letter-spacing:-.01em}
.solution .sol-b{font-size:11.5px;color:var(--w2);line-height:1.5;margin-top:3px}
.solution .sol-cta{flex:0 0 auto;background:var(--cyan);color:var(--navy);font-weight:800;font-size:11px;padding:9px 15px;border-radius:7px;text-decoration:none}
.surfaces{display:grid;grid-template-columns:1fr 1fr 1fr;gap:11px;margin-bottom:16px}
.surf{border:1px solid var(--rule);border-radius:11px;overflow:hidden;display:flex;flex-direction:column}
.surf .sf-head{padding:13px 15px;color:var(--w)}
.surf.covered .sf-head{background:linear-gradient(135deg,var(--cyan-deep),#0077A8)}
.surf .sf-k{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;opacity:.8}
.surf .sf-n{font-size:15px;font-weight:800;letter-spacing:-.01em;margin-top:3px}
.surf .sf-cov{font-size:9.5px;font-weight:700;margin-top:8px;display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:100px;background:rgba(255,255,255,.16)}
.surf .sf-body{padding:13px 15px;flex:1;background:var(--paper)}
.surf .sf-item{display:flex;align-items:flex-start;gap:8px;font-size:11px;line-height:1.4;margin-bottom:8px;color:var(--ink-2)}
.surf .sf-item:last-child{margin-bottom:0}
.surf .sf-item .b{width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-top:4px}
.b.ok{background:var(--good)}.b.warn{background:var(--warn)}.b.bad{background:var(--bad)}.b.na{background:var(--ink-4)}.b.cy{background:var(--cyan-deep)}
.surf .sf-foot{padding:10px 15px;border-top:1px solid var(--rule);font-size:10px;color:var(--ink-3);line-height:1.45;background:var(--tint)}
.physical-line{margin-bottom:16px;background:var(--tint);border:1px solid var(--rule);border-left:3px solid var(--ink-4);border-radius:8px;padding:11px 15px;font-size:11px;line-height:1.5;color:var(--ink-3)}
.physical-line b{color:var(--ink-2);font-weight:600}
.balance{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:4px}
.bcol{border-radius:10px;padding:14px 16px}
.bcol.good{background:var(--good-wash);border:1px solid var(--good-line)}
.bcol.bad{background:var(--bad-wash);border:1px solid var(--bad-line)}
.bcol .bh{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-bottom:9px}
.bcol.good .bh{color:var(--good)}.bcol.bad .bh{color:var(--bad)}
.bcol .bi{font-size:11.5px;line-height:1.5;color:var(--ink-2);margin-bottom:7px;padding-left:14px;position:relative}
.bcol .bi:last-child{margin-bottom:0}
.bcol .bi::before{position:absolute;left:0;top:0;font-weight:700}
.bcol.good .bi::before{content:"+";color:var(--good)}
.bcol.bad .bi::before{content:"\2013";color:var(--bad)}
.bcol .bi code{font-family:'JetBrains Mono',monospace;font-size:10.5px;background:rgba(255,255,255,.6);padding:1px 5px;border-radius:3px}
.fix{border:1px solid var(--rule);border-radius:9px;margin-bottom:10px;overflow:hidden}
.fix .fx-head{display:flex;align-items:center;gap:11px;padding:11px 15px;background:var(--tint)}
.fix .fx-num{width:24px;height:24px;border-radius:6px;background:var(--navy);color:var(--w);font-weight:800;font-size:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.fix .fx-t{font-size:13px;font-weight:700;letter-spacing:-.01em;flex:1}
.fix .fx-pri{font-size:8.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:100px}
.fx-pri.now{color:var(--bad);background:var(--bad-wash)}
.fx-pri.soon{color:var(--warn);background:var(--warn-wash)}
.fx-pri.plan{color:var(--cyan-deep);background:var(--cyan-wash)}
.monitor-note{background:var(--tint);border:1px solid var(--rule);border-left:3px solid var(--ink-4);border-radius:8px;padding:11px 15px;margin-top:4px;font-size:11px;line-height:1.5;color:var(--ink-2)}
.monitor-note .mn-h{display:block;font-size:9px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-3);margin-bottom:5px}
.monitor-note b{color:var(--ink);font-weight:600}
.fix .fx-body{padding:12px 15px;font-size:11.5px;line-height:1.55;color:var(--ink-2)}
.fix .fx-body .why{margin-bottom:9px}
.fix .fx-cmd{font-family:'JetBrains Mono',monospace;font-size:10.5px;background:var(--navy-deep);color:#CFE8F5;padding:10px 13px;border-radius:6px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
.fix .fx-cmd .cm{color:#6BA8C0}
.maturity-note{background:var(--cyan-wash);border:1px solid #B6E8FA;border-radius:9px;padding:13px 16px;margin-top:12px;font-size:11.5px;line-height:1.55;color:var(--ink-2)}
.maturity-note .mh{display:block;font-size:9.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--cyan-deep);margin-bottom:7px}
.maturity-note b{color:var(--ink);font-weight:600}
.primer{border:1px solid var(--bad-line);border-radius:12px;overflow:hidden;margin-bottom:16px}
.primer-scale{display:flex;align-items:center;gap:20px;background:linear-gradient(135deg,#2A0E0E,#3D1414);color:#fff;padding:20px 24px}
.primer-scale .ps-num{font-size:52px;font-weight:900;letter-spacing:-.04em;line-height:.85;color:#FF9A9A;flex:0 0 auto}
.primer-scale .ps-num .sup{font-size:20px;vertical-align:super}
.primer-scale .ps-txt{font-size:12.5px;line-height:1.55;color:var(--w2)}
.primer-scale .ps-txt b{color:#fff;font-weight:600}
.primer-cite{background:var(--bad-wash);padding:8px 24px;font-size:9.5px;color:#7A1212;font-style:italic;font-family:'JetBrains Mono',monospace;letter-spacing:.01em}
.mech{border:1px solid var(--rule);border-radius:12px;overflow:hidden;margin-bottom:16px}
.mech-h{background:var(--navy);color:var(--w);font-size:12px;font-weight:700;letter-spacing:.02em;padding:12px 18px}
.mech-steps{padding:16px 18px 6px;display:flex;flex-direction:column;gap:12px}
.mstep{display:flex;gap:13px;align-items:flex-start}
.mstep .mnum{flex:0 0 auto;width:26px;height:26px;border-radius:50%;background:var(--cyan-wash);color:var(--cyan-deep);font-weight:800;font-size:12px;display:flex;align-items:center;justify-content:center;border:1.5px solid var(--cyan)}
.mstep .mbody{font-size:11.5px;line-height:1.55;color:var(--ink-2)}
.mstep .mbody b{color:var(--ink);font-weight:600}
.mech-punch{margin:8px 18px 16px;background:var(--tint);border-left:3px solid var(--cyan);border-radius:0 7px 7px 0;padding:12px 15px;font-size:12px;line-height:1.55;color:var(--ink);font-weight:500}
.mech-punch b{color:var(--cyan-deep);font-weight:700}
.mech-escalate{display:flex;gap:13px;align-items:flex-start;margin:4px 18px 8px;background:var(--warn-wash);border:1px solid var(--warn-line);border-radius:9px;padding:13px 15px}
.mech-escalate .me-icon{flex:0 0 auto;font-size:16px;color:var(--warn);line-height:1.3}
.mech-escalate .me-body{font-size:11.5px;line-height:1.6;color:#5C3A0A}
.mech-escalate .me-body b{color:#7A4A09;font-weight:700}
.seam{border:1px solid var(--rule);border-radius:12px;overflow:hidden;margin-bottom:14px}
.seam-h{display:flex;align-items:center;gap:14px;padding:14px 18px;background:linear-gradient(135deg,var(--navy),var(--navy-2));color:var(--w)}
.seam-n{flex:0 0 auto;width:34px;height:34px;border-radius:8px;background:rgba(0,194,255,.16);border:1px solid rgba(0,194,255,.3);color:var(--cyan);font-weight:900;font-size:15px;display:flex;align-items:center;justify-content:center}
.seam-title{font-size:15px;font-weight:800;letter-spacing:-.015em}
.seam-sub{font-size:10.5px;color:var(--w3);margin-top:2px;line-height:1.4}
.seam-body{padding:15px 18px;background:var(--paper)}
.seam-lead{font-size:11.5px;line-height:1.55;color:var(--ink-2);margin-bottom:12px}
.tiers{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.tier{border:1px solid var(--rule);border-radius:8px;padding:11px 13px;border-left:3px solid var(--ink-4)}
.tier.declared{border-left-color:var(--ink-3)}
.tier.strong{border-left-color:var(--good)}
.tier.possible{border-left-color:var(--warn)}
.tier.defensive{border-left-color:var(--cyan-deep)}
.tier .tk{font-size:9px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-3)}
.tier .tn{font-size:12px;font-weight:700;color:var(--ink);margin:4px 0 3px;letter-spacing:-.01em}
.tier .td{font-size:10px;line-height:1.45;color:var(--ink-2)}
.seam-note{margin-top:12px;background:var(--tint);border-left:3px solid var(--cyan);border-radius:0 7px 7px 0;padding:10px 14px;font-size:11px;line-height:1.55;color:var(--ink-2)}
.seam-note b{color:var(--ink);font-weight:600}
.sys-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.sys{display:flex;gap:9px;align-items:flex-start;border:1px solid var(--rule);border-radius:8px;padding:10px 13px}
.sys-i{color:var(--cyan-deep);font-size:11px;margin-top:2px}
.sys-t{font-size:10.5px;line-height:1.5;color:var(--ink-2)}
.sys-t b{color:var(--ink);font-weight:600}
.upgrade-cta{display:flex;align-items:center;gap:18px;background:linear-gradient(135deg,#062A38,#0A3D50);color:var(--w);border-radius:12px;padding:18px 22px;margin:14px 0 12px}
.upgrade-cta .uc-text{flex:1}
.upgrade-cta .uc-h{font-size:16px;font-weight:800;letter-spacing:-.02em}
.upgrade-cta .uc-b{font-size:11.5px;color:var(--w2);line-height:1.5;margin-top:3px}
.upgrade-cta .uc-btn{flex:0 0 auto;background:var(--cyan);color:var(--navy);font-weight:800;font-size:12px;padding:11px 18px;border-radius:8px;text-decoration:none}
.gloss-strip{font-size:10px;line-height:1.7;color:var(--ink-3);border-top:1px solid var(--rule);padding-top:11px}
.gloss-strip b{color:var(--ink)}
.gloss-strip span{display:inline;margin-right:14px}
</style>
</head>
<body>

<!-- ============ COVER / DASHBOARD ============ -->
<div class="page cover">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">SINGLE-DOMAIN CYBER EXPOSURE REPORT · FREE EDITION</div></div>
  <div class="cover-main">
    <div class="kick"><span class="d"></span>Single-Domain Cyber Exposure Report · Free Edition · {{ date }}</div>
    <div class="org">{{ org }}<span class="dom">{{ domain }}</span></div>
    <p class="synthesis">{{ synthesis|safe }}</p>
    <div class="dash">
      {% for c in dashboard %}
      <div class="dcard {{ c.cls }}">
        <div class="dk">{{ c.key }}</div>
        <div class="dstate">{{ c.state }}</div>
        <div class="dnote">{{ c.note }}</div>
      </div>
      {% endfor %}
    </div>
    <div class="lens">
      <div class="lh">
        <svg class="li" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-4z" stroke="#00C2FF" stroke-width="1.6" stroke-linejoin="round"/></svg>
        What a cyber insurer would note
      </div>
      <div class="lbody">{{ lens_body|safe }}</div>
      <div class="lscope">{{ scope_caveat }}</div>
    </div>
  </div>
  <div class="cover-foot"><div>Datazag · Cyber Risk Intelligence</div><div>{{ org }} · Confidential · 1 / 5</div></div>
</div>

<!-- ============ PAGE 2 — THE CYBER ATTACK ECONOMY ============ -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ domain }}</div></div>
  <div class="body">
    <div class="shead">
      <div><div class="stitle">How the cyber attack economy works.</div><div class="ssub">Platform impersonation is an industry with business models. Understanding how it operates explains why every organisation on {{ top_platform }} sits in its path.</div></div>
    </div>
    <div class="primer">
      <div class="primer-scale">
        <div class="ps-num">3<span class="sup">rd</span></div>
        <div class="ps-txt"><b>If cybercrime were a country, it would be the world's third-largest economy</b> — behind only the United States and China. It is projected to cost the world <b>$10.5 trillion in 2025</b> — roughly <b>$29 billion every day</b>.</div>
      </div>
      <div class="primer-cite">Source: Cybersecurity Ventures, 2025 Official Cybercrime Report. Industry context, not a Datazag measurement.</div>
    </div>
    <p class="lead">That economy runs on a small number of repeatable business models. The one that reaches your employees is <b>mass credential harvesting</b> — estimated at <b>80–90% of all platform-impersonation activity</b> (industry estimate). It explains why your exposure has little to do with whether anyone has singled you out.</p>
    <div class="mech">
      <div class="mech-h">How mass credential harvesting works — "spray and pray"</div>
      <div class="mech-steps">
        <div class="mstep"><div class="mnum">1</div><div class="mbody"><b>Harvest the list.</b> Criminals buy corporate email lists from breach dumps, or scrape addresses from public directories. They tend not to choose targets — they accumulate them by the million.</div></div>
        <div class="mstep"><div class="mnum">2</div><div class="mbody"><b>Blast identical fakes.</b> Automated frameworks send the same fake {{ top_platform }} alert — "your password has expired," "you have a held message" — to many addresses at once, each pointing at a convincing fake login page.</div></div>
        <div class="mstep"><div class="mnum">3</div><div class="mbody"><b>Harvest credentials at volume.</b> If even 1% of recipients enter their password, the operator nets thousands of valid logins — then bundles and resells them to extortion and ransomware crews.</div></div>
      </div>
      <div class="mech-escalate">
        <div class="me-icon">⚠</div>
        <div class="me-body"><b>It often takes only one — and you may never know it happened.</b> A single working credential moves the organisation off the anonymous spray-and-pray list and onto a <b>curated target list</b>. Because a credential is data, the same access is often <b>resold to multiple buyers at once</b>. And <b>a captured login is usually silent</b> — no outage, no alert; the gap between compromise and discovery is often weeks.</div>
      </div>
      <div class="mech-punch">The attacker never decided to target {{ org }}. The attacker decided to target <b>everyone who uses {{ top_platform }}</b> — and you do. That is the logic of your exposure.</div>
    </div>
    <p class="lead" style="margin-bottom:10px"><b>The platforms that put you in the target set</b> — confirmed from your mail and DNS configuration, not guessed:</p>
    {% for p in confirmed_platforms %}
    <div class="prow confirmed">
      <div class="pmark">{{ p.mark }}</div>
      <div class="pmain">
        <div class="pn">{{ p.name }} <span class="tag">Confirmed</span></div>
        <div class="pr">{{ p.note }}</div>
        <div class="pev">{{ p.evidence }}</div>
      </div>
    </div>
    {% endfor %}
    {% if not confirmed_platforms %}
    <div class="discovery-note">No third-party platform was confirmed from MX / SPF / CNAME evidence for this domain. The industry argument above still applies to any cloud mail or SaaS you operate.</div>
    {% endif %}
    <div class="evidence" style="margin-top:4px">
      <b>What Datazag actually observed reaching toward you.</b> {{ observed_event|safe }}
      <div class="src">Source: external_threat.impersonations · confidence = "exact". The 80–90% and $10.5tn figures are cited industry context; this observation is Datazag's own.</div>
    </div>
    <div class="solution">
      <div class="sol-mark"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2v6m0 0l3-3m-3 3L9 5M5 12a7 7 0 0014 0" stroke="#00C2FF" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="16" r="2.5" stroke="#00C2FF" stroke-width="1.6"/></svg></div>
      <div class="sol-text">
        <div class="sol-h">A captured login is silent. The certificate isn't.</div>
        <div class="sol-b">The fake login page needs a certificate, and that is public the moment it's issued. Platform &amp; Brand Impersonation Watch alerts your team within 5–10 seconds of a certificate for your platforms appearing — one of the earliest moments to act.</div>
      </div>
      <a href="#" class="sol-cta">See the Watch →</a>
    </div>
  </div>
  <div class="foot"><div>The cyber attack economy</div><div>Datazag · Confidential · 2 / 5</div></div>
</div>

<!-- ============ PAGE 3 — ATTACK SURFACE ============ -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ domain }}</div></div>
  <div class="body">
    <div class="shead">
      <div><div class="stitle">Your attack surface.</div><div class="ssub">The three faces of your estate an attacker reads from outside — all observed without touching your network.</div></div>
    </div>
    <p class="lead">Datazag sees three faces of your attack surface entirely from outside your network — how attackers reach your people, your public-facing systems, and the infrastructure you're hosted on. <b>The one surface we don't touch — physical — sits with your other tools, noted beneath.</b></p>
    <div class="surfaces">
      {% for s in surfaces %}
      <div class="surf covered">
        <div class="sf-head">
          <div class="sf-k">Surface {{ s.n }}</div>
          <div class="sf-n">{{ s.name|safe }}</div>
          <div class="sf-cov">● Datazag covers this</div>
        </div>
        <div class="sf-body">
          {% for it in s['items'] %}
          <div class="sf-item"><span class="b {{ it.b }}"></span>{{ it.html|safe }}</div>
          {% endfor %}
        </div>
        <div class="sf-foot">{{ s.foot }}</div>
      </div>
      {% endfor %}
    </div>
    <div class="physical-line"><b>Not covered — physical surface.</b> Hardware, networks, firewalls, operating systems, endpoints and access control sit with your endpoint and network security stack, not Datazag. Knowing where each tool's responsibility ends is how you avoid blind spots.</div>
    <p class="lead" style="margin-top:18px;margin-bottom:12px"><b>The balance on the surfaces we cover.</b> The strengths are real and worth protecting; the weaknesses are concrete but fixable.</p>
    <div class="balance">
      <div class="bcol good">
        <div class="bh">Genuine strengths</div>
        {% for s in strengths %}<div class="bi">{{ s.html|safe }}</div>{% endfor %}
        {% if not strengths %}<div class="bi">Configuration is broadly sound on the surfaces we observe.</div>{% endif %}
      </div>
      <div class="bcol bad">
        <div class="bh">Genuine weaknesses</div>
        {% for w in weaknesses %}<div class="bi">{{ w.html|safe }}</div>{% endfor %}
        {% if not weaknesses %}<div class="bi">No material externally observable weaknesses were found on the covered surfaces.</div>{% endif %}
      </div>
    </div>
    {% if maturity_controls %}
    <div class="maturity-note">
      <span class="mh">Maturity opportunities — not weaknesses</span>
      The following are absent but are <b>advanced or gold-standard</b> controls that many well-run estates have not yet adopted. Their absence is normal and does not create exploitable risk today: {% for c in maturity_controls %}<b>{{ c.label }}</b> ({{ c.note }}){% if not loop.last %}, {% endif %}{% endfor %}. Worth planning, not worth alarm.
    </div>
    {% endif %}
  </div>
  <div class="foot"><div>Attack surface</div><div>Datazag · Confidential · 3 / 5</div></div>
</div>

<!-- ============ PAGE 4 — WHAT TO DO ============ -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ domain }}</div></div>
  <div class="body">
    <div class="shead">
      <div><div class="stitle">What to do.</div><div class="ssub">Exact changes, ranked by exploitability first, then effort. Hand straight to your DNS or platform team.</div></div>
      <div class="smeta"><div class="sm-k">Priority actions</div><div class="sm-v">{{ fix_count }}</div></div>
    </div>
    {% for f in fixes %}
    <div class="fix">
      <div class="fx-head"><div class="fx-num">{{ f.num }}</div><div class="fx-t">{{ f.title }}</div><span class="fx-pri {{ f.priority }}">{{ pri_label[f.priority] }}</span></div>
      <div class="fx-body">
        <div class="why">{{ f.why|safe }}</div>
        <div class="fx-cmd">{{ f.cmd|safe }}</div>
      </div>
    </div>
    {% endfor %}
    {% if not fixes %}
    <div class="discovery-note">No exploitable misconfigurations were found on the covered surfaces. The maturity opportunities on the previous page are worth planning at your own pace.</div>
    {% endif %}
    {% if monitor_note %}
    <div class="monitor-note">
      <span class="mn-h">Worth a glance — not an action</span>
      {{ monitor_note|safe }}
    </div>
    {% endif %}
  </div>
  <div class="foot"><div>Remediation</div><div>Datazag · Confidential · 4 / 5</div></div>
</div>

<!-- ============ PAGE 5 — WHAT ONE DOMAIN CAN'T SHOW ============ -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ domain }}</div></div>
  <div class="body">
    <div class="shead">
      <div><div class="stitle">What one domain can't show you.</div><div class="ssub">This report covers {{ domain }}. Two risks only appear when you look across your whole estate.</div></div>
    </div>
    <p class="lead">A single-domain report answers "how exposed is this domain?" It cannot answer the two questions that keep a security or risk team awake: <b>how many domains do we really own — including the ones we've forgotten</b> — and <b>what's wrong in the same way across all of them at once.</b> The Cross-Estate Report answers both.</p>
    <div class="seam">
      <div class="seam-h">
        <div class="seam-n">01</div>
        <div class="seam-t">
          <div class="seam-title">The domains you didn't know you owned</div>
          <div class="seam-sub">Found in Datazag's 340M-domain corpus and certificate-transparency feed — not from a list you provide.</div>
        </div>
      </div>
      <div class="seam-body">
        <p class="seam-lead">Starting from the domains you declare, Datazag walks certificate SAN relationships, shared mail and DNS infrastructure, and registration patterns to surface the rest of your estate — then sorts everything found into four confidence tiers:</p>
        <div class="tiers">
          <div class="tier declared"><div class="tk">Declared</div><div class="tn">The domains you told us about</div><div class="td">Your starting list — the baseline the rest is measured against.</div></div>
          <div class="tier strong"><div class="tk">Strongly associated</div><div class="tn">High-confidence: you own these</div><div class="td">Shared certificate SANs, same MX + SPF, matching registrar/nameserver patterns, redirects to your primary site, subsidiary-name matches.</div></div>
          <div class="tier possible"><div class="tk">Possible</div><div class="tn">Medium-confidence: review these</div><div class="td">Lexical brand similarity, shared infrastructure, partial naming overlap, parked-but-historically-linked.</div></div>
          <div class="tier defensive"><div class="tk">Defensive / acquisition</div><div class="tn">Consider recovering or monitoring</div><div class="td">For-sale, expired, typo-adjacent, old acquired-company names, and login/payroll/invoice/portal lookalikes attackers favour.</div></div>
        </div>
        <div class="seam-note"><b>Why this matters for {{ domain }}:</b> the estate that carries your brand is often larger than the list any one team holds — acquisitions, regional registrations, campaign microsites and shadow IT accumulate. Unmanaged domains are often easier for attackers to find than for internal teams to govern.</div>
      </div>
    </div>
    <div class="seam">
      <div class="seam-h">
        <div class="seam-n">02</div>
        <div class="seam-t">
          <div class="seam-title">The weaknesses that repeat across your estate</div>
          <div class="seam-sub">Systemic risk is what's wrong in the same way on many domains — hard to see one domain at a time.</div>
        </div>
      </div>
      <div class="seam-body">
        <div class="sys-grid">
          <div class="sys"><div class="sys-i">◆</div><div class="sys-t"><b>Concentration risk.</b> "If one provider falls, X% of the estate goes with it" — single registrar, DNS, mailbox or certificate authority across many domains.</div></div>
          <div class="sys"><div class="sys-i">◆</div><div class="sys-t"><b>Posture variance.</b> Which business units or acquired companies sit below your group security baseline — the classic integration gap.</div></div>
          <div class="sys"><div class="sys-i">◆</div><div class="sys-t"><b>Correlated weakness.</b> "DMARC unenforced on 44% of domains, clustered in acquired and retail" — a pattern, not isolated tickets.</div></div>
          <div class="sys"><div class="sys-i">◆</div><div class="sys-t"><b>Operational calendar.</b> Expired registrations, lapsed certificates and unlocked domains across the estate — the live outages and takeover windows.</div></div>
        </div>
        <div class="seam-note"><b>What the Cross-Estate Report delivers:</b> an estate grade and grade distribution, the concentration map, posture variance by segment, the correlated-weakness rollup, a prioritised exception register, and a full remediation plan — for every domain you own, declared and discovered.</div>
      </div>
    </div>
    <div class="upgrade-cta">
      <div class="uc-text">
        <div class="uc-h">Find the domains your teams forgot — before attackers do.</div>
        <div class="uc-b">Enter your known domains in the Datazag portal — we'll discover the rest and assess systemic risk across the whole estate.</div>
      </div>
      <a href="#" class="uc-btn">Request the Cross-Estate Report →</a>
    </div>
    <div class="gloss-strip">
      <b>Key terms:</b> <span><b>DMARC/SPF</b> — email authentication that reduces mail being spoofed as you.</span> <span><b>CAA</b> — restricts which authorities may issue your certificates.</span> <span><b>Certificate SAN</b> — the list of domains sharing one certificate; a declared link between them.</span> <span><b>Platform impersonation</b> — fake login pages for trusted platforms rather than your brand.</span>
    </div>
  </div>
  <div class="foot"><div>Datazag · datazag.com · intelligence@datazag.com</div><div>Single-Domain Cyber Exposure Report · Free Edition · 5 / 5</div></div>
</div>

</body>
</html>
"""
