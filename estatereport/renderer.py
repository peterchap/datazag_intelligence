"""
estatereport/renderer.py
------------------------
`EstateReportRenderer` — renders the Cross-Estate Domain Risk Report (v2.2):
6 fixed core pages + Appendix A (remediation worksheet, A1–An), reproducing
`cross_estate_v2.html`. The CSS is carried verbatim from that render, which is
itself built on the free-report design system (shared `:root`, `.page/.runner/
.foot`, tiers, seam, CTA). jinja2 is imported lazily.

The renderer BINDS — it computes nothing analytic. Everything (grades, shares,
severities, collapse groupings, worksheet rows) arrives on the EstateReport.
"""

from __future__ import annotations

import json
import math
from typing import Any

from estatereport.contract import EstateReport

_PRI_LABEL = {"now": "Now", "soon": "Soon", "plan": "Maturity"}
_GRADE_CLS = {"A": "ga", "B": "gb", "C": "gc", "D": "gd", "E": "ge", "F": "gf"}


class EstateReportRenderer:
    def __init__(self, report: EstateReport, brand: Any = None):
        self.report = report
        self.brand = brand

    def to_json(self) -> str:
        return json.dumps(self.report.model_dump(mode="json"), indent=2, default=str)

    def to_markdown(self) -> str:
        r = self.report
        L: list[str] = []
        A = L.append
        A(f"# Cross-Estate Domain Risk Report — {r.group}\n")
        A(_strip(r.synthesis_html) + "\n")
        A(f"## Estate discovery\nDeclared {r.discovery.declared_count}; "
          f"{'discovery not enabled' if not r.discovery.enabled else f'{r.discovery.total_found} found'}.\n")
        A("## Concentration & posture variance\n")
        A(f"Estate grade **{r.grade.grade}** ({r.grade.score:.0f}/100).\n")
        for c in r.concentration:
            sev = f" [{c.severity.upper()}]" if c.severity else ""
            A(f"- {c.label}: **{c.provider}** {round(c.share_post_discovery*100)}% "
              f"({c.resilience_tier}, exit {c.exit_friction}){sev} — {c.recommendation}")
        A("\n### Variance")
        for v in r.variance:
            A(f"- {v.segment}: median {v.median_grade}"
              + (f" · OUTLIER (−{v.bands_below_baseline} bands)" if v.outlier else ""))
        A("\n## Correlated weakness & active exposure\n")
        for c in r.correlated:
            A(f"- {c.label}: {c.affected}/{c.estate_size} ({round(c.pct*100)}%)"
              + (f" — clustered in {', '.join(c.segments)}" if c.segment_isolated else ""))
        A(f"\n**Active exposure:** {r.exposure.total_exact} exact impersonations "
          f"({r.exposure.provenance}).\n")
        A("## Exception register\n")
        for e in r.exceptions:
            A(f"{e.rank}. **[{e.severity.upper()}]** {e.title}")
            if e.collapsed_from:
                A(f"   - collapsed from {e.collapsed_from}")
            A(f"   - `{e.evidence_line}`")
        A("\n## Appendix A — remediation worksheet\n")
        for p in r.remediation:
            A(f"### {p.title} — {_PRI_LABEL[p.priority]}")
            for e in p.entries:
                A(f"- [ ] {e.domain} ({e.admin_point}) · now: {e.now} → {e.fix}")
            if p.overflow:
                A(f"- +{p.overflow} more domains in the JSON/MD export")
            A("")
        return "\n".join(L).rstrip() + "\n"

    def to_html(self, brand: Any = None) -> str:
        from jinja2 import BaseLoader, Environment, select_autoescape
        env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]),
                          trim_blocks=True, lstrip_blocks=True)
        return env.from_string(ESTATE_TEMPLATE).render(**self._build_context(brand or self.brand))

    def _build_context(self, brand: Any) -> dict:
        r = self.report
        total = sum(r.grade.distribution.values()) or 1
        grade_rows = [{"letter": g, "count": r.grade.distribution.get(g, 0),
                       "pct": round(r.grade.distribution.get(g, 0) / total * 100),
                       "cls": _GRADE_CLS[g]}
                      for g in ("A", "B", "C", "D", "E", "F")]
        # Appendix pagination: 2 pattern cards per page; glossary on the last.
        chunks = [r.remediation[i:i + 2] for i in range(0, len(r.remediation), 2)] or []
        appendix_pages = []
        for i, ch in enumerate(chunks):
            appendix_pages.append({"n": i + 1, "patterns": ch,
                                   "adm_strip": (i == 0), "glossary": (i == len(chunks) - 1)})
        # Discovery table: discovered rows first (the interesting ones — every one
        # carries its connection evidence), then declared, capped at 18.
        disc_rows = []
        for t in ("strong", "possible", "defensive", "declared"):
            for d in r.discovery.tiers.get(t, []):
                disc_rows.append({
                    "domain": d.domain, "tier": t,
                    "label": {"strong": "Strong", "possible": "Possible",
                              "defensive": "Defensive", "declared": "Declared"}[t],
                    "evidence": "; ".join(e.detail for e in d.evidence) or "—",
                })
        return {
            "r": r, "group": r.group, "snapshot": (r.generated_at or "")[:10],
            "pri_label": _PRI_LABEL, "grade_rows": grade_rows,
            "appendix_pages": appendix_pages, "appendix_total": len(appendix_pages),
            "gradepill_cls": _GRADE_CLS, "brand": brand, "disc_rows": disc_rows[:18],
        }


def _strip(html: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", html or "").replace("&nbsp;", " ").replace("&amp;", "&").strip()


# CSS carried verbatim from cross_estate_v2.html (built on the free-report design
# system). Only the <body> is templatised.
ESTATE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Datazag Cross-Estate Domain Risk Report — {{ group }}</title>
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
.dcard.ok{border-top-color:var(--good)}.dcard.warn{border-top-color:var(--warn)}.dcard.bad{border-top-color:var(--bad)}.dcard.cy{border-top-color:var(--cyan)}
.dcard .dk{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--w3)}
.dcard .dstate{font-size:18px;font-weight:800;letter-spacing:-.02em;margin:9px 0 7px}
.dcard.ok .dstate{color:#7DE3B6}.dcard.warn .dstate{color:#FFD27A}.dcard.bad .dstate{color:#FF9A9A}.dcard.cy .dstate{color:#7FDBFF}
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
.sm-v.bad{color:var(--bad)}.sm-v.warn{color:var(--warn)}.sm-v.good{color:var(--good)}.sm-v.cy{color:var(--cyan-deep)}
.lead{font-size:13px;line-height:1.62;color:var(--ink-2);margin-bottom:16px;max-width:625px}
.lead b{color:var(--ink);font-weight:600}
.discovery-note{background:var(--tint);border:1px solid var(--rule);border-radius:8px;padding:12px 15px;margin:6px 0 16px;font-size:11.5px;line-height:1.55;color:var(--ink-2)}
.discovery-note b{color:var(--ink);font-weight:600}
.discovery-note code{font-family:'JetBrains Mono',monospace;font-size:10.5px;background:var(--tint-2);padding:1px 5px;border-radius:3px}
.monitor-note{background:var(--tint);border:1px solid var(--rule);border-left:3px solid var(--ink-4);border-radius:8px;padding:11px 15px;margin-top:4px;font-size:11px;line-height:1.5;color:var(--ink-2)}
.monitor-note .mn-h{display:block;font-size:9px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-3);margin-bottom:5px}
.monitor-note b{color:var(--ink);font-weight:600}
.tiers{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.tier{border:1px solid var(--rule);border-radius:8px;padding:11px 13px;border-left:3px solid var(--ink-4)}
.tier.declared{border-left-color:var(--ink-3)}
.tier.strong{border-left-color:var(--good)}
.tier.possible{border-left-color:var(--warn)}
.tier.defensive{border-left-color:var(--cyan-deep)}
.tier .tk{font-size:9px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-3)}
.tier .tn{font-size:12px;font-weight:700;color:var(--ink);margin:4px 0 3px;letter-spacing:-.01em}
.tier .td{font-size:10px;line-height:1.45;color:var(--ink-2)}
.funnel{display:flex;align-items:stretch;gap:0;border:1px solid var(--rule);border-radius:12px;overflow:hidden;margin-bottom:16px}
.funnel .f-declared{background:linear-gradient(135deg,var(--navy),var(--navy-2));color:var(--w);padding:20px 24px;flex:0 0 auto;min-width:190px;display:flex;flex-direction:column;justify-content:center}
.funnel .f-declared .fn{font-size:44px;font-weight:900;letter-spacing:-.04em;line-height:.9}
.funnel .f-declared .fl{font-size:11px;color:var(--w2);margin-top:8px;line-height:1.4}
.funnel .f-arrow{display:flex;align-items:center;padding:0 14px;background:var(--tint);color:var(--ink-4);font-size:20px;font-weight:300}
.funnel .f-found{background:linear-gradient(135deg,#062A38,#0A3D50);color:var(--w);padding:20px 24px;flex:1;display:flex;align-items:center;gap:20px}
.funnel .f-found .fn{font-size:44px;font-weight:900;letter-spacing:-.04em;line-height:.9;color:var(--cyan)}
.funnel .f-found .fl{font-size:12px;color:var(--w2);line-height:1.5}
.funnel .f-found .fl b{color:var(--w);font-weight:600}
.disc-table{width:100%;border-collapse:collapse;margin-bottom:12px;font-size:10.5px}
.disc-table th{text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-4);padding:6px 9px;border-bottom:1.5px solid var(--rule)}
.disc-table td{padding:6px 9px;border-bottom:1px solid var(--rule-2);vertical-align:top}
.disc-table td.dom{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--ink);font-weight:500;white-space:nowrap}
.disc-table td.ev{font-size:9.5px;color:var(--ink-2);line-height:1.45}
.disc-table td.ev code{font-family:'JetBrains Mono',monospace;font-size:9px;background:var(--tint-2);padding:1px 4px;border-radius:3px}
.disc-table tr:last-child td{border-bottom:none}
.tpill{font-size:8px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;padding:2px 8px;border-radius:100px;white-space:nowrap}
.tpill.strong{color:var(--good);background:var(--good-wash)}
.tpill.possible{color:var(--warn);background:var(--warn-wash)}
.tpill.defensive{color:var(--cyan-deep);background:var(--cyan-wash)}
.tpill.declared{color:var(--ink-3);background:var(--tint-2)}
.grade-strip{display:flex;align-items:stretch;gap:12px;margin-bottom:16px}
.grade-box{flex:0 0 auto;min-width:150px;background:linear-gradient(135deg,var(--navy),var(--navy-2));color:var(--w);border-radius:12px;padding:16px 20px;display:flex;flex-direction:column;justify-content:center}
.grade-box .gb-k{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--w3)}
.grade-box .gb-g{font-size:46px;font-weight:900;letter-spacing:-.03em;line-height:1;color:#FFD27A;margin:6px 0 4px}
.grade-box .gb-s{font-size:10px;color:var(--w2);font-family:'JetBrains Mono',monospace}
.grade-dist{flex:1;border:1px solid var(--rule);border-radius:12px;padding:14px 18px}
.grade-dist .gd-k{font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-4);margin-bottom:10px}
.gd-row{display:flex;align-items:center;gap:9px;margin-bottom:6px}
.gd-row:last-child{margin-bottom:0}
.gd-row .gl{width:14px;font-size:11px;font-weight:800;color:var(--ink-2);font-family:'JetBrains Mono',monospace}
.gd-row .gbar{flex:1;height:13px;background:var(--tint-2);border-radius:4px;overflow:hidden}
.gd-row .gfill{height:100%;border-radius:4px}
.gd-row .gn{width:20px;font-size:10px;font-weight:700;color:var(--ink-3);text-align:right;font-family:'JetBrains Mono',monospace}
.gfill.ga{background:var(--good)}.gfill.gb{background:#5BBF8F}.gfill.gc{background:var(--warn)}
.gfill.gd{background:#C2661C}.gfill.ge{background:var(--bad)}.gfill.gf{background:#8B1414}
.conc{margin-bottom:14px}
.conc-row{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--rule-2)}
.conc-row:last-child{border-bottom:none}
.conc-row .ck{flex:0 0 150px;font-size:10.5px;font-weight:600;color:var(--ink-2);line-height:1.3}
.conc-row .cprov{flex:0 0 132px;font-size:10.5px;font-weight:700;color:var(--ink);letter-spacing:-.01em}
.conc-row .cprov .ct{display:block;font-size:8px;font-weight:500;color:var(--ink-4);margin-top:1px;letter-spacing:0}
.conc-row .cbar{flex:1;height:15px;background:var(--tint-2);border-radius:4px;overflow:hidden;position:relative}
.conc-row .cfill{height:100%;border-radius:4px;background:var(--cyan-deep)}
.conc-row .cpct{flex:0 0 66px;text-align:right;font-size:12px;font-weight:800;font-family:'JetBrains Mono',monospace;color:var(--ink)}
.conc-row .cpct .delta{display:block;font-size:8.5px;font-weight:500;color:var(--ink-4)}
.conc-row .csev{flex:0 0 74px;text-align:right}
.csev .ex-sev{font-size:8.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:100px}
.csev .none{font-size:8.5px;color:var(--ink-4)}
.var-table{width:100%;border-collapse:collapse;margin-bottom:14px;font-size:11px}
.var-table th{text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-4);padding:7px 10px;border-bottom:1.5px solid var(--rule)}
.var-table td{padding:8px 10px;border-bottom:1px solid var(--rule-2);vertical-align:middle}
.var-table td.seg{font-weight:700;color:var(--ink)}
.var-table td.mono{font-family:'JetBrains Mono',monospace;font-size:10.5px}
.var-table tr:last-child td{border-bottom:none}
.gradepill{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:7px;font-weight:900;font-size:13px;color:#fff}
.gradepill.ga{background:var(--good)}.gradepill.gb{background:#5BBF8F}.gradepill.gc{background:var(--warn)}
.gradepill.gd{background:#C2661C}.gradepill.ge{background:var(--bad)}.gradepill.gf{background:#8B1414}
.outlier-tag{font-size:8.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--bad);background:var(--bad-wash);padding:3px 9px;border-radius:100px}
.cw{border:1px solid var(--rule);border-radius:9px;margin-bottom:8px;padding:11px 15px;display:flex;align-items:center;gap:14px}
.cw .cw-main{flex:1;min-width:0}
.cw .cw-t{font-size:12.5px;font-weight:700;letter-spacing:-.01em;color:var(--ink)}
.cw .cw-seg{font-size:10px;color:var(--ink-3);margin-top:2px}
.cw .cw-seg b{color:var(--warn);font-weight:700}
.cw .cw-bar{flex:0 0 150px;height:13px;background:var(--tint-2);border-radius:4px;overflow:hidden}
.cw .cw-fill{height:100%;border-radius:4px;background:var(--warn)}
.cw .cw-fill.hot{background:var(--bad)}
.cw .cw-pct{flex:0 0 88px;text-align:right;font-size:12px;font-weight:800;font-family:'JetBrains Mono',monospace;color:var(--ink)}
.cw .cw-pct .of{display:block;font-size:8.5px;font-weight:500;color:var(--ink-4)}
.scale{display:flex;align-items:stretch;gap:0;border:1px solid var(--bad-line);border-radius:12px;overflow:hidden;margin-bottom:16px}
.scale .sbig{background:linear-gradient(135deg,#2A0E0E,#3D1414);color:#fff;padding:22px 26px;flex:0 0 auto;display:flex;flex-direction:column;justify-content:center;min-width:215px}
.scale .sbig .snum{font-size:44px;font-weight:900;letter-spacing:-.04em;line-height:.9;color:#FF9A9A}
.scale .sbig .slab{font-size:11px;color:var(--w2);margin-top:8px;line-height:1.4}
.scale .sbig .sprov{font-size:9px;color:var(--w3);margin-top:9px;font-family:'JetBrains Mono',monospace;letter-spacing:.01em;border-top:1px solid var(--rd);padding-top:8px}
.scale .stext{padding:20px 24px;background:var(--bad-wash);font-size:12.5px;line-height:1.6;color:#7A1212;display:flex;align-items:center}
.scale .stext b{font-weight:700}
.imp-table{width:100%;border-collapse:collapse;margin-bottom:14px;font-size:10.5px}
.imp-table th{text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-4);padding:6px 9px;border-bottom:1.5px solid var(--rule)}
.imp-table td{padding:7px 9px;border-bottom:1px solid var(--rule-2);vertical-align:top}
.imp-table td.dom{font-family:'JetBrains Mono',monospace;font-size:9.5px;color:var(--ink)}
.imp-table tr:last-child td{border-bottom:none}
.cal-table{width:100%;border-collapse:collapse;margin-bottom:14px;font-size:11px}
.cal-table th{text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-4);padding:7px 10px;border-bottom:1.5px solid var(--rule)}
.cal-table td{padding:7px 10px;border-bottom:1px solid var(--rule-2);vertical-align:top}
.cal-table td.dom{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:500;color:var(--ink);white-space:nowrap}
.cal-table tr:last-child td{border-bottom:none}
.due{font-size:8.5px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:100px;white-space:nowrap}
.due.overdue{color:#fff;background:var(--bad)}
.due.soon{color:var(--warn);background:var(--warn-wash)}
.due.later{color:var(--ink-3);background:var(--tint-2)}
.exc{border:1px solid var(--rule);border-radius:9px;margin-bottom:9px;overflow:hidden}
.exc .ex-head{display:flex;align-items:center;gap:11px;padding:10px 15px;background:var(--tint)}
.exc .ex-num{width:24px;height:24px;border-radius:6px;background:var(--navy);color:var(--w);font-weight:800;font-size:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.exc .ex-t{font-size:12.5px;font-weight:700;letter-spacing:-.01em;flex:1;line-height:1.3}
.exc .ex-sev{font-size:8.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:100px;flex-shrink:0}
.ex-sev.high{color:var(--bad);background:var(--bad-wash)}
.ex-sev.elevated{color:var(--warn);background:var(--warn-wash)}
.ex-sev.watch{color:var(--cyan-deep);background:var(--cyan-wash)}
.exc .ex-body{padding:10px 15px;font-size:11px;line-height:1.55;color:var(--ink-2)}
.exc .ex-body b{color:var(--ink);font-weight:600}
.exc .ex-ev{font-family:'JetBrains Mono',monospace;font-size:9.5px;color:var(--ink-3);margin-top:6px;padding-top:6px;border-top:1px solid var(--rule-2)}
.seam{border:1px solid var(--rule);border-radius:12px;overflow:hidden;margin-bottom:14px}
.seam-h{display:flex;align-items:center;gap:14px;padding:14px 18px;background:linear-gradient(135deg,var(--navy),var(--navy-2));color:var(--w)}
.seam-n{flex:0 0 auto;width:34px;height:34px;border-radius:8px;background:rgba(0,194,255,.16);border:1px solid rgba(0,194,255,.3);color:var(--cyan);font-weight:900;font-size:15px;display:flex;align-items:center;justify-content:center}
.seam-title{font-size:15px;font-weight:800;letter-spacing:-.015em}
.seam-sub{font-size:10.5px;color:var(--w3);margin-top:2px;line-height:1.4}
.seam-body{padding:15px 18px;background:var(--paper)}
.seam-lead{font-size:11.5px;line-height:1.55;color:var(--ink-2);margin-bottom:12px}
.seam-note{margin-top:12px;background:var(--tint);border-left:3px solid var(--cyan);border-radius:0 7px 7px 0;padding:10px 14px;font-size:11px;line-height:1.55;color:var(--ink-2)}
.seam-note b{color:var(--ink);font-weight:600}
.upgrade-cta{display:flex;align-items:center;gap:18px;background:linear-gradient(135deg,#062A38,#0A3D50);color:var(--w);border-radius:12px;padding:18px 22px;margin:14px 0 12px}
.upgrade-cta .uc-text{flex:1}
.upgrade-cta .uc-h{font-size:16px;font-weight:800;letter-spacing:-.02em}
.upgrade-cta .uc-b{font-size:11.5px;color:var(--w2);line-height:1.5;margin-top:3px}
.upgrade-cta .uc-btn{flex:0 0 auto;background:var(--cyan);color:var(--navy);font-weight:800;font-size:12px;padding:11px 18px;border-radius:8px;text-decoration:none}
.limits{margin-top:14px;border:1px solid var(--rule);border-radius:10px;overflow:hidden}
.limits .lim-h{background:var(--navy);color:var(--w);font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:10px 16px}
.limits .lim-grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--rule)}
.limits .lim-item{background:var(--paper);padding:12px 16px;font-size:10.5px;line-height:1.5;color:var(--ink-2)}
.limits .lim-item b{color:var(--ink);font-weight:700}
.gloss-strip{font-size:10px;line-height:1.7;color:var(--ink-3);border-top:1px solid var(--rule);padding-top:11px;margin-top:12px}
.gloss-strip b{color:var(--ink)}
.gloss-strip span{display:inline;margin-right:14px}
.evidence{background:var(--tint);border:1px solid var(--rule);border-radius:8px;padding:12px 15px;margin:6px 0 14px;font-size:11.5px;line-height:1.55;color:var(--ink-2)}
.evidence b{color:var(--ink);font-weight:600}
.fix{border:1px solid var(--rule);border-radius:9px;margin-bottom:12px;overflow:hidden}
.fix .fx-head{display:flex;align-items:center;gap:11px;padding:11px 15px;background:var(--tint)}
.fix .fx-num{width:24px;height:24px;border-radius:6px;background:var(--navy);color:var(--w);font-weight:800;font-size:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.fix .fx-t{font-size:13px;font-weight:700;letter-spacing:-.01em;flex:1}
.fix .fx-pri{font-size:8.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:100px}
.fx-pri.now{color:var(--bad);background:var(--bad-wash)}
.fx-pri.soon{color:var(--warn);background:var(--warn-wash)}
.fx-pri.plan{color:var(--cyan-deep);background:var(--cyan-wash)}
.fix .fx-body{padding:12px 15px;font-size:11.5px;line-height:1.55;color:var(--ink-2)}
.fix .fx-body .why{margin-bottom:9px}
.fix .fx-body .why b{color:var(--ink);font-weight:600}
.fix .fx-cmd{font-family:'JetBrains Mono',monospace;font-size:10px;background:var(--navy-deep);color:#CFE8F5;padding:10px 13px;border-radius:6px;line-height:1.6;white-space:pre-wrap;word-break:break-word;margin-bottom:10px}
.fix .fx-cmd .cm{color:#6BA8C0}
.ws-table{width:100%;border-collapse:collapse;font-size:10px}
.ws-table th{text-align:left;font-size:8px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-4);padding:6px 8px;border-bottom:1.5px solid var(--rule)}
.ws-table td{padding:6px 8px;border-bottom:1px solid var(--rule-2);vertical-align:top}
.ws-table td.dom{font-family:'JetBrains Mono',monospace;font-size:9.5px;font-weight:500;color:var(--ink);white-space:nowrap}
.ws-table td.adm{font-size:9px;color:var(--ink-3);white-space:nowrap}
.ws-table td.now{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--bad)}
.ws-table td.tgt{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--ink-2)}
.ws-table tr:last-child td{border-bottom:none}
.ws-check{width:13px;height:13px;border:1.5px solid var(--ink-4);border-radius:3px;display:inline-block}
.adm-strip{display:flex;gap:9px;margin-bottom:14px}
.adm{flex:1;border:1px solid var(--rule);border-radius:9px;padding:10px 13px}
.adm .ak{font-size:8.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-4)}
.adm .an{font-size:13px;font-weight:800;color:var(--ink);margin-top:3px;letter-spacing:-.01em}
.adm .ad{font-size:9.5px;color:var(--ink-3);margin-top:2px;line-height:1.4}
.gloss{columns:2;column-gap:28px;margin-top:4px}
.gterm{break-inside:avoid;margin-bottom:11px}
.gterm .gt{font-size:11px;font-weight:700;color:var(--ink)}
.gterm .gd{font-size:10px;color:var(--ink-2);line-height:1.48;margin-top:2px}
</style></head><body>

<!-- PAGE 1 — COVER -->
<div class="page cover">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">CROSS-ESTATE DOMAIN RISK REPORT</div></div>
  <div class="cover-main">
    <div class="kick"><span class="d"></span>Cross-Estate Domain Risk Report · {{ snapshot }}</div>
    <div class="org">{{ group }}<span class="dom">{{ r.discovery.declared_count }} declared domains</span></div>
    <p class="synthesis">{{ r.synthesis_html|safe }}</p>
    <div class="dash">
      {% for c in r.dash %}
      <div class="dcard {{ c.cls }}"><div class="dk">{{ c.key }}</div><div class="dstate">{{ c.state }}</div><div class="dnote">{{ c.note }}</div></div>
      {% endfor %}
    </div>
    <div class="lens">
      <div class="lh"><svg class="li" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-4z" stroke="#00C2FF" stroke-width="1.6" stroke-linejoin="round"/></svg>What a cyber insurer would note</div>
      <div class="lbody">{{ r.lens_html|safe }}</div>
      <div class="lscope">{{ r.scope_caveat }}</div>
    </div>
  </div>
  <div class="cover-foot"><div>Datazag · Cyber Risk Intelligence</div><div>Prepared for {{ group }} · Confidential · 1 / 6</div></div>
</div>

<!-- PAGE 2 — DISCOVERY -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ group|lower }} · estate discovery</div></div>
  <div class="body">
    <div class="shead"><div><div class="stitle">The estate you didn't know you had.</div><div class="ssub">Discovery is the headline: how much of the estate carrying your brand extends beyond the list you hold.</div></div>
      <div class="smeta"><div class="sm-k">Estate found</div><div class="sm-v cy">{{ r.discovery.total_found }}</div></div></div>
    <div class="funnel">
      <div class="f-declared"><div class="fn">{{ r.discovery.declared_count }}</div><div class="fl">Domains declared</div></div>
      <div class="f-arrow">→</div>
      <div class="f-found"><div class="fn">{{ r.discovery.total_found }}</div><div class="fl"><b>The estate Datazag {{ 'found' if r.discovery.enabled else 'assessed' }}</b><br>{{ 'declared + discovered across four confidence tiers' if r.discovery.enabled else 'declared estate — discovery not enabled for this run' }}</div></div>
    </div>
    <div class="tiers">
      <div class="tier declared"><div class="tk">Declared · {{ r.discovery.tier_count('declared') }}</div><div class="tn">The domains you told us about</div><div class="td">Your starting list — graded and assessed throughout this report.</div></div>
      <div class="tier strong"><div class="tk">Strongly associated · {{ r.discovery.tier_count('strong') }}</div><div class="tn">High-confidence: you own these</div><div class="td">Shared certificate SANs, same MX + SPF, matching registrar/nameserver patterns, redirects, subsidiary-name matches. Graded with the declared estate.</div></div>
      <div class="tier possible"><div class="tk">Possible · {{ r.discovery.tier_count('possible') }}</div><div class="tn">Medium-confidence: review these</div><div class="td">Lexical similarity, shared infrastructure, partial overlap. Listed but left ungraded (pending confirmation).</div></div>
      <div class="tier defensive"><div class="tk">Defensive / acquisition · {{ r.discovery.tier_count('defensive') }}</div><div class="tn">Consider recovering or monitoring</div><div class="td">For-sale, expired, typo-adjacent, old acquired names, and login/payroll/invoice lookalikes. Never graded.</div></div>
    </div>
    {% if not r.discovery.enabled %}
    <div class="discovery-note"><b>Discovery not enabled for this run.</b> {{ r.discovery.note }}</div>
    {% endif %}
    <table class="disc-table"><tr><th>Domain</th><th>Tier</th><th>Connection evidence</th></tr>
    {% for d in disc_rows %}
      <tr><td class="dom">{{ d.domain }}</td><td><span class="tpill {{ d.tier }}">{{ d.label }}</span></td>
        <td class="ev">{{ d.evidence }}</td></tr>
    {% endfor %}
    </table>
    <div class="discovery-note">{{ r.grade_scope_note }}</div>
  </div>
  <div class="foot"><div>Estate discovery</div><div>Datazag · Confidential · 2 / 6</div></div>
</div>

<!-- PAGE 3 — CONCENTRATION & VARIANCE -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ group|lower }} · systemic risk</div></div>
  <div class="body">
    <div class="shead"><div><div class="stitle">Concentration &amp; posture variance.</div><div class="ssub">Where the estate is single-threaded, and which parts sit below the group standard.</div></div>
      <div class="smeta"><div class="sm-k">Estate grade</div><div class="sm-v {{ 'bad' if r.grade.grade in ['E','F'] else 'warn' if r.grade.grade in ['C','D'] else 'good' }}">{{ r.grade.grade }}</div></div></div>
    <div class="grade-strip">
      <div class="grade-box"><div class="gb-k">Estate grade</div><div class="gb-g">{{ r.grade.grade }}</div><div class="gb-s">{{ '%.1f'|format(r.grade.score) }} / 100 · {{ r.grade.domain_count }} domains</div></div>
      <div class="grade-dist"><div class="gd-k">Grade distribution</div>
        {% for g in grade_rows %}
        <div class="gd-row"><div class="gl">{{ g.letter }}</div><div class="gbar"><div class="gfill {{ g.cls }}" style="width:{{ g.pct }}%"></div></div><div class="gn">{{ g.count }}</div></div>
        {% endfor %}
      </div>
    </div>
    <div class="conc">
    {% for c in r.concentration %}
      <div class="conc-row">
        <div class="ck">{{ c.label }}</div>
        <div class="cprov">{{ c.provider }}<span class="ct">{{ c.resilience_tier }}{% if not c.resilience_assessed %} · not assessed{% elif c.exit_friction == 'high' %} · high exit friction{% endif %}</span></div>
        <div class="cbar"><div class="cfill" style="width:{{ (c.share_post_discovery*100)|round|int }}%"></div></div>
        <div class="cpct">{{ (c.share_post_discovery*100)|round|int }}%{% if c.share_pre_discovery is not none %}<span class="delta">was {{ (c.share_pre_discovery*100)|round|int }}%</span>{% endif %}</div>
        <div class="csev">{% if c.severity %}<span class="ex-sev {{ c.severity }}">{{ c.severity }}</span>{% else %}<span class="none">—</span>{% endif %}</div>
      </div>
    {% endfor %}
    </div>
    <div class="discovery-note">{{ r.vanity_mx_note }}</div>
    <table class="var-table"><tr><th>Segment</th><th>Domains</th><th>Median grade</th><th>vs baseline</th><th></th></tr>
    {% for v in r.variance %}
      <tr><td class="seg">{{ v.segment }}</td><td class="mono">{{ v.domain_count }}</td>
        <td><span class="gradepill {{ gradepill_cls[v.median_grade] if v.median_grade in gradepill_cls else 'gc' }}">{{ v.median_grade }}</span></td>
        <td class="mono">{% if v.bands_below_baseline > 0 %}−{{ v.bands_below_baseline }} bands{% else %}baseline{% endif %}</td>
        <td>{% if v.outlier %}<span class="outlier-tag">Outlier</span>{% endif %}</td></tr>
    {% endfor %}
    </table>
    <div class="monitor-note"><span class="mn-h">Integration-gap monitor</span>Baseline grade is <b>{{ r.baseline_grade }}</b>; outlier segments are the classic acquired-company integration gap — track them as they converge (or drift) over the hold.</div>
  </div>
  <div class="foot"><div>Systemic risk</div><div>Datazag · Confidential · 3 / 6</div></div>
</div>

<!-- PAGE 4 — CORRELATED WEAKNESS & EXPOSURE -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ group|lower }} · systemic risk</div></div>
  <div class="body">
    <div class="shead"><div><div class="stitle">Correlated weakness &amp; active exposure.</div><div class="ssub">What's wrong in the same way across many domains — and what's actively hitting the estate now.</div></div>
      <div class="smeta"><div class="sm-k">Systemic controls</div><div class="sm-v warn">{{ r.correlated|length }}</div></div></div>
    {% for c in r.correlated %}
      <div class="cw"><div class="cw-main"><div class="cw-t">{{ c.label }}</div>
        <div class="cw-seg">{% if c.segment_isolated %}Clustered in <b>{{ c.segments|join(', ') }}</b> — one standard, isolated segments{% else %}Spread across the estate{% endif %}</div></div>
        <div class="cw-bar"><div class="cw-fill {{ 'hot' if c.hot else '' }}" style="width:{{ (c.pct*100)|round|int }}%"></div></div>
        <div class="cw-pct">{{ (c.pct*100)|round|int }}%<span class="of">{{ c.affected }} / {{ c.estate_size }} domains</span></div></div>
    {% endfor %}
    <div class="scale" style="margin-top:16px">
      <div class="sbig"><div class="snum">{{ r.exposure.total_exact }}</div><div class="slab">active impersonations across the estate (30d)</div><div class="sprov">{{ r.exposure.provenance }}</div></div>
      <div class="stext">{% if r.exposure.top_platform %}The concentration is the finding: <b>{{ (r.exposure.top_share*100)|round|int }}% targeting {{ r.exposure.top_platform }}</b>. Exact-match certificates only; lower-confidence candidates are excluded.{% else %}No exact-match impersonation of the estate's platforms in the last 30 days.{% endif %}</div>
    </div>
    {% if r.exposure.rows %}
    <table class="imp-table"><tr><th>Impersonating domain</th><th>Target</th><th>Window</th><th>Pattern</th></tr>
    {% for row in r.exposure.rows %}<tr><td class="dom">{{ row.domain }}</td><td>{{ row.target }}</td><td>{{ row.detail }}</td><td>{{ row.pattern }}</td></tr>{% endfor %}
    </table>
    {% endif %}
    <div class="monitor-note"><span class="mn-h">Report is the map · feed is the tripwire</span>This is the <b>standing</b> exposure snapshot. The Platform &amp; Brand Impersonation Watch delivers the <b>live</b> events — a certificate for your platforms, 5–10 seconds from issuance.</div>
  </div>
  <div class="foot"><div>Systemic risk</div><div>Datazag · Confidential · 4 / 6</div></div>
</div>

<!-- PAGE 5 — CALENDAR & EXCEPTION REGISTER -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ group|lower }} · exceptions</div></div>
  <div class="body">
    <div class="shead"><div><div class="stitle">Calendar &amp; exception register.</div><div class="ssub">What lapses when, and the prioritised list of what to act on — most severe first.</div></div>
      <div class="smeta"><div class="sm-k">Exceptions</div><div class="sm-v bad">{{ r.exceptions|length }}</div></div></div>
    {% if r.calendar %}
    <table class="cal-table"><tr><th>Domain</th><th>Segment</th><th>Item</th><th>Due</th><th>Detail</th></tr>
    {% for it in r.calendar[:8] %}<tr><td class="dom">{{ it.domain }}</td><td>{{ it.segment }}</td><td>{{ it.item_kind }}</td>
      <td><span class="due {{ it.due_class }}">{% if it.overdue %}Overdue{% elif it.due_class == 'soon' %}Soon{% else %}Standing{% endif %}</span></td><td>{{ it.detail }}</td></tr>{% endfor %}
    </table>
    {% endif %}
    {% for e in r.exceptions %}
      <div class="exc"><div class="ex-head"><div class="ex-num">{{ e.rank }}</div><div class="ex-t">{{ e.title }}</div><span class="ex-sev {{ e.severity }}">{{ e.severity }}</span></div>
        <div class="ex-body">{{ e.body_html|safe }}{% if e.collapsed_from %} <i>(collapsed from {{ e.collapsed_from }})</i>{% endif %}<div class="ex-ev">{{ e.evidence_line }}</div></div></div>
    {% endfor %}
    <div class="monitor-note"><span class="mn-h">Remediation worksheet</span>The fix-by-fix worksheet — pattern-grouped, ordered by admin point, ready to hand to your DNS and registrar teams — is in <b>Appendix A</b>.</div>
  </div>
  <div class="foot"><div>Exceptions</div><div>Datazag · Confidential · 5 / 6</div></div>
</div>

<!-- PAGE 6 — CONTINUITY -->
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ group|lower }} · what happens next</div></div>
  <div class="body">
    <div class="shead"><div><div class="stitle">What happens next.</div><div class="ssub">This report is a point-in-time map. Two channels keep it live.</div></div></div>
    <div class="seam"><div class="seam-h"><div class="seam-n">01</div><div class="seam-t"><div class="seam-title">The live impersonation feed</div><div class="seam-sub">The report is the map; the feed is the tripwire.</div></div></div>
      <div class="seam-body"><p class="seam-lead">Every exact-match certificate for your platforms and brands, delivered to your SOC/SIEM within 5–10 seconds of issuance — the standing exposure on page 4, turned into live events.</p>
        <div class="seam-note"><b>Platform &amp; Brand Impersonation Watch</b> — webhook + takedown evidence pack (landing-page screenshot with the brand match highlighted).</div></div></div>
    <div class="seam"><div class="seam-h"><div class="seam-n">02</div><div class="seam-t"><div class="seam-title">Continuous discovery &amp; drift</div><div class="seam-sub">Estate change becomes its own alert stream.</div></div></div>
      <div class="seam-body"><p class="seam-lead">Re-run across the {{ r.corpus_label }}-domain corpus on a cadence: new domains appearing in your estate, segments drifting below baseline, sleeper lookalikes activating — "3 new domains appeared in your estate this week; one is RED."</p>
        <div class="seam-note"><b>Runs over time</b> turn this snapshot into a monitored posture with drift/delta alerts.</div></div></div>
    <div class="upgrade-cta"><div class="uc-text"><div class="uc-h">Move from snapshot to monitored estate.</div><div class="uc-b">Wire the feed and schedule continuous discovery — the estate you can't fully see, watched continuously.</div></div><a href="#" class="uc-btn">Talk to Datazag →</a></div>
    <div class="limits"><div class="lim-h">Scope &amp; limits of this assessment</div><div class="lim-grid">
      <div class="lim-item"><b>Grade scope.</b> Declared + strongly-associated domains. Possible-tier listed ungraded; defensive-tier never graded.</div>
      <div class="lim-item"><b>Externally observable only.</b> Public DNS + certificate transparency at a point in time. No endpoint, network-segmentation, IAM or patch posture.</div>
      <div class="lim-item"><b>Impersonation.</b> Exact-match only; lower-confidence candidates excluded from headline counts.</div>
      <div class="lim-item"><b>Corpus.</b> {{ r.corpus_label }}-domain Datazag corpus + certificate-transparency feed.</div>
    </div></div>
    <div class="gloss-strip"><b>Key terms:</b> <span><b>Concentration</b> — share of the estate on one provider.</span> <span><b>Resilience tier</b> — how survivable that provider's failure is.</span> <span><b>Posture variance</b> — segments below the group baseline.</span> <span><b>Exact match</b> — a certificate impersonating your platform, not a fuzzy typosquat.</span></div>
  </div>
  <div class="foot"><div>Datazag · datazag.com · intelligence@datazag.com</div><div>Cross-Estate Domain Risk Report · 6 / 6</div></div>
</div>

<!-- APPENDIX A — REMEDIATION WORKSHEET -->
{% for ap in appendix_pages %}
<div class="page">
  <div class="runner"><div class="r-brand">DATA<span>ZAG</span></div><div class="r-id">{{ group|lower }} · remediation worksheet</div></div>
  <div class="body">
    {% if ap.adm_strip %}
    <div class="shead"><div><div class="stitle">Remediation worksheet.</div><div class="ssub">Grouped by fix pattern, ordered by admin point — one team's work batches into one change window. Hand to your DNS &amp; registrar teams.</div></div>
      <div class="smeta"><div class="sm-k">Fix patterns</div><div class="sm-v">{{ r.remediation|length }}</div></div></div>
    <div class="adm-strip">
      {% for a in r.admin_points %}<div class="adm"><div class="ak">{{ a.key }}</div><div class="an">{{ a.name }}</div><div class="ad">{{ a.detail }}</div></div>{% endfor %}
    </div>
    {% endif %}
    {% for p in ap.patterns %}
    <div class="fix">
      <div class="fx-head"><div class="fx-num">{{ loop.index + (ap.n-1)*2 }}</div><div class="fx-t">{{ p.title }}</div><span class="fx-pri {{ p.priority }}">{{ pri_label[p.priority] }}</span></div>
      <div class="fx-body">
        <div class="why">{{ p.why_html|safe }}{% if p.end_state %} <b>End state:</b> {{ p.end_state }}.{% endif %}</div>
        {% if p.record_template %}<div class="fx-cmd">{{ p.record_template|safe }}</div>{% endif %}
        <table class="ws-table"><tr><th></th><th>Domain</th><th>Admin point</th><th>Now</th><th>Fix</th></tr>
        {% for e in p.entries %}<tr><td><span class="ws-check"></span></td><td class="dom">{{ e.domain }}</td><td class="adm">{{ e.admin_point }} · {{ e.segment }}</td><td class="now">{{ e.now }}</td><td class="tgt">{{ e.fix|safe }}</td></tr>{% endfor %}
        {% if p.overflow %}<tr><td></td><td colspan="4" style="color:var(--ink-4);font-style:italic">+{{ p.overflow }} more domains in the JSON/MD export</td></tr>{% endif %}
        </table>
      </div>
    </div>
    {% endfor %}
    {% if ap.glossary %}
    <div class="gloss">
      <div class="gterm"><div class="gt">Now / Soon / Maturity</div><div class="gd">Fix urgency: baseline gaps now, advanced controls soon, gold-standard controls at maturity.</div></div>
      <div class="gterm"><div class="gt">Admin point</div><div class="gd">The zone host or registrar where a change is made — the batching and ticketing unit.</div></div>
      <div class="gterm"><div class="gt">rua</div><div class="gd">The DMARC reporting address; confirm senders here before tightening policy.</div></div>
      <div class="gterm"><div class="gt">-all / ~all</div><div class="gd">SPF hard-fail vs soft-fail; hard-fail rejects unlisted senders.</div></div>
    </div>
    <div class="monitor-note"><span class="mn-h">Verification</span>Each fix is externally observable on the next run or feed event — this worksheet is checkable, not just advisory. Sequence: recovery/locks first, then baseline email controls, then hardening.</div>
    {% endif %}
  </div>
  <div class="foot"><div>Remediation worksheet</div><div>Datazag · Confidential · A{{ ap.n }} / A{{ appendix_total }}</div></div>
</div>
{% endfor %}

</body></html>
"""
