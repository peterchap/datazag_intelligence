"""
crossestate/renderer.py
-----------------------
Render an `EstateViewModel` three ways, mirroring `HealthReportRenderer`:

  * to_json()     — the COMPLETE nested payload (group→segment→domain + analytics
                    + exception register + remediation). Always complete, cut-
                    independent — the machine feed for GRC / SIEM / underwriting.
  * to_markdown() — the exception-first, summary-of-summaries document, gated by
                    the cut (sections + per-domain-fix suppression).
  * to_html()     — the same document via a Jinja template constant (jinja2 is
                    imported lazily so JSON/markdown work without it installed).

The cut only parameterises the HUMAN render. The oversight cut suppresses per-
domain fix instructions and replaces the per-domain appendix with a fixable-
weakness ROLLUP (a portfolio finding, not an instruction — the liability-artefact
requirement). It does NOT touch the JSON.
"""

from __future__ import annotations

import json
from typing import Any

from crossestate.contract import EstateViewModel
from crossestate.cuts import CutConfig, get_cut


class CrossEstateRenderer:
    def __init__(self, estate: EstateViewModel, cut: str = "operator", brand: Any = None):
        self.estate = estate
        self.cut: CutConfig = get_cut(cut)
        self.brand = brand

    # ----- JSON (always complete, cut-independent) -----------------------

    def to_json(self) -> str:
        return json.dumps(self.estate.model_dump(mode="json"), indent=2, default=str)

    def to_dict(self) -> dict:
        return self.estate.model_dump(mode="json")

    # ----- Markdown (exception-first, cut-gated) -------------------------

    def to_markdown(self) -> str:
        L: list[str] = []
        self._L = L
        for section in self.cut.sections:
            fn = getattr(self, f"_md_{section}", None)
            if fn:
                fn()
        return "\n".join(L).rstrip() + "\n"

    def _A(self, *lines: str) -> None:
        self._L.extend(lines)

    # -- cover / executive aggregate --
    def _md_cover(self) -> None:
        e = self.estate
        self._A(
            f"# {self.cut.title}",
            "",
            f"## {e.group} — cross-estate aggregate",
            "",
            f"*Snapshot {(e.generated_at or '')[:10]} · {self.cut.description}*",
            "",
            f"- **Estate size:** {e.declared_n} declared domains "
            f"({e.assessed_count} assessed)"
            + ("" if e.completeness.available
               else " · undeclared-domain discovery not enabled in this edition"),
            f"- **Estate grade:** {e.estate_grade} ({e.estate_score}/100, higher = worse)",
            f"- **Grade distribution:** " + self._grade_dist_str(e.grade_distribution),
            f"- **Active impersonations (30d, EXACT):** {e.exposure.total_30d} "
            f"across {len(e.exposure.by_platform)} platform(s)",
        )
        flagged = [d for d in e.concentration if d.flagged]
        if flagged:
            top3 = ", ".join(f"{d.top_provider} ({self._pct(d.top_pct)} of {d.label.lower()})"
                             for d in flagged[:3])
            self._A(f"- **Top concentration risks:** {top3}")
        reds = self._red_domains()
        if reds:
            self._A(f"- **RED domains (E/F):** {len(reds)} — {', '.join(reds[:8])}"
                    + (" …" if len(reds) > 8 else ""))
        self._A("")

    # -- completeness (stub) --
    def _md_completeness(self) -> None:
        c = self.estate.completeness
        self._A("## Estate completeness", "")
        if c.available:
            self._A(f"Declared {c.declared_n}; discovered {c.discovered_n}; "
                    f"{len(c.delta)} undeclared/shadow domain(s).", "")
        else:
            self._A(f"Declared estate: **{c.declared_n} domains**.", "", f"> {c.note}", "")

    # -- concentration --
    def _md_concentration(self) -> None:
        self._A("## Concentration & accumulation", "",
                "*Where the estate is single-threaded — \"if X falls, Y% of the estate is affected.\"*", "")
        self._A("| Dimension | Top provider | Share | Flagged |", "|---|---|---|---|")
        for d in self.estate.concentration:
            self._A(f"| {d.label} | {d.top_provider or '—'} | {self._pct(d.top_pct)} "
                    f"({d.denom} known) | {'**yes**' if d.flagged else 'no'} |")
        self._A("")

    # -- correlated weakness --
    def _md_correlated(self) -> None:
        self._A("## Correlated weakness", "",
                "*What's wrong in the same way across many domains — systemic ≠ isolated.*", "")
        for w in self.estate.correlated_weakness:
            if w.n_affected == 0:
                continue
            tag = " · **systemic**" if w.systemic else (
                f" · clustered in: {', '.join(w.systemic_segments)}" if w.systemic_segments else "")
            self._A(f"- **{w.label}** — {w.n_affected}/{w.n_assessed} domains "
                    f"({self._pct(w.pct)}){tag}")
        self._A("")

    # -- posture variance --
    def _md_variance(self) -> None:
        v = self.estate.variance
        self._A("## Posture variance", "",
                f"*Estate baseline grade **{v.estate_baseline_grade}** "
                f"({v.estate_baseline_score}/100). The variance is the signal.*", "")
        self._A("| Segment | Domains | Median grade | Below baseline | Outlier |",
                "|---|---|---|---|---|")
        for sp in v.per_segment:
            self._A(f"| {sp.segment} | {sp.stats.count} | {sp.stats.grade} | "
                    f"{sp.bands_below_baseline} band(s) | {'**yes**' if sp.is_outlier else 'no'} |")
        if v.unassessed:
            self._A("", f"*{v.unassessed} domain(s) not yet assessed (excluded from the baseline).*")
        self._A("")

    # -- active exposure --
    def _md_exposure(self) -> None:
        e = self.estate.exposure
        self._A("## Active exposure", "",
                "*Standing impersonation snapshot (EXACT matches). The live feed (SKU-2) "
                "delivers these as events; this report is the map.*", "")
        if e.total_30d == 0:
            self._A("No active EXACT impersonation of the estate's platforms in the last 30 days.", "")
        else:
            self._A(f"**{e.total_30d} active impersonations (30d)**, "
                    f"targeting concentration {self._pct(e.targeting_concentration)} on the top platform.", "")
            self._A("| Platform | 7d | 30d | Domains targeted | Samples |", "|---|---|---|---|---|")
            for p in e.by_platform:
                self._A(f"| {p.platform} | {p.count_7d} | {p.count_30d} | {p.targeted_domains} | "
                        f"{', '.join(p.sample_domains[:3]) or '—'} |")
            self._A("")
        if e.lookalike_total_30d:
            self._A(f"*Lookalike candidates (lower confidence, watchlist only — not in the headline): "
                    f"{e.lookalike_total_30d} in 30d.*", "")

    # -- operational calendar --
    def _md_calendar(self) -> None:
        c = self.estate.calendar
        self._A("## Operational calendar", "",
                f"*Overdue {c.overdue} · due ≤30d {c.next_30d} · due ≤90d {c.next_90d}.*", "")
        if not c.items:
            self._A("No lapses within the configured horizons.", "")
            return
        self._A("| Domain | Segment | Item | Due | Detail |", "|---|---|---|---|---|")
        for it in c.items[:40]:
            due = ("overdue" if (it.days_left is not None and it.days_left < 0)
                   else f"{it.days_left}d" if it.days_left is not None else "—")
            self._A(f"| {it.domain} | {it.segment} | {it.kind} | {due} | {it.detail} |")
        self._A("")

    # -- exception register --
    def _md_exceptions(self) -> None:
        self._A("## Exception register", "",
                "*The prioritised, actionable list — most severe first.*", "")
        for x in self.estate.exceptions:
            self._A(f"### [{x.severity.upper()}] {x.title}")
            if x.evidence:
                self._A(f"- **Evidence:** {x.evidence}")
            if x.members:
                self._A(f"- **Affected:** {', '.join(x.members[:12])}"
                        + (" …" if len(x.members) > 12 else ""))
            if x.detail:
                self._A(f"- {x.detail}")
            if self.cut.show_per_domain_fixes and x.remediation:
                self._A(f"- **Remediation:** {x.remediation}")
            self._A("")

    # -- appendix: per-domain drill-down (operator) / fixable rollup (oversight) --
    def _md_appendix(self) -> None:
        if self.cut.show_per_domain_fixes:
            self._md_appendix_operator()
        else:
            self._md_appendix_oversight()

    def _md_appendix_operator(self) -> None:
        self._A("## Per-domain drill-down", "",
                "*Evidence underneath the aggregate — the single reports as backing detail.*", "")
        self._A("| Domain | Segment | Grade | Score | Top findings |", "|---|---|---|---|---|")
        for seg in self.estate.segments:
            for d in seg.domains:
                letter = d.vm.grade.letter if getattr(d.vm, "grade", None) else "?"
                if d.load_error:
                    self._A(f"| {d.domain} | {seg.key} | ? | — | load error: {d.load_error} |")
                    continue
                titles = "; ".join(f.get("title", "") for f in (d.vm.findings or [])[:3]) or "—"
                self._A(f"| {d.domain} | {seg.key} | {letter} | {d.vm.composite_score} | {titles} |")
        self._A("")

    def _md_appendix_oversight(self) -> None:
        self._A("## Fixable-weakness rollup", "",
                "*Control states across the estate — a portfolio finding, not per-domain fix "
                "instructions (those are suppressed in the oversight edition).*", "")
        rollup = self.fixable_weakness_rollup()
        if not rollup:
            self._A("No systemic fixable weaknesses recorded.", "")
            return
        self._A("| Fixable weakness | Estate share | Segments most affected |", "|---|---|---|")
        for r in rollup:
            self._A(f"| {r['label']} | {self._pct(r['pct'])} ({r['n_affected']}/{r['n_assessed']}) | "
                    f"{', '.join(r['segments']) or '—'} |")
        self._A("")

    # ----- helpers -------------------------------------------------------

    def fixable_weakness_rollup(self) -> list[dict]:
        """The oversight remediation view: weakness-class prevalence, no per-domain
        instructions. \"62% of the estate shares this fixable weakness.\""""
        out = []
        for w in self.estate.correlated_weakness:
            if w.n_affected == 0:
                continue
            out.append({
                "control": w.control, "label": w.label,
                "n_affected": w.n_affected, "n_assessed": w.n_assessed, "pct": w.pct,
                "segments": w.systemic_segments,
            })
        out.sort(key=lambda r: -r["pct"])
        return out

    def _red_domains(self) -> list[str]:
        reds = []
        for seg in self.estate.segments:
            for d in seg.domains:
                letter = d.vm.grade.letter if getattr(d.vm, "grade", None) else "?"
                if letter in ("E", "F"):
                    reds.append(d.domain)
        return sorted(reds)

    @staticmethod
    def _pct(x: float) -> str:
        return f"{round((x or 0.0) * 100)}%"

    @staticmethod
    def _grade_dist_str(dist: dict[str, int]) -> str:
        if not dist:
            return "—"
        return " · ".join(f"{g}:{dist[g]}" for g in ("A", "B", "C", "D", "E", "F") if dist.get(g))

    # ----- HTML (lazy jinja) --------------------------------------------

    def to_html(self, brand: Any = None) -> str:
        from jinja2 import BaseLoader, Environment, select_autoescape  # lazy: not needed for JSON/MD
        env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]),
                          trim_blocks=True, lstrip_blocks=True)
        ctx = self._build_context(brand or self.brand)
        return env.from_string(CROSS_ESTATE_TEMPLATE).render(**ctx)

    def _build_context(self, brand: Any) -> dict:
        e = self.estate
        return {
            "cut": self.cut,
            "sections": self.cut.sections,
            "show_fixes": self.cut.show_per_domain_fixes,
            "brand": brand,
            "e": e,
            "group": e.group,
            "snapshot": (e.generated_at or "")[:10],
            "grade_dist": self._grade_dist_str(e.grade_distribution),
            "flagged_conc": [d for d in e.concentration if d.flagged],
            "red_domains": self._red_domains(),
            "rollup": self.fixable_weakness_rollup(),
            "pct": self._pct,
        }


# A compact, print-friendly HTML template reusing the health report's design
# tokens. Sections are gated by the cut's `sections` tuple, in that order.
CROSS_ESTATE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Datazag {{ cut.title }} — {{ group }}</title>
<style>
  :root{--navy:#0F1923;--ink:#0F172A;--ink-2:#334155;--ink-3:#64748B;
        --rule:#E2E8F0;--paper:#FAFAF8;--cyan:#0096CC;--warn:#C2410C;--bad:#B91C1C;--good:#15803D;}
  *{box-sizing:border-box;margin:0;padding:0;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
  body{font-family:'Inter',system-ui,sans-serif;color:var(--ink);background:var(--paper);
       font-size:13px;line-height:1.5;}
  .page{max-width:960px;margin:0 auto;padding:32px 40px;}
  h1{font-size:26px;color:var(--navy);margin-bottom:4px;}
  h2{font-size:19px;color:var(--navy);margin:26px 0 6px;border-bottom:2px solid var(--cyan);padding-bottom:4px;}
  h3{font-size:14px;margin:14px 0 4px;}
  .sub{color:var(--ink-3);font-style:italic;margin-bottom:10px;}
  table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:12px;}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--rule);vertical-align:top;}
  th{color:var(--ink-3);text-transform:uppercase;font-size:10px;letter-spacing:.05em;}
  ul{margin:6px 0 12px 20px;}
  .flag{color:var(--bad);font-weight:600;}
  .sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:10px;font-weight:700;
       text-transform:uppercase;color:#fff;}
  .sev.critical,.sev.high{background:var(--bad);}
  .sev.elevated{background:var(--warn);}
  .sev.medium{background:#B45309;}
  .sev.low,.sev.info{background:var(--ink-3);}
  .kpis{display:flex;flex-wrap:wrap;gap:14px;margin:12px 0;}
  .kpi{border:1px solid var(--rule);border-radius:8px;padding:10px 14px;min-width:120px;}
  .kpi .n{font-size:22px;font-weight:800;color:var(--navy);}
  .kpi .l{font-size:10px;color:var(--ink-3);text-transform:uppercase;}
</style></head><body><div class="page">

{% for section in sections %}
{% if section == 'cover' %}
  <h1>{{ cut.title }}</h1>
  <div class="sub">{{ group }} — cross-estate aggregate · snapshot {{ snapshot }}</div>
  <div class="kpis">
    <div class="kpi"><div class="n">{{ e.declared_n }}</div><div class="l">Declared domains</div></div>
    <div class="kpi"><div class="n">{{ e.estate_grade }}</div><div class="l">Estate grade ({{ e.estate_score }}/100)</div></div>
    <div class="kpi"><div class="n">{{ e.exposure.total_30d }}</div><div class="l">Impersonations 30d</div></div>
    <div class="kpi"><div class="n">{{ red_domains|length }}</div><div class="l">RED domains (E/F)</div></div>
    <div class="kpi"><div class="n">{{ e.calendar.overdue }}</div><div class="l">Overdue lapses</div></div>
  </div>
  <div class="sub">Grade distribution: {{ grade_dist }}</div>
  {% if flagged_conc %}<div class="sub">Top concentration:
    {% for d in flagged_conc[:3] %}{{ d.top_provider }} ({{ pct(d.top_pct) }} of {{ d.label|lower }}){% if not loop.last %} · {% endif %}{% endfor %}</div>{% endif %}
{% elif section == 'completeness' %}
  <h2>Estate completeness</h2>
  {% if e.completeness.available %}
    <p>Declared {{ e.completeness.declared_n }}; discovered {{ e.completeness.discovered_n }};
       {{ e.completeness.delta|length }} undeclared/shadow domain(s).</p>
  {% else %}
    <p>Declared estate: <strong>{{ e.completeness.declared_n }} domains</strong>.</p>
    <p class="sub">{{ e.completeness.note }}</p>
  {% endif %}
{% elif section == 'concentration' %}
  <h2>Concentration &amp; accumulation</h2>
  <div class="sub">Where the estate is single-threaded — "if X falls, Y% of the estate is affected."</div>
  <table><tr><th>Dimension</th><th>Top provider</th><th>Share</th><th>Flagged</th></tr>
  {% for d in e.concentration %}<tr><td>{{ d.label }}</td><td>{{ d.top_provider or '—' }}</td>
    <td>{{ pct(d.top_pct) }} ({{ d.denom }} known)</td>
    <td>{% if d.flagged %}<span class="flag">yes</span>{% else %}no{% endif %}</td></tr>{% endfor %}
  </table>
{% elif section == 'correlated' %}
  <h2>Correlated weakness</h2>
  <div class="sub">What's wrong in the same way across many domains — systemic ≠ isolated.</div>
  <ul>{% for w in e.correlated_weakness %}{% if w.n_affected %}
    <li><strong>{{ w.label }}</strong> — {{ w.n_affected }}/{{ w.n_assessed }} ({{ pct(w.pct) }})
    {% if w.systemic %}<span class="flag">· systemic</span>{% elif w.systemic_segments %}· clustered in: {{ w.systemic_segments|join(', ') }}{% endif %}</li>
  {% endif %}{% endfor %}</ul>
{% elif section == 'variance' %}
  <h2>Posture variance</h2>
  <div class="sub">Estate baseline grade <strong>{{ e.variance.estate_baseline_grade }}</strong>
    ({{ e.variance.estate_baseline_score }}/100). The variance is the signal.</div>
  <table><tr><th>Segment</th><th>Domains</th><th>Median grade</th><th>Below baseline</th><th>Outlier</th></tr>
  {% for sp in e.variance.per_segment %}<tr><td>{{ sp.segment }}</td><td>{{ sp.stats.count }}</td>
    <td>{{ sp.stats.grade }}</td><td>{{ sp.bands_below_baseline }}</td>
    <td>{% if sp.is_outlier %}<span class="flag">yes</span>{% else %}no{% endif %}</td></tr>{% endfor %}
  </table>
{% elif section == 'exposure' %}
  <h2>Active exposure</h2>
  <div class="sub">Standing impersonation snapshot (EXACT). The live feed delivers events; this is the map.</div>
  {% if e.exposure.total_30d %}
    <p><strong>{{ e.exposure.total_30d }} active impersonations (30d)</strong>,
       targeting concentration {{ pct(e.exposure.targeting_concentration) }} on the top platform.</p>
    <table><tr><th>Platform</th><th>7d</th><th>30d</th><th>Domains</th><th>Samples</th></tr>
    {% for p in e.exposure.by_platform %}<tr><td>{{ p.platform }}</td><td>{{ p.count_7d }}</td>
      <td>{{ p.count_30d }}</td><td>{{ p.targeted_domains }}</td>
      <td>{{ p.sample_domains[:3]|join(', ') or '—' }}</td></tr>{% endfor %}
    </table>
  {% else %}<p>No active EXACT impersonation in the last 30 days.</p>{% endif %}
{% elif section == 'calendar' %}
  <h2>Operational calendar</h2>
  <div class="sub">Overdue {{ e.calendar.overdue }} · due ≤30d {{ e.calendar.next_30d }} · due ≤90d {{ e.calendar.next_90d }}.</div>
  {% if e.calendar.items %}
  <table><tr><th>Domain</th><th>Segment</th><th>Item</th><th>Due</th><th>Detail</th></tr>
  {% for it in e.calendar.items[:40] %}<tr><td>{{ it.domain }}</td><td>{{ it.segment }}</td>
    <td>{{ it.kind }}</td><td>{% if it.days_left is not none and it.days_left < 0 %}<span class="flag">overdue</span>{% elif it.days_left is not none %}{{ it.days_left }}d{% else %}—{% endif %}</td>
    <td>{{ it.detail }}</td></tr>{% endfor %}</table>
  {% else %}<p>No lapses within the configured horizons.</p>{% endif %}
{% elif section == 'exceptions' %}
  <h2>Exception register</h2>
  <div class="sub">The prioritised, actionable list — most severe first.</div>
  {% for x in e.exceptions %}
    <h3><span class="sev {{ x.severity }}">{{ x.severity }}</span> {{ x.title }}</h3>
    <ul>
      {% if x.evidence %}<li><strong>Evidence:</strong> {{ x.evidence }}</li>{% endif %}
      {% if x.members %}<li><strong>Affected:</strong> {{ x.members[:12]|join(', ') }}</li>{% endif %}
      {% if x.detail %}<li>{{ x.detail }}</li>{% endif %}
      {% if show_fixes and x.remediation %}<li><strong>Remediation:</strong> {{ x.remediation }}</li>{% endif %}
    </ul>
  {% endfor %}
{% elif section == 'appendix' %}
  {% if show_fixes %}
    <h2>Per-domain drill-down</h2>
    <div class="sub">Evidence underneath the aggregate — the single reports as backing detail.</div>
    <table><tr><th>Domain</th><th>Segment</th><th>Grade</th><th>Score</th><th>Top findings</th></tr>
    {% for seg in e.segments %}{% for d in seg.domains %}<tr>
      <td>{{ d.domain }}</td><td>{{ seg.key }}</td>
      <td>{{ d.vm.grade.letter if d.vm.grade else '?' }}</td><td>{{ d.vm.composite_score }}</td>
      <td>{% if d.load_error %}load error{% else %}{{ d.vm.findings[:3]|map(attribute='title')|join('; ') or '—' }}{% endif %}</td>
    </tr>{% endfor %}{% endfor %}</table>
  {% else %}
    <h2>Fixable-weakness rollup</h2>
    <div class="sub">Control states across the estate — a portfolio finding, not per-domain fix instructions.</div>
    <table><tr><th>Fixable weakness</th><th>Estate share</th><th>Segments most affected</th></tr>
    {% for r in rollup %}<tr><td>{{ r.label }}</td>
      <td>{{ pct(r.pct) }} ({{ r.n_affected }}/{{ r.n_assessed }})</td>
      <td>{{ r.segments|join(', ') or '—' }}</td></tr>{% endfor %}</table>
  {% endif %}
{% endif %}
{% endfor %}

</div></body></html>
"""
