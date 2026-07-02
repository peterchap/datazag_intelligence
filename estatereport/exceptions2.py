"""
estatereport/exceptions2.py
---------------------------
The collapsed exception register (spec §3.3). Correlated weaknesses sharing a fix
collapse into ONE entry that references the page-4 rollup; concentration findings
collapse into ONE entry listing the top providers. Target 5–7 entries — never one
exception per weakness per segment (the v1 failure mode: 16 entries, severity
dilution). Severity vocabulary: HIGH / ELEVATED / WATCH.
"""

from __future__ import annotations

from estatereport.contract import EstateReport, Exception_

_SEV_RANK = {"high": 0, "elevated": 1, "watch": 2}


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def build_exceptions(report: EstateReport) -> list[Exception_]:
    ex: list[Exception_] = []

    # 1) Recovery first — expired / unlocked domains (takeover windows precede hygiene).
    overdue = [c for c in report.calendar if c.overdue]
    unlocked = [c for c in report.calendar if c.item_kind == "unlocked"]
    if overdue or unlocked:
        doms = sorted({c.domain for c in overdue} | {c.domain for c in unlocked})
        ex.append(Exception_(
            rank=0, severity="high",
            title=f"{len(doms)} domain(s) expired or unlocked — recover before anything else",
            body_html="Expired registrations and absent registrar locks are live takeover windows. "
                      "Renew and re-lock these before DNS hygiene work.",
            evidence_line=f"calendar.overdue × {len(overdue)} · registrar_lock = none × {len(unlocked)}",
            collapsed_from=(f"calendar × {len(overdue) + len(unlocked)}" if (len(overdue) + len(unlocked)) > 1 else None),
        ))

    # 2) surface_diversity_masking — lead when present (hidden concentration).
    masked = [c for c in report.concentration if c.surface_diversity_masking]
    for c in masked:
        ex.append(Exception_(
            rank=0, severity=c.severity or "elevated",
            title=f"Apparent diversity, actual concentration: {c.provider} is {_pct(c.share_post_discovery)} "
                  f"of the estate's {c.label.lower()} underneath",
            body_html=f"The estate appears diversified at MX level but is {_pct(c.share_post_discovery)} "
                      f"{c.provider} underneath — only visible with vanity-MX resolution.",
            evidence_line=f"{c.dimension}={c.provider} {_pct(c.share_post_discovery)} · surface_diversity_masking = true",
        ))

    # 3) Concentration — collapse the rest into ONE entry listing top providers.
    conc = [c for c in report.concentration if c.severity and not c.surface_diversity_masking]
    if conc:
        conc.sort(key=lambda c: _SEV_RANK[c.severity])
        worst = conc[0].severity
        listed = ", ".join(f"{c.provider} {_pct(c.share_post_discovery)} ({c.label.lower()})" for c in conc[:4])
        ev = " · ".join(f"{c.dimension}={c.provider} {_pct(c.share_post_discovery)} "
                        f"[{c.resilience_tier}{'/high-exit' if c.exit_friction == 'high' else ''}]"
                        for c in conc[:4])
        ex.append(Exception_(
            rank=0, severity=worst,
            title=f"Provider concentration across the estate — {len(conc)} single points of failure",
            body_html=f"Top concentrations: {listed}. Severity reflects provider resilience, not share alone.",
            evidence_line=ev,
            collapsed_from=(f"concentration × {len(conc)}" if len(conc) > 1 else None),
        ))

    # 4) Correlated weakness — collapse into ONE entry pointing at the page-4 rollup.
    cw = report.correlated
    if cw:
        worst = "high" if any(c.hot and c.pct >= 0.5 for c in cw) else "elevated"
        top = ", ".join(f"{c.label} ({_pct(c.pct)})" for c in cw[:3])
        ex.append(Exception_(
            rank=0, severity=worst,
            title="Systemic misconfiguration repeats across the estate — fix as a standard",
            body_html=f"Most prevalent: {top}. These share fixes — see the correlated-weakness rollup "
                      "and the remediation worksheet (Appendix A), not per-domain tickets.",
            evidence_line=f"correlated_weakness × {len(cw)} · see page 4 rollup",
            collapsed_from=f"correlated_weakness × {len(cw)}",
        ))

    # 5) Posture variance — outlier segments.
    outliers = [v for v in report.variance if v.outlier]
    if outliers:
        names = ", ".join(v.segment for v in outliers)
        ex.append(Exception_(
            rank=0, severity="elevated",
            title=f"Segment(s) below the estate baseline: {names}",
            body_html=f"Baseline grade {report.baseline_grade}; {names} sit materially below it — the "
                      "classic acquired-company integration gap.",
            evidence_line=" · ".join(f"{v.segment}: median {v.median_grade}, −{v.bands_below_baseline} bands"
                                     for v in outliers),
        ))

    # 6) Active exposure.
    if report.exposure.total_exact > 0:
        ex.append(Exception_(
            rank=0, severity="high",
            title=f"{report.exposure.total_exact} active impersonations across the estate (30d)",
            body_html=f"Concentrated on {report.exposure.top_platform} "
                      f"({_pct(report.exposure.top_share)} of targeting). The live feed delivers these as "
                      "events; this report is the map.",
            evidence_line=report.exposure.provenance,
        ))

    # Rank by severity, cap at 7 (§3.3 target 5–7).
    ex.sort(key=lambda e: _SEV_RANK[e.severity])
    ex = ex[:7]
    for i, e in enumerate(ex, 1):
        e.rank = i
    return ex
