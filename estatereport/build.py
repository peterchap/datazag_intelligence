"""
estatereport/build.py
---------------------
Assemble the v2.2 EstateReport. The heavy lifting (loading, segmentation, the
five deterministic analytics) is delegated to the committed `crossestate` MVP
engine; this module ENRICHES that result with the v2.2 layers (resilience
severity, discovery tiers, exception collapse, remediation worksheet) and composes
the page-1 cover. Nothing in crossestate/ is mutated.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Optional

from crossestate.build import build_estate_from_manifest, build_estate_view_model
from crossestate.contract import EstateThresholds
from estatereport import transform
from estatereport.contract import EstateReport
from estatereport.discovery import DiscoveryProvider, default_discovery, to_estate_discovery
from estatereport.exceptions2 import build_exceptions
from estatereport.remediation import build_remediation
from freereport.compose import SCOPE_CAVEAT

_GRADE_SCOPE_NOTE = (
    "Grades cover the declared and strongly-associated estate. Possible-tier domains are listed "
    "but left ungraded (pending confirmation); defensive / acquisition domains are never graded.")


def build_estate_report_from_manifest(manifest_path: str,
                                      thresholds: Optional[EstateThresholds] = None,
                                      discovery: Optional[DiscoveryProvider] = None,
                                      now: Optional[datetime] = None) -> EstateReport:
    mvp = build_estate_from_manifest(manifest_path, thresholds=thresholds, now=now)
    return build_estate_report(mvp, discovery=discovery, now=now)


def build_estate_report(mvp, discovery: Optional[DiscoveryProvider] = None,
                        now: Optional[datetime] = None) -> EstateReport:
    now = now or datetime.now(timezone.utc)
    discovery = discovery or default_discovery()

    refs = [d for seg in mvp.segments for d in seg.domains]
    declared = [r.domain for r in refs]
    disc = to_estate_discovery(discovery.discover(mvp.group, refs), declared)

    conc = transform.concentration(mvp)
    var, baseline = transform.variance(mvp)
    corr = transform.correlated(mvp)
    cal = transform.calendar(mvp)
    exp = transform.exposure(mvp)
    grade = transform.estate_grade(mvp)

    report = EstateReport(
        group=mvp.group, generated_at=now.isoformat(),
        synthesis_html=_synthesis(mvp, disc, grade, exp),
        dash=_dash(mvp, disc, grade, exp),
        lens_html=_lens(mvp, conc, var, exp),
        scope_caveat=SCOPE_CAVEAT,
        discovery=disc, grade_scope_note=_GRADE_SCOPE_NOTE,
        grade=grade, concentration=conc, variance=var, baseline_grade=baseline,
        vanity_mx_note=transform.VANITY_MX_NOTE,
        correlated=corr, exposure=exp,
        calendar=cal,
    )
    report.exceptions = build_exceptions(report)
    patterns, admin_points = build_remediation(mvp, cal)
    report.remediation = patterns
    report.admin_points = admin_points
    # Appendix pagination: 2 pattern cards per page; the glossary closer shares
    # the final card page (matching the reference render's A4).
    report.appendix_pages = max(1, math.ceil(len(patterns) / 2)) if patterns else 0
    return report


# ── page-1 cover composition ─────────────────────────────────────────────────

def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def _synthesis(mvp, disc, grade, exp) -> str:
    if disc.enabled:
        lead = (f"Starting from <b>{disc.declared_count} declared domains</b>, Datazag found "
                f"<b>{disc.total_found} across the estate</b>.")
    else:
        lead = (f"Across <b>{disc.declared_count} declared domains</b> (undeclared-domain discovery "
                "not enabled for this run),")
    tail = f" the estate grades <b>{grade.grade}</b> ({grade.score:.0f}/100)."
    flagged = [c for c in mvp.concentration if c.flagged]
    if flagged:
        tail += (f" It is single-threaded on <b>{flagged[0].top_provider}</b> for "
                 f"{flagged[0].label.lower()} ({_pct(flagged[0].top_pct)}).")
    if exp.total_exact:
        tail += f" {exp.total_exact} active impersonations are hitting the estate."
    return lead + tail


def _dash(mvp, disc, grade, exp) -> list[dict]:
    from estatereport.transform import grade_cls
    overdue = sum(1 for it in mvp.calendar.items if it.days_left is not None and it.days_left < 0)
    soon = mvp.calendar.next_30d
    return [
        {"cls": "cy", "key": "Estate discovered",
         "state": str(disc.total_found),
         "note": (f"{disc.declared_count} declared" if not disc.enabled
                  else f"{disc.declared_count} declared → {disc.total_found} found")},
        {"cls": grade_cls(grade.grade), "key": "Estate grade", "state": grade.grade,
         "note": f"{grade.score:.0f}/100 across {grade.domain_count} graded domains"},
        {"cls": "warn" if exp.total_exact else "ok", "key": "Active exposure",
         "state": str(exp.total_exact), "note": "exact impersonations (30d)"},
        {"cls": "bad" if overdue else ("warn" if soon else "ok"), "key": "Live lapses",
         "state": str(overdue + soon), "note": f"{overdue} overdue · {soon} due ≤30d"},
    ]


def _lens(mvp, conc, var, exp) -> str:
    parts = []
    flagged = [c for c in conc if c.severity]
    if flagged:
        c = flagged[0]
        parts.append(f"accumulation risk on <b>{c.provider}</b> ({_pct(c.share_post_discovery)} of "
                     f"{c.label.lower()}, {c.resilience_tier})")
    outliers = [v for v in var if v.outlier]
    if outliers:
        parts.append(f"a below-baseline segment (<b>{outliers[0].segment}</b>)")
    if exp.total_exact:
        parts.append(f"<b>{exp.total_exact}</b> active impersonations")
    body = "On the externally observable evidence, an underwriter would weigh " + (
        "; ".join(parts) if parts else "a broadly consistent estate") + "."
    return body
