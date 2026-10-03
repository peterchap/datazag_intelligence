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
from estatereport.contract import CorpusInfo, EstateReport, share_text
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
                                      now: Optional[datetime] = None,
                                      tls_probe=None, observatory=None) -> EstateReport:
    mvp = build_estate_from_manifest(manifest_path, thresholds=thresholds, now=now,
                                     tls_probe=tls_probe)
    return build_estate_report(mvp, discovery=discovery, now=now, observatory=observatory)


def build_estate_report(mvp, discovery: Optional[DiscoveryProvider] = None,
                        now: Optional[datetime] = None, observatory=None) -> EstateReport:
    """`observatory`: an observatory.Observatory (tests inject a fixture or
    Observatory.unavailable()); default is the live, process-cached load."""
    now = now or datetime.now(timezone.utc)
    import observatory as _obs
    corpus = _obs.corpus_size(observatory if observatory is not None else _obs.load_cached())
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
        corpus=(CorpusInfo(domains=corpus.domains, label=corpus.label, as_of=corpus.as_of)
                if corpus else None),
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
                f"<b>{disc.estate_count} across the estate</b>.")
    else:
        lead = (f"Across <b>{disc.declared_count} declared domains</b> (undeclared-domain discovery "
                "not enabled for this run),")
    tail = f" The estate grades <b>{grade.grade}</b> ({grade.score:.0f}/100)."
    flagged = [c for c in mvp.concentration if c.flagged]
    if flagged:
        f0 = flagged[0]
        n0 = f0.shares[0].count if f0.shares else 0
        tail += (f" It is single-threaded on <b>{f0.top_provider}</b> for "
                 f"{f0.label.lower()} ({share_text(n0, f0.denom)}).")
    if exp.total_exact:
        tail += (f" {exp.total_exact:,} new lookalike domains impersonating the estate's platforms (30d, internet-wide): they target every organization on those "
                 "platforms, not this estate specifically.")
    return lead + tail


def _dash(mvp, disc, grade, exp) -> list[dict]:
    from estatereport.transform import grade_cls
    # Distinct hosts, not rows (crossestate counts them that way).
    overdue = mvp.calendar.overdue
    soon = mvp.calendar.next_30d
    return [
        {"cls": "cy", "key": "Estate discovered",
         "state": str(disc.estate_count),
         "note": (f"{disc.declared_count} declared" if not disc.enabled
                  else f"{disc.declared_count} declared → {disc.estate_count} found")},
        {"cls": grade_cls(grade.grade), "key": "Estate grade", "state": grade.grade,
         "note": f"{grade.score:.0f}/100 across {grade.domain_count} graded domains"},
        {"cls": "warn" if exp.total_exact else "ok", "key": "Active exposure",
         "state": f"{exp.total_exact:,}", "note": "platform lookalikes (30d, internet-wide)"},
        {"cls": "bad" if overdue else ("warn" if soon else "ok"), "key": "Live lapses",
         "state": str(overdue + soon), "note": f"{overdue} overdue · {soon} due ≤30d"},
    ]


def _lens(mvp, conc, var, exp) -> str:
    parts = []
    flagged = [c for c in conc if c.severity]
    if flagged:
        c = flagged[0]
        parts.append(f"accumulation risk on <b>{c.provider}</b> ({c.share_label} of "
                     f"{c.label.lower()}, {c.resilience_tier})")
    outliers = [v for v in var if v.outlier]
    if outliers:
        parts.append(f"a below-baseline segment (<b>{outliers[0].segment}</b>)")
    if exp.total_exact:
        parts.append(f"<b>{exp.total_exact:,}</b> internet-wide lookalikes of the estate's platforms")
    body = "On the externally observable evidence, an underwriter would weigh " + (
        "; ".join(parts) if parts else "a broadly consistent estate") + "."
    return body
