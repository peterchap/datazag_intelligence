"""
crossestate/exceptions.py
-------------------------
The cross-estate exception register — the prioritised, actionable "do this"
list. Deterministic and rule-based (mirrors `findings_rules.derive_findings`):
each rule fires off the already-computed analytics blocks, so the register is a
function of the estate, never LLM-invented.

Emits `EstateException` items (finding-dict-shaped: finding / severity / title /
evidence / detail / remediation / category, plus `scope` and `members`). The
`remediation` field is populated for everyone; the OVERSIGHT human render drops
it at render time (JSON keeps it).
"""

from __future__ import annotations

from crossestate.contract import EstateException, EstateViewModel

_SEV_ORDER = {"critical": 0, "high": 1, "elevated": 2, "medium": 3, "low": 4, "info": 5}
_RED_GRADES = {"E", "F"}


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def derive_estate_exceptions(estate: EstateViewModel) -> list[EstateException]:
    out: list[EstateException] = []
    th = estate.thresholds

    # ── Concentration / single-point-of-failure (§2.2) ───────────────────
    for dim in estate.concentration:
        if dim.flagged and dim.top_provider:
            sev = "high" if dim.top_pct >= 0.60 else "elevated"
            out.append(EstateException(
                finding="estate_concentration",
                severity=sev,
                title=f"Single point of failure: {dim.top_provider} handles "
                      f"{_pct(dim.top_pct)} of the estate's {dim.label.lower()}",
                evidence=f"{dim.top_provider}: {_pct(dim.top_pct)} of {dim.denom} "
                         f"domains with a known {dim.label.lower()}.",
                detail=f"If {dim.top_provider} suffers an outage or compromise, "
                       f"{_pct(dim.top_pct)} of the estate is affected at once.",
                remediation=f"Assess resilience/failover for {dim.top_provider}; "
                            f"consider diversifying the estate's {dim.label.lower()}.",
                category="concentration",
                scope="estate",
                members=[dim.top_provider],
            ))

    # ── Correlated / systemic weakness (§2.3) ────────────────────────────
    for w in estate.correlated_weakness:
        if w.n_affected == 0:
            continue
        if w.systemic:
            sev = "high" if w.control in ("internal_ip_leak", "dangling_subdomain", "dmarc") else "elevated"
            out.append(EstateException(
                finding=f"systemic_{w.control}",
                severity=sev,
                title=f"Systemic weakness: {w.label} on {w.n_affected}/{w.n_assessed} "
                      f"domains ({_pct(w.pct)})",
                evidence=f"{w.n_affected} of {w.n_assessed} assessed domains: {w.label.lower()}.",
                detail="This is a systemic misconfiguration across the estate, not an "
                       "isolated domain — fix it as a standard, not case by case.",
                remediation=w.remediation,
                category="correlated_weakness",
                scope="estate",
                members=w.systemic_segments or [],
            ))
        elif w.systemic_segments:
            # Not estate-systemic, but clustered in specific segments.
            out.append(EstateException(
                finding=f"clustered_{w.control}",
                severity="elevated",
                title=f"{w.label} clustered in segment(s): {', '.join(w.systemic_segments)}",
                evidence=f"{w.label} affects the whole of: {', '.join(w.systemic_segments)}.",
                detail="Isolated to specific segments rather than estate-wide — likely a "
                       "segment-level standard gap (e.g. an acquired unit).",
                remediation=w.remediation,
                category="correlated_weakness",
                scope="segment",
                members=w.systemic_segments,
            ))

    # ── Posture variance / M&A gap (§2.4) ────────────────────────────────
    for sp in estate.variance.per_segment:
        if sp.is_outlier:
            out.append(EstateException(
                finding="posture_outlier_segment",
                severity="elevated",
                title=f"Segment '{sp.segment}' is {sp.bands_below_baseline} grade band(s) "
                      f"below the estate baseline ({estate.variance.estate_baseline_grade})",
                evidence=f"Segment median grade {sp.stats.grade} vs estate baseline "
                         f"{estate.variance.estate_baseline_grade}.",
                detail="A segment materially below the parent standard — the classic "
                       "acquired-company integration gap.",
                remediation=f"Bring '{sp.segment}' up to the estate baseline; treat as an "
                            "integration/remediation programme, not per-domain tickets.",
                category="posture_variance",
                scope="segment",
                members=[sp.segment],
            ))

    # ── Active exposure (§2.5) ───────────────────────────────────────────
    exp = estate.exposure
    if exp.total_30d > 0:
        top = exp.by_platform[0] if exp.by_platform else None
        out.append(EstateException(
            finding="active_impersonation",
            severity="high",
            title=f"{exp.total_30d} active impersonations across the estate (30d), "
                  f"{len(exp.by_platform)} platform(s) targeted",
            evidence=(f"Top target: {top.platform} ({top.count_30d} in 30d)." if top else ""),
            detail="Standing exposure snapshot (EXACT matches). The live feed (SKU-2) "
                   "delivers these as events; this report is the map.",
            remediation="Prioritise takedowns for the most-targeted platforms/brands; "
                        "wire the live impersonation feed for continuous alerting.",
            category="active_exposure",
            scope="estate",
            members=[p.platform for p in exp.by_platform[:5]],
        ))

    # ── Operational calendar (§2.6) ──────────────────────────────────────
    cal = estate.calendar
    if cal.overdue > 0:
        overdue_domains = sorted({it.domain for it in cal.items if it.days_left is not None and it.days_left < 0})
        out.append(EstateException(
            finding="overdue_lapses",
            severity="high",
            title=f"{cal.overdue} overdue lapse(s) across the estate (expired domains/certs)",
            evidence=f"Overdue items on: {', '.join(overdue_domains[:10])}.",
            detail="Expired registrations/certificates are live outages or takeover windows.",
            remediation="Renew/reissue immediately for the overdue items.",
            category="operational_calendar",
            scope="estate",
            members=overdue_domains,
        ))
    if cal.next_30d > 0:
        out.append(EstateException(
            finding="imminent_lapses",
            severity="elevated",
            title=f"{cal.next_30d} lapse(s) due within 30 days",
            evidence=f"{cal.next_30d} domain/cert expiries within 30 days.",
            detail="Near-term renewals across the estate.",
            remediation="Schedule renewals; enable auto-renew where possible.",
            category="operational_calendar",
            scope="estate",
        )) if cal.overdue == 0 else None
    out = [e for e in out if e is not None]

    # ── RED domains rollup ───────────────────────────────────────────────
    red = []
    for seg in estate.segments:
        for d in seg.domains:
            letter = d.vm.grade.letter if getattr(d.vm, "grade", None) else "?"
            if letter in _RED_GRADES:
                red.append(d.domain)
    if red:
        out.append(EstateException(
            finding="red_domains",
            severity="high",
            title=f"{len(red)} RED domain(s) (grade E/F) in the estate",
            evidence=f"{', '.join(sorted(red)[:10])}" + (" …" if len(red) > 10 else ""),
            detail="Domains at the worst grade bands — the head of the exception queue.",
            remediation="Triage the RED domains first; see the per-domain drill-down.",
            category="posture_variance",
            scope="domain",
            members=sorted(red),
        ))

    # ── Segment reconciliation (data quality, low severity) ──────────────
    disagreements = sorted({
        d.domain for seg in estate.segments for d in seg.domains if d.segment_disagreement
    })
    if disagreements:
        out.append(EstateException(
            finding="segment_tag_disagreement",
            severity="low",
            title=f"{len(disagreements)} domain(s) whose segment tag disagrees with inference",
            evidence=f"{', '.join(disagreements[:10])}.",
            detail="Supplied segment tag differs from the inferred grouping (same "
                   "registrable domain spanning segments). Tag was kept, not overridden.",
            remediation="Confirm the intended segment for these domains in the manifest.",
            category="data_quality",
            scope="domain",
            members=disagreements,
        ))

    out.sort(key=lambda e: (_SEV_ORDER.get(e.severity, 9), e.finding))
    return out
