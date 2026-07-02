"""
estatereport/transform.py
-------------------------
Transform the committed `crossestate` MVP estate (EstateViewModel) into the v2.2
report pieces for pages 1–5. Pure functions; the MVP analytics are reused
verbatim and only ENRICHED here (resilience join, severity, deltas, masking,
collapse inputs). No re-computation of the underlying distributions.
"""

from __future__ import annotations

from estatereport import resilience
from estatereport.contract import (
    CalItem,
    Concentration,
    CorrelatedWeakness,
    EstateGrade,
    Exposure,
    ImpRow,
    SegmentVariance,
)

_GRADE_CLS = {"A": "good", "B": "good", "C": "warn", "D": "warn", "E": "bad", "F": "bad"}
_HOT_CONTROLS = {"dmarc", "internal_ip_leak", "dangling_subdomain"}

VANITY_MX_NOTE = ("Mailbox shares are resolved through vanity MX records to the operating "
                  "provider — a domain fronting Google Workspace behind its own MX counts as "
                  "Google Workspace concentration.")


# ── §4a concentration (one row per dimension: its top provider) ───────────────

def concentration(mvp) -> list[Concentration]:
    out: list[Concentration] = []
    for dim in mvp.concentration:
        if not dim.top_provider or dim.denom == 0:
            continue
        res = resilience.lookup(dim.top_provider, dim.dimension)
        share = dim.top_pct
        sev, reco = resilience.severity(share, res)
        masking = False
        if dim.dimension == "mailbox":
            masking = _mx_masking(mvp, dim.top_provider, share)
            if masking and sev:
                sev = _bump(sev)      # hidden concentration is worse than visible
                reco = "apparent diversity, actual concentration — " + (reco or "reduce")
        out.append(Concentration(
            dimension=dim.dimension, label=dim.label, provider=dim.top_provider,
            share_post_discovery=share, share_pre_discovery=None,   # discovery disabled → no delta
            known_count=dim.denom,
            resilience_tier=res.tier, exit_friction=res.exit_friction,
            resilience_assessed=res.assessed,
            severity=sev, recommendation=reco,
            surface_diversity_masking=masking, bar_class="",        # bar neutral; colour on the pill
        ))
    return out


def _bump(sev: str) -> str:
    order = ["watch", "elevated", "high"]
    return order[min(2, order.index(sev) + 1)]


def _mx_masking(mvp, provider: str, share: float) -> bool:
    """surface_diversity_masking: ≥3 distinct MX hostnames across the estate
    resolving to one operating provider whose true share ≥ 50%."""
    if share < 0.50:
        return False
    hosts: set[str] = set()
    for seg in mvp.segments:
        for d in seg.domains:
            vm = d.vm
            if (vm.annotation.mailbox_provider or "") != provider:
                continue
            for mx in (vm.dns_records.mx or []):
                parts = str(mx).split()
                if parts:
                    hosts.add(parts[-1].lower())
    return len(hosts) >= 3


# ── §4 variance ──────────────────────────────────────────────────────────────

def variance(mvp) -> tuple[list[SegmentVariance], str]:
    rows = [
        SegmentVariance(segment=sp.segment, domain_count=sp.stats.count,
                        median_grade=sp.stats.grade, bands_below_baseline=sp.bands_below_baseline,
                        outlier=sp.is_outlier)
        for sp in mvp.variance.per_segment
    ]
    return rows, mvp.variance.estate_baseline_grade


# ── §4 correlated weakness ───────────────────────────────────────────────────

def correlated(mvp) -> list[CorrelatedWeakness]:
    out: list[CorrelatedWeakness] = []
    for w in mvp.correlated_weakness:
        if w.n_affected == 0:
            continue
        segs = w.systemic_segments or sorted(w.per_segment.keys())
        # isolated == every affected domain sits inside the systemic segments
        in_syst = sum(w.per_segment.get(s, 0) for s in w.systemic_segments)
        isolated = bool(w.systemic_segments) and in_syst == w.n_affected and len(w.systemic_segments) < len(w.per_segment_total)
        out.append(CorrelatedWeakness(
            control=w.control, label=w.label, affected=w.n_affected,
            estate_size=w.n_assessed, pct=w.pct, segments=segs,
            segment_isolated=isolated, hot=w.control in _HOT_CONTROLS,
        ))
    out.sort(key=lambda c: -c.pct)
    return out


# ── §4 calendar ──────────────────────────────────────────────────────────────

def calendar(mvp) -> list[CalItem]:
    out: list[CalItem] = []
    for it in mvp.calendar.items:
        if it.days_left is not None and it.days_left < 0:
            cls = "overdue"
        elif it.days_left is not None and it.days_left <= 30:
            cls = "soon"
        else:
            cls = "later"
        out.append(CalItem(
            domain=it.domain, segment=it.segment, item_kind=it.kind,
            due=it.date, overdue=(it.days_left is not None and it.days_left < 0),
            detail=it.detail, due_class=cls,
        ))
    return out


# ── §2.5 exposure (EXACT only) ───────────────────────────────────────────────

def exposure(mvp) -> Exposure:
    e = mvp.exposure
    rows: list[ImpRow] = []
    for p in e.by_platform:
        for s in p.sample_domains[:4]:
            rows.append(ImpRow(domain=s, target=p.platform,
                               detail=f"{p.count_30d} in 30d", pattern="Exact platform match"))
    top = e.by_platform[0] if e.by_platform else None
    return Exposure(
        total_exact=e.total_30d, top_platform=(top.platform if top else None),
        top_share=e.targeting_concentration, rows=rows[:12],
        lookalike_total=e.lookalike_total_30d,
    )


# ── estate grade ─────────────────────────────────────────────────────────────

def estate_grade(mvp) -> EstateGrade:
    return EstateGrade(grade=mvp.estate_grade, score=float(mvp.estate_score),
                       domain_count=mvp.assessed_count, distribution=mvp.grade_distribution)


def grade_cls(letter: str) -> str:
    return _GRADE_CLS.get(letter, "warn")
