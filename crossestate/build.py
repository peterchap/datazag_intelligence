"""
crossestate/build.py
--------------------
The cross-estate engine entry point. Turns a manifest into a complete
`EstateViewModel`:

    manifest → load contracts → resolve segments → 5 analytics
             → completeness stub → exception register → EstateViewModel

Pure with respect to rendering (no HTML/PDF here); `estate_run.py` renders and
writes files. `build_estate_view_model` is the unit-test seam.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from crossestate.analytics import (
    compute_calendar,
    compute_concentration,
    compute_correlated,
    compute_exposure,
    compute_variance,
)
from crossestate.contract import (
    DomainRef,
    EstateThresholds,
    EstateViewModel,
    Segment,
    SegmentPosture,
)
from crossestate.discovery import (
    ConnectedDomainDiscoveryProvider,
    DiscoveryProvider,
    to_completeness,
)
from crossestate.exceptions import derive_estate_exceptions
from crossestate.manifest import ManifestEntry, load_contract, load_manifest
from crossestate.segments import resolve_segments
from healthreport.grade import score_to_grade
from intelligence_contract import ReportViewModel


def build_estate_from_manifest(
    manifest_path: str,
    thresholds: Optional[EstateThresholds] = None,
    discovery: Optional[DiscoveryProvider] = None,
    now: Optional[datetime] = None,
) -> EstateViewModel:
    """Convenience wrapper: parse the manifest file, then build."""
    group, entries = load_manifest(manifest_path)
    return build_estate_view_model(group, entries, thresholds=thresholds,
                                   discovery=discovery, now=now)


def build_estate_view_model(
    group: str,
    entries: list[ManifestEntry],
    thresholds: Optional[EstateThresholds] = None,
    discovery: Optional[DiscoveryProvider] = None,
    now: Optional[datetime] = None,
) -> EstateViewModel:
    thresholds = thresholds or EstateThresholds()
    discovery = discovery or ConnectedDomainDiscoveryProvider()
    now = now or datetime.now(timezone.utc)

    # ── Load contracts (per-file failure is non-fatal) ───────────────────
    vms: dict[str, ReportViewModel] = {}
    load_errors: dict[str, str] = {}
    for e in entries:
        try:
            vms[e.domain] = load_contract(e.contract_path)
        except Exception as ex:  # noqa: BLE001 - one bad file must not sink the estate
            load_errors[e.domain] = f"{type(ex).__name__}: {ex}"

    # ── Resolve segments (tag authoritative; inference fills gaps) ────────
    assignments = resolve_segments(entries, vms)

    refs: list[DomainRef] = []
    for e in entries:
        a = assignments[e.domain]
        vm = vms.get(e.domain) or _unassessed_vm(e.domain)
        refs.append(DomainRef(
            domain=e.domain, segment=a.segment,
            segment_source=a.source, segment_disagreement=a.disagreement,
            vm=vm, contract_path=e.contract_path,
            load_error=load_errors.get(e.domain),
        ))

    # ── Analytics (deterministic aggregations) ───────────────────────────
    concentration = compute_concentration(refs, thresholds)
    correlated = compute_correlated(refs, thresholds)
    variance = compute_variance(refs, thresholds)
    exposure = compute_exposure(refs, thresholds)
    calendar = compute_calendar(refs, thresholds, now=now)
    completeness = to_completeness(discovery.discover(group, refs))

    # ── Segment hierarchy (posture from the variance block) ──────────────
    posture_by_seg = {sp.segment: sp for sp in variance.per_segment}
    seg_refs: dict[str, list[DomainRef]] = {}
    for r in refs:
        seg_refs.setdefault(r.segment, []).append(r)
    segments = [
        Segment(
            key=key, n_domains=len(rs), domains=rs,
            posture=posture_by_seg.get(key, SegmentPosture(segment=key)),
        )
        for key, rs in sorted(seg_refs.items())
    ]

    # ── Estate roll-up ───────────────────────────────────────────────────
    assessed = [r for r in refs if getattr(r.vm, "has_intelligence", False) and not r.load_error]
    estate_score = round(variance.estate_baseline_score) if assessed else 0
    estate_grade = score_to_grade(estate_score).letter if assessed else "?"

    estate = EstateViewModel(
        group=group,
        generated_at=now.isoformat(),
        thresholds=thresholds,
        domain_count=len(entries),
        assessed_count=len(assessed),
        declared_n=len(entries),
        estate_score=estate_score,
        estate_grade=estate_grade,
        grade_distribution=variance.grade_distribution,
        segments=segments,
        concentration=concentration,
        correlated_weakness=correlated,
        variance=variance,
        exposure=exposure,
        calendar=calendar,
        completeness=completeness,
        exceptions=[],
    )
    estate.exceptions = derive_estate_exceptions(estate)
    return estate


def _unassessed_vm(domain: str) -> ReportViewModel:
    """A 'not yet assessed' placeholder for a domain whose contract failed to
    load — counted in the estate size, excluded from assessed analytics."""
    unknown = score_to_grade(None)
    from intelligence_contract import ThreatSurface, TrustSurface
    return ReportViewModel(
        domain=domain, has_intelligence=False, composite_score=0, grade=unknown,
        trust=TrustSurface(score=0, grade=unknown),
        threat=ThreatSurface(score=0, grade=unknown),
    )
