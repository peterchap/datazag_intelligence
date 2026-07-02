"""Pure-logic tests for the five cross-estate analytics."""

from __future__ import annotations

from datetime import datetime, timezone

from estate_helpers import imp, make_ref  # noqa: E402

from crossestate.analytics import (  # noqa: E402
    compute_calendar,
    compute_concentration,
    compute_correlated,
    compute_exposure,
    compute_variance,
)
from crossestate.contract import EstateThresholds  # noqa: E402

TH = EstateThresholds()
NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)


def test_concentration_flags_dominant_provider_and_excludes_unknown():
    refs = [
        make_ref("a.com", "s", ns="Cloudflare"),
        make_ref("b.com", "s", ns="Cloudflare"),
        make_ref("c.com", "s", ns="Cloudflare"),
        make_ref("d.com", "s", ns="Route 53"),
        make_ref("e.com", "s", ns=None),          # unknown → excluded from denom
    ]
    dims = {d.dimension: d for d in compute_concentration(refs, TH)}
    ns = dims["ns"]
    assert ns.denom == 4                            # e.com excluded
    assert ns.top_provider == "Cloudflare"
    assert round(ns.top_pct, 2) == 0.75
    assert ns.flagged is True


def test_correlated_weakness_prevalence_and_segment_clustering():
    refs = [
        make_ref("a.com", "corp", dmarc="reject"),
        make_ref("b.com", "corp", dmarc="reject"),
        make_ref("x.com", "acquired", dmarc="none"),   # weak
        make_ref("y.com", "acquired", dmarc="none"),   # weak → 100% of 'acquired'
    ]
    ws = {w.control: w for w in compute_correlated(refs, TH)}
    dmarc = ws["dmarc"]
    assert dmarc.n_affected == 2 and dmarc.n_assessed == 4
    assert round(dmarc.pct, 2) == 0.50
    assert dmarc.systemic is True                      # 50% >= 0.50 threshold
    assert dmarc.systemic_segments == ["acquired"]     # 2/2 in acquired


def test_correlated_ignores_unassessed_domains():
    refs = [
        make_ref("a.com", "s", dmarc="none"),
        make_ref("z.com", "s", dmarc="none", has_intel=False),  # not assessed
    ]
    dmarc = {w.control: w for w in compute_correlated(refs, TH)}["dmarc"]
    assert dmarc.n_assessed == 1 and dmarc.n_affected == 1


def test_variance_detects_outlier_segment():
    refs = [
        make_ref("a.com", "corp", score=20),
        make_ref("b.com", "corp", score=25),
        make_ref("x.com", "acquired", score=90),
        make_ref("y.com", "acquired", score=88),
    ]
    v = compute_variance(refs, TH)
    assert "acquired" in v.outlier_segments
    acq = next(sp for sp in v.per_segment if sp.segment == "acquired")
    assert acq.is_outlier and acq.bands_below_baseline >= TH.variance_outlier_bands


def test_variance_excludes_unassessed_from_baseline():
    refs = [
        make_ref("a.com", "s", score=20),
        make_ref("z.com", "s", score=0, has_intel=False),
    ]
    v = compute_variance(refs, TH)
    assert v.unassessed == 1
    assert v.estate_baseline_score == 20.0            # the 0-score unassessed excluded


def test_exposure_sums_exact_only_and_keeps_lookalikes_separate():
    refs = [
        make_ref("a.com", "s", imps=[imp("microsoft365", 2, 6, ["m1.com"])],
                 lookalikes=[imp("google", 0, 4, ["g1.com"], confidence="lookalike")]),
        make_ref("b.com", "s", imps=[imp("microsoft365", 1, 3, ["m2.com"])]),
    ]
    e = compute_exposure(refs, TH)
    assert e.total_30d == 9                            # 6 + 3, EXACT only
    assert e.lookalike_total_30d == 4                  # parallel, not summed in
    top = e.by_platform[0]
    assert top.platform == "microsoft365" and top.targeted_domains == 2
    assert e.targeting_concentration == 1.0


def test_calendar_orders_overdue_first_and_counts_windows():
    refs = [
        make_ref("exp.com", "s", expires="2026-06-20"),   # overdue (before NOW)
        make_ref("soon.com", "s", expires="2026-07-20"),  # ~18d
        make_ref("far.com", "s", expires="2028-01-01"),   # beyond 60d horizon → omitted
        make_ref("unlocked.com", "s", status="ok"),       # no lock token → unlocked item
    ]
    c = compute_calendar(refs, TH, now=NOW)
    kinds = [it.kind for it in c.items]
    assert "domain_expiry" in kinds and "unlocked" in kinds
    assert c.overdue >= 1
    # far.com's expiry is beyond the horizon → not an item
    assert not any(it.domain == "far.com" for it in c.items)
    # first item is the overdue one
    assert c.items[0].days_left is not None and c.items[0].days_left < 0


def _run_all():
    import sys
    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
