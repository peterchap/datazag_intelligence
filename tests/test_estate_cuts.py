"""Tests for the operator|oversight cut: human-render suppression + JSON completeness."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from estate_helpers import ESTATE_MANIFEST  # noqa: E402

from crossestate.build import build_estate_from_manifest  # noqa: E402
from crossestate.cuts import get_cut  # noqa: E402
from crossestate.renderer import CrossEstateRenderer  # noqa: E402

NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)


def _renderers():
    e = build_estate_from_manifest(ESTATE_MANIFEST, now=NOW)
    return CrossEstateRenderer(e, cut="operator"), CrossEstateRenderer(e, cut="oversight")


def _unchecked_renderer(cut="operator"):
    """An estate where every impersonation lookup failed: totals are 0 because
    nothing was fetched, not because nothing was found."""
    e = build_estate_from_manifest(ESTATE_MANIFEST, now=NOW)
    e.exposure.total_7d = 0
    e.exposure.total_30d = 0
    e.exposure.by_platform = []
    e.exposure.unchecked_domains = ["acme.com", "acmeshop.com"]
    return CrossEstateRenderer(e, cut=cut)


def test_estate_all_clear_gated_on_the_lookup_having_run():
    md = _unchecked_renderer().to_markdown()
    assert "No active EXACT impersonation" not in md
    assert "Not checked" in md
    html = _unchecked_renderer().to_html()
    assert "No active EXACT impersonation" not in html
    assert "Not checked" in html


def test_estate_all_clear_survives_when_every_lookup_ran():
    """The counterpart: a fully-checked estate with no matches keeps its all-clear."""
    e = build_estate_from_manifest(ESTATE_MANIFEST, now=NOW)
    e.exposure.total_30d = 0
    e.exposure.by_platform = []
    e.exposure.unchecked_domains = []
    assert "No active EXACT impersonation" in CrossEstateRenderer(e, cut="operator").to_markdown()


def test_cut_config():
    assert get_cut("operator").show_per_domain_fixes is True
    assert get_cut("oversight").show_per_domain_fixes is False


def test_operator_shows_per_domain_fixes_and_drilldown():
    op, _ = _renderers()
    md = op.to_markdown()
    assert "Remediation:" in md
    assert "Per-domain drill-down" in md


def test_oversight_suppresses_fixes_and_shows_rollup():
    _, ov = _renderers()
    md = ov.to_markdown()
    assert "Remediation:" not in md                    # per-domain fixes suppressed
    assert "Per-domain drill-down" not in md
    assert "Fixable-weakness rollup" in md             # portfolio finding instead


def test_json_is_complete_and_cut_independent():
    op, ov = _renderers()
    assert op.to_json() == ov.to_json()                # cut never changes the feed
    payload = json.loads(op.to_json())
    # remediation survives in the JSON even for the oversight consumer
    assert any(x.get("remediation") for x in payload["exceptions"])
    assert "correlated_weakness" in payload and "exposure" in payload


def test_oversight_leads_with_concentration():
    _, ov = _renderers()
    secs = get_cut("oversight").sections
    # concentration/variance/exposure precede the exception register
    assert secs.index("concentration") < secs.index("exceptions")


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
