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
