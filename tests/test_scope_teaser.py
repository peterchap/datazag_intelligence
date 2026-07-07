"""WU20 teaser guardrails — the commercial rules the doc locks."""
from __future__ import annotations

import json
from datetime import date
from types import SimpleNamespace

from scopeteaser.bands import BANDS, BANDS_JSON, band_for, band_range_label, export_json
from scopeteaser.compose import build_teaser, tiers_from_discovery_result
from scopeteaser.contract import MAX_PROOF_DOMAINS
from scopeteaser.renderer import render_teaser_html


def _dom(name, tier, detail="shared certificate SAN with acme.com"):
    return SimpleNamespace(domain=name, tier=tier, evidence=[{"kind": "san", "detail": detail}])


def _teaser(strong=5, possible=4, defensive=6, declared=9):
    tiers = {
        "declared": [f"decl{i}.com" for i in range(declared)],
        "strong": [_dom(f"strong{i}.com", "strong") for i in range(strong)],
        "possible": [_dom(f"possible{i}.com", "possible") for i in range(possible)],
        "defensive": [_dom(f"defensive{i}.com", "defensive") for i in range(defensive)],
    }
    return build_teaser(tiers, declared_count=declared, requested_by="buyer@example.com",
                        src="free-report", today=date(2026, 7, 6))


def test_proof_domains_capped_and_strong_only():
    vm = _teaser(strong=5)
    assert len(vm.proof_domains) == MAX_PROOF_DOMAINS
    assert all(p.domain.startswith("strong") for p in vm.proof_domains)
    assert all(p.evidence_line for p in vm.proof_domains)


def test_teaser_never_names_possible_or_defensive_domains():
    vm = _teaser()
    html = render_teaser_html(vm, "https://portal.datazag.com/scope/result/tok")
    for i in range(6):
        assert f"possible{i}.com" not in html
        assert f"defensive{i}.com" not in html
    # counts ARE public
    assert "Possible · 4" in html and "Defensive / acquisition · 6" in html


def test_delta_headline_and_band_on_graded_estate():
    vm = _teaser(strong=5, declared=9)
    assert vm.evidenced_count == 14 and vm.delta == 5
    assert vm.band == band_for(14)          # declared + strong, possible NOT banded
    html = render_teaser_html(vm, "https://x")
    assert "You told us 9. We can evidence 14." in html


def test_bottom_band_is_the_only_self_serve():
    assert [b.self_serve for b in BANDS] == [True, False, False, False]
    assert band_for(15).self_serve and not band_for(16).self_serve
    assert "Band A · up to 15 domains · from £3,500" == band_range_label(BANDS[0])


def test_subscription_and_partner_link_render():
    from scopeteaser.bands import PARTNER_DISCOUNT_URL, band_subscription_label
    # Subscription figures are pending — render "on request", never an invented price.
    assert all(b.from_price_sub_gbp is None for b in BANDS)
    assert "on request" in band_subscription_label(BANDS[0])
    html = render_teaser_html(_teaser(), "https://x")
    assert "on request" in html and PARTNER_DISCOUNT_URL in html


def test_bands_json_matches_table():
    assert json.loads(BANDS_JSON.read_text(encoding="utf-8")) == json.loads(export_json())


def test_watermark_and_expiry_render():
    vm = _teaser()
    html = render_teaser_html(vm, "https://x")
    assert "buyer@example.com" in html           # watermarked with requesting email
    assert "2026-08-05" in html                  # 30-day expiry


def test_discovery_result_adapter_maps_lanes():
    result = SimpleNamespace(
        declared=["a.com", "b.com"],
        discovered=[_dom("s.com", "strong"), _dom("d.com", "defensive")],
        candidates=[_dom("c.com", "possible")],
        hostile=[_dom("h.com", "possible")],
    )
    tiers = tiers_from_discovery_result(result)
    assert [d.domain for d in tiers["strong"]] == ["s.com"]
    assert [d.domain for d in tiers["possible"]] == ["c.com"]
    assert {d.domain for d in tiers["defensive"]} == {"d.com", "h.com"}
