"""
test_report_pipeline.py
-----------------------
Phase 7 orchestration, exercised with a mock IntelligenceClient + fixtures —
no network, no riskscore endpoint, no dnsproject, no Playwright.

Run: pytest tests/test_report_pipeline.py  (or python tests/test_report_pipeline.py)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from intelligence_contract import (  # noqa: E402
    BrandExposure, BrandFunnel, DomainIntelligence, ExternalThreat, PlatformImpersonation,
)
import report_pipeline as rp  # noqa: E402

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


# A representative dnsproject live-scan `output` dict (only the fields the
# pipeline reads).
SAMPLE_OUTPUT = {
    "domain": "riskyexample.com",
    "email_auth": {"dmarc_policy": "reject",
                   "spf_raw": "v=spf1 include:_spf.google.com -all",
                   "spf_strictness": "strict"},
    "technographics": {"mx_provider_name": "Microsoft 365", "asn": "64500",
                       "ns_provider_name": "Cloudflare"},
    "dns_records": {"a": ["203.0.113.10", "203.0.113.11"]},
    "txt_intelligence": {"all_identified": ["Microsoft 365", "Okta", "Mailchimp"]},
    "labels": {"lowest_ttl": 300},
}


def _ext_from_fixture() -> ExternalThreat:
    data = _load("platform_impersonation_sample.json")
    return ExternalThreat(
        impersonations=[PlatformImpersonation.model_validate(p) for p in data["platforms"]],
        own_brand=BrandExposure.model_validate(data["own_brand"]),
        lookalike_candidates=[PlatformImpersonation.model_validate({**p, "confidence": "lookalike"})
                              for p in data.get("platform_lookalikes", [])],
        own_brand_lookalikes=BrandExposure.model_validate(
            {**data.get("own_brand_lookalikes", {}), "confidence": "lookalike"}),
    )


class MockClient:
    def __init__(self, di: DomainIntelligence, ext: ExternalThreat):
        self._di, self._ext = di, ext
        self.fetch_args = None
        self.imp_args = None

    async def fetch(self, domain, fallback_asn=None, fallback_ip=None,
                    profile=None, live_dns_report=None):
        self.fetch_args = dict(domain=domain, fallback_asn=fallback_asn,
                               fallback_ip=fallback_ip, live_dns_report=live_dns_report)
        return self._di

    async def fetch_platform_impersonations(self, platforms, windows=(7, 30), brand=None):
        self.imp_args = dict(platforms=platforms, brand=brand)
        return self._ext

    async def fetch_brand_funnel(self, domain):
        self.funnel_args = dict(domain=domain)
        return BrandFunnel()


# ---------------------------------------------------------------------------
# Input derivation
# ---------------------------------------------------------------------------

def test_synth_live_dns_report():
    r = rp.synth_live_dns_report(SAMPLE_OUTPUT)
    es = r["email_security"]
    assert es["inferred_mbp"] == "Microsoft 365"
    assert es["dmarc_enforced"] is True          # p=reject
    assert es["spf_strict"] is True              # -all
    assert r["dns_profile"]["records"]["A"]["raw"] == ["203.0.113.10", "203.0.113.11"]
    assert r["dns_profile"]["security_heuristics"]["lowest_ttl"] == 300


def test_synth_live_dns_report_monitor_only():
    out = {"email_auth": {"dmarc_policy": "none", "spf_raw": "v=spf1 ~all"}}
    es = rp.synth_live_dns_report(out)["email_security"]
    assert es["dmarc_enforced"] is False         # p=none is monitor-only
    assert es["spf_strict"] is False             # ~all is soft


def test_detect_platforms_dedups():
    plats = rp.detect_platforms(SAMPLE_OUTPUT)
    # all_identified + ns provider; mx provider dedups against all_identified
    assert plats == ["Microsoft 365", "Okta", "Mailchimp", "Cloudflare"]


def test_detect_platforms_filters_non_platforms():
    out = {**SAMPLE_OUTPUT,
           "txt_intelligence": {"all_identified": ["Microsoft 365", "SPF Policy", "Okta"]}}
    plats = rp.detect_platforms(out)
    assert "Microsoft 365" in plats and "Okta" in plats
    assert not any("spf" in p.lower() for p in plats)


def test_fallback_asn_ip():
    assert rp.fallback_asn_ip(SAMPLE_OUTPUT) == (64500, "203.0.113.10")
    assert rp.fallback_asn_ip({}) == (None, None)


def test_client_timeout_default_and_override():
    from intelligence_client import IntelligenceClient
    os.environ["INTELLIGENCE_BASE_URL"] = "http://riskscore:8817"
    os.environ.pop("INTELLIGENCE_TIMEOUT", None)
    assert IntelligenceClient().timeout.total == 60        # raised from the old 15s
    os.environ["INTELLIGENCE_TIMEOUT"] = "180"
    assert IntelligenceClient().timeout.total == 180
    os.environ.pop("INTELLIGENCE_TIMEOUT", None)


def test_is_medallion_payload():
    assert rp.is_medallion_payload(_load("medallion_sample.json")) is True
    assert rp.is_medallion_payload(SAMPLE_OUTPUT) is False
    assert rp.is_medallion_payload({"schema_version": "1.0"}) is False  # no risk_assessment


# ---------------------------------------------------------------------------
# View-model assembly (POST path)
# ---------------------------------------------------------------------------

def test_build_view_model_live_post():
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    client = MockClient(di, _ext_from_fixture())
    vm = asyncio.run(rp.build_view_model("riskyexample.com", client, live_output=SAMPLE_OUTPUT))

    # POST path: a live_dns_report was synthesised and passed
    assert client.fetch_args["live_dns_report"] is not None
    assert client.fetch_args["live_dns_report"]["email_security"]["dmarc_enforced"] is True
    assert client.fetch_args["fallback_asn"] == 64500
    assert client.fetch_args["fallback_ip"] == "203.0.113.10"
    # impersonations queried with the detected stack + own brand
    assert "Microsoft 365" in client.imp_args["platforms"]
    assert client.imp_args["brand"] == "riskyexample.com"

    # composed view-model
    assert vm.has_intelligence
    assert vm.external_threat.total_30d == 41 + 25 + 4
    assert vm.external_threat.lookalike_total_30d == 11
    assert vm.findings
    assert any(f["finding"] == "threat_feed_feodo" for f in vm.findings)


def test_build_view_model_snapshot_get():
    """No live_output → GET path (no live_dns_report), no platforms queried."""
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    client = MockClient(di, ExternalThreat())
    vm = asyncio.run(rp.build_view_model("riskyexample.com", client))
    assert client.fetch_args["live_dns_report"] is None
    assert client.imp_args["platforms"] == []
    assert vm.has_intelligence


def test_view_model_from_medallion():
    vm = rp.view_model_from_medallion(_load("medallion_sample.json"))
    assert vm.has_intelligence
    assert vm.domain == "riskyexample.com"
    assert vm.findings


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_render_variants_full():
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = asyncio.run(rp.build_view_model(
        "riskyexample.com", MockClient(di, _ext_from_fixture()), live_output=SAMPLE_OUTPUT))
    reports = rp.render_variants(vm, audiences=["flagship", "external_threat"],
                                 tier="full", legacy=SAMPLE_OUTPUT)
    assert set(reports) == {"flagship", "external_threat"}
    assert reports["flagship"]["html"].lstrip().startswith("<!DOCTYPE html>")
    assert "markdown" in reports["flagship"]
    # exact lure visible at full tier
    assert "micros0ft-365-login.com" in reports["flagship"]["html"]


def test_render_variants_teaser_redacts():
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = asyncio.run(rp.build_view_model(
        "riskyexample.com", MockClient(di, _ext_from_fixture()), live_output=SAMPLE_OUTPUT))
    reports = rp.render_variants(vm, audiences=["flagship"], tier="teaser", legacy=SAMPLE_OUTPUT)
    assert "micros0ft-365-login.com" not in reports["flagship"]["html"]


def test_render_variants_rejects_pdf_format():
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = rp.view_model_from_medallion(_load("medallion_sample.json"))
    try:
        rp.render_variants(vm, audiences=["flagship"], formats=("pdf",))
    except ValueError:
        return
    raise AssertionError("expected ValueError for pdf format")


def _main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
            import traceback
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    _main()
