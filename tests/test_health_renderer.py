"""
test_health_renderer.py
-----------------------
Render tests for the flagship Trust + Threat Surface engine, off fixtures —
no network, no riskscore endpoint, no Playwright.

Runs under pytest (`pytest tests/test_health_renderer.py`) or standalone
(`python tests/test_health_renderer.py`).
"""

from __future__ import annotations

import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from intelligence_contract import (  # noqa: E402
    BrandExposure,
    DomainIntelligence,
    PlatformImpersonation,
    build_view_models,
    redact_for_teaser,
    _mask_domain,
)
from findings_rules import derive_findings  # noqa: E402
from healthreport.renderer import HealthReportRenderer  # noqa: E402

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# A specific lookalike domain from the impersonation fixture — must appear in
# FULL tier output and must NEVER appear in TEASER tier output.
SENSITIVE_LURE = "micros0ft-365-login.com"
SENSITIVE_OWN_BRAND = "riskyexample-support.com"


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _sample_vm():
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    data = _load("platform_impersonation_sample.json")
    imps = [PlatformImpersonation.model_validate(p) for p in data["platforms"]]
    own = BrandExposure.model_validate(data["own_brand"])
    looks = [PlatformImpersonation.model_validate({**p, "confidence": "lookalike"})
             for p in data.get("platform_lookalikes", [])]
    own_looks = BrandExposure.model_validate({**data.get("own_brand_lookalikes", {}),
                                              "confidence": "lookalike"})
    findings = derive_findings(di, imps)
    return build_view_models(
        di,
        detected_platforms=["microsoft365", "okta", "mailchimp"],
        impersonations=imps,
        own_brand=own,
        findings=findings,
        lookalike_candidates=looks,
        own_brand_lookalikes=own_looks,
    )


# ---------------------------------------------------------------------------
# Flagship / full
# ---------------------------------------------------------------------------

def test_flagship_full_renders():
    html = HealthReportRenderer(_sample_vm()).to_html()
    # platform-impersonation data surfaced
    assert SENSITIVE_LURE in html, "full tier must show real lure domains"
    assert SENSITIVE_OWN_BRAND in html
    assert "41" in html                       # microsoft365 count_30d
    assert "Platforms targeted" in html
    # all 12 pages, dynamic numbering intact
    assert "Page 1 of 12" in html
    assert "Page 12 of 12" in html
    # medallion findings drive the priorities/infra side
    assert "Trust Grade" in html or "trust grade" in html.lower()


def test_flagship_full_vendor_stack_from_corpus():
    """With no legacy dict, vendors come from detected_platforms."""
    html = HealthReportRenderer(_sample_vm()).to_html()
    assert "Microsoft 365" in html
    assert "Okta" in html
    assert "Mailchimp" in html


def test_full_shows_per_platform_counts():
    r = HealthReportRenderer(_sample_vm())
    ctx_rows = r._active_impersonations()
    assert [i.platform for i in ctx_rows] == ["microsoft365", "okta", "mailchimp"]
    assert r._pill_platforms_at_risk() == 3
    assert r._pill_brand_exposures() == 3


def test_lookalike_candidates_separate_from_headline():
    vm = _sample_vm()
    # headline (exact) excludes the fuzzy candidates
    assert vm.external_threat.total_30d == 41 + 25 + 4
    assert vm.external_threat.lookalike_total_30d == 11
    assert vm.external_threat.own_brand_lookalikes.count_30d == 6
    html = HealthReportRenderer(vm).to_html()
    # candidates section present, clearly lower-confidence
    assert "Lookalike candidates" in html
    assert "Lower confidence" in html
    assert "rnicrosoft365.com" in html          # platform typosquat sample
    assert "risky-examp1e.com" in html          # own-brand typosquat sample
    # the confidence caveat is present
    assert "false positives" in html.lower()
    # to_dict surfaces the candidate totals separately
    d = HealthReportRenderer(vm).to_dict()
    assert d["external_threat"]["lookalike_candidates_30d"] == 11
    assert d["external_threat"]["own_brand_lookalikes_30d"] == 6


def test_teaser_masks_lookalike_domains():
    html = HealthReportRenderer(_sample_vm(), tier="teaser").to_html()
    assert "rnicrosoft365.com" not in html
    assert "risky-examp1e.com" not in html
    assert _mask_domain("rnicrosoft365.com") in html


# ---------------------------------------------------------------------------
# Teaser tier — redaction must hold in the rendered source
# ---------------------------------------------------------------------------

def test_teaser_redacts_specifics():
    html = HealthReportRenderer(_sample_vm(), tier="teaser").to_html()
    # No raw lookalike domains anywhere in the teaser source
    assert SENSITIVE_LURE not in html
    assert SENSITIVE_OWN_BRAND not in html
    # Masked forms appear instead
    assert _mask_domain(SENSITIVE_LURE) in html
    # Headline counts survive redaction (that's the teaser hook)
    assert "41" in html
    # CTA present
    assert "teaser edition" in html.lower()


def test_teaser_redacts_finding_remediation():
    vm = _sample_vm()
    teaser = redact_for_teaser(vm)
    assert all(f["remediation"] == "Included in the full report." for f in teaser.findings)
    assert all(f["evidence"] == "Included in the full report." for f in teaser.findings)
    # full vm untouched (deep copy)
    assert any(f["remediation"] != "Included in the full report." for f in vm.findings)


# ---------------------------------------------------------------------------
# Variants
# ---------------------------------------------------------------------------

def test_external_threat_variant_sections():
    html = HealthReportRenderer(_sample_vm(), audience="external_threat").to_html()
    assert "of 6" in html                      # 6 enabled sections
    assert SENSITIVE_LURE in html              # the deep-dive content
    assert "External Threat Report" in html    # masthead label
    # glossary (full-report-only section) absent
    assert "Certificate Transparency" not in html


def test_unknown_audience_rejected():
    try:
        HealthReportRenderer(_sample_vm(), audience="nope")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown audience")


def test_unknown_tier_rejected():
    try:
        HealthReportRenderer(_sample_vm(), tier="freemium")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown tier")


# ---------------------------------------------------------------------------
# No-intelligence state — never a false all-clear
# ---------------------------------------------------------------------------

def test_nxdomain_renders_not_assessed():
    di = DomainIntelligence.model_validate(_load("medallion_nxdomain.json"))
    vm = build_view_models(di)
    r = HealthReportRenderer(vm)
    assert r._grade.letter == "?"
    html = r.to_html()
    assert "Not yet assessed" in html


# ---------------------------------------------------------------------------
# Legacy enrichment path
# ---------------------------------------------------------------------------

def test_legacy_dict_enriches_render():
    legacy = {
        "domain": "riskyexample.com",
        "generated_at": "2026-06-10T09:00:00",
        "email_auth": {"dmarc_policy": "none", "is_spoofable": True,
                       "spoofing_severity": "high", "missing_layers": ["BIMI"]},
        "threat_flags": {"has_caa": False},
        "findings": [{"finding": "legacy_only", "severity": "high",
                      "title": "Legacy live-scan finding", "evidence": "x",
                      "detail": "y", "remediation": "z"}],
        "subdomains": [{"host": "support.riskyexample.com",
                        "cname": "desk.zoho.com", "risk_level": "low"}],
    }
    r = HealthReportRenderer(_sample_vm(), legacy=legacy)
    html = r.to_html()
    # legacy email-auth branch used
    assert "DMARC at p=none" in html
    # legacy findings merged in alongside medallion findings
    assert any(f["finding"] == "legacy_only" for f in r.findings)
    assert any(f["finding"] == "threat_feed_feodo" for f in r.findings)
    # CNAME vendor detection from legacy subdomains
    assert "Zoho" in html


# ---------------------------------------------------------------------------
# Other formats
# ---------------------------------------------------------------------------

def test_markdown_and_dict():
    r = HealthReportRenderer(_sample_vm(), tier="full")
    md = r.to_markdown()
    assert "External threat — platform impersonation" in md
    assert "microsoft365" in md
    d = r.to_dict()
    assert d["external_threat"]["impersonations_30d"] == 70   # 41+25+4
    assert d["pillars"]["trust"]["score"] > 0
    assert d["tier"] == "full"


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
