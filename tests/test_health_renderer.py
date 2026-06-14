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
    # all 15 pages (incl. DNS records, infra/routing, IT remediation), numbering intact
    assert "Page 1 of 15" in html
    assert "Page 15 of 15" in html
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


def test_is_platform_name_stoplist():
    from healthreport.renderer import is_platform_name
    assert is_platform_name("Google Workspace")
    assert is_platform_name("Microsoft 365")
    assert not is_platform_name("SPF Policy")
    assert not is_platform_name("spf_policy")
    assert not is_platform_name("DMARC")
    assert not is_platform_name("")


def test_spf_policy_not_rendered_as_platform():
    """Regression: 'SPF Policy' leaked from txt_intelligence into the stack on
    the first live report. It must never appear as a detected platform."""
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = build_view_models(di, detected_platforms=["Google Workspace", "SPF Policy"],
                           impersonations=[], findings=derive_findings(di, []))
    r = HealthReportRenderer(vm)
    names = [v["name"] for v in r._build_vendor_list()]
    assert "Google Workspace" in names
    assert not any("spf" in n.lower() for n in names)


def test_platform_priority_preventative_when_no_impersonation():
    """Regression: with zero observed impersonations the platform priority must
    NOT claim a 'Critical active campaign likely' — that contradicted the
    'Monitoring / no matches' state shown elsewhere."""
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = build_view_models(di, detected_platforms=["Google Workspace"],
                           impersonations=[], findings=derive_findings(di, []))
    r = HealthReportRenderer(vm)
    plat = next(p for p in r._build_priorities() if p["surface"] == "vendor")
    assert plat["severity"] == "medium"
    assert "likely" not in plat["title"].lower()
    html = r.to_html()
    assert "Active impersonation campaign against" not in html


def test_teaser_masks_lookalike_domains():
    html = HealthReportRenderer(_sample_vm(), tier="teaser").to_html()
    assert "rnicrosoft365.com" not in html
    assert "risky-examp1e.com" not in html
    assert _mask_domain("rnicrosoft365.com") in html


# ---------------------------------------------------------------------------
# Teaser tier — redaction must hold in the rendered source
# ---------------------------------------------------------------------------

def test_it_remediation_tearoff():
    """The back-of-report IT remediation plan: consolidated, severity-sorted,
    concrete fixes from control gaps + findings — and it lives at the back
    (after roadmap, before glossary), in flagship/advisory/remediation only."""
    legacy = {
        "domain": "riskyexample.com",
        "email_auth": {"dmarc_policy": "none"},   # → a control-gap action
        "threat_flags": {"has_caa": False},
    }
    r = HealthReportRenderer(_sample_vm(), audience="flagship", legacy=legacy)
    acts = r._build_remediation_actions()
    assert acts, "expected remediation actions from control gaps + findings"
    sevs = [a["severity"] for a in acts]
    assert sevs == sorted(sevs, key=lambda s: {"critical": 0, "high": 1, "medium": 2}.get(s, 3))
    assert all(a["step"] for a in acts)          # every row has a concrete fix
    html = r.to_html()
    assert "Remediation plan — hand this to your team." in html
    # rendered as the penultimate section (the section body sits after the roadmap
    # body and immediately before the glossary section)
    rem = html.index("Remediation plan — hand this to your team.")
    roadmap = html.index("The implementation changes that close the gaps.")
    glossary = html.index("Glossary &amp; methodology") if "Glossary &amp; methodology" in html else html.rindex("Glossary")
    assert roadmap < rem < glossary
    assert "## IT remediation plan" in r.to_markdown()

    # audience scoping: in flagship/advisory/remediation, not insurer/external_threat
    from healthreport.audiences import get_audience
    for aud in ("flagship", "advisory", "remediation"):
        assert "remediation_plan" in get_audience(aud).sections
    for aud in ("insurer", "external_threat"):
        assert "remediation_plan" not in get_audience(aud).sections


def test_dns_records_section():
    """Full DNS records with weakness commentary — the completeness centerpiece."""
    legacy = {
        "domain": "riskyexample.com",
        "dns_records": {
            "a": ["203.0.113.10"],
            "mx": [{"priority": 10, "host": "mx.example.com"}],
            "ns": ["ns1.example.com"],                              # single → weakness
            "txt": ["v=spf1 include:_spf.google.com ~all",          # ~all → weakness
                    "google-site-verification=abc123"],             # reveals SaaS
            "caa": [],                                              # missing → weakness
        },
        "email_auth": {"dnssec": False},                           # → weakness
    }
    r = HealthReportRenderer(_sample_vm(), legacy=legacy)
    dv = r._build_dns_records()
    types = {g["type"] for g in dv["groups"]}
    assert {"A", "MX", "NS", "TXT", "CAA", "DNSSEC"} <= types
    assert dv["weak"] >= 4         # NS single, CAA missing, SPF ~all, DNSSEC off
    html = r.to_html()
    assert "Full DNS records" in html
    assert "203.0.113.10" in html
    assert "any certificate authority can issue" in html      # CAA missing note
    assert "Single nameserver" in html                        # NS weakness
    assert "soft-fail" in html                                # SPF ~all
    assert "not cryptographically signed" in html             # DNSSEC
    assert "reveals a SaaS platform" in html                  # verification token
    md = r.to_markdown()
    assert "## Full DNS records" in md


def test_infra_routing_section():
    """IP / prefix / ASN quality section — the piece flagged as missing vs the
    old reports. Every datapoint comes from the medallion view-model."""
    vm = _sample_vm()
    r = HealthReportRenderer(vm, audience="flagship")
    ir = r._build_infra_routing()
    assert ir["asn"] == "AS64500"
    assert ir["rpki_class"] == "bad"          # rpki_state invalid
    assert ir["moas"] is True
    assert any(x["label"].startswith("ASN infrastructure") for x in ir["reputation"])
    html = r.to_html()
    assert "routing intelligence" in html.lower()
    assert "AS64500" in html
    assert "INVALID" in html                  # RPKI pill
    assert "malicious domains share this asn" in html   # concentration co-tenancy
    assert "64500" in html
    # markdown carries it too
    md = r.to_markdown()
    assert "## Infrastructure & routing intelligence" in md
    assert "AS64500" in md


def test_infra_routing_in_remediation_not_external_threat():
    vm = _sample_vm()
    assert "infra_routing" in [s for s in __import__("healthreport.audiences", fromlist=["get_audience"]).get_audience("remediation").sections]
    assert "infra_routing" not in __import__("healthreport.audiences", fromlist=["get_audience"]).get_audience("external_threat").sections


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

def test_markdown_is_full_report():
    """Markdown must be the full report (all sections), not a short summary."""
    legacy = {
        "domain": "riskyexample.com",
        "email_auth": {"dmarc_policy": "none"},
        "rdap": {"domain_age_days": 4200, "registrar_name": "Example Registrar"},
        "subdomains": [
            {"dns_name": "vpn.riskyexample.com", "risk_level": "high", "days_remaining": 12,
             "is_takeover_vulnerable": True},
            {"dns_name": "www.riskyexample.com", "risk_level": "info", "days_remaining": 200},
        ],
    }
    md = HealthReportRenderer(_sample_vm(), tier="full", legacy=legacy).to_markdown()
    # the three-act arc + the rich sections all present
    for heading in ("# Datazag", "## The attacker problem", "## Your defence weaknesses",
                    "## Platform footprint", "## Defensive controls", "## Hidden infrastructure",
                    "## Three things to address first", "## Implementation-changes roadmap",
                    "## All findings"):
        assert heading in md, f"missing section: {heading}"
    # impersonation detail + subdomains rendered
    assert "microsoft365" in md
    assert "micros0ft-365-login.com" in md
    assert "vpn.riskyexample.com" in md           # subdomain table populated
    assert "threat_feed_feodo" not in md          # findings shown by title, not key
    assert "Listed on Feodo C2 tracker" in md


def test_dict_external_threat_totals():
    d = HealthReportRenderer(_sample_vm(), tier="full").to_dict()
    assert d["external_threat"]["impersonations_30d"] == 70   # 41+25+4
    assert d["external_threat"]["lookalike_candidates_30d"] == 11
    assert d["pillars"]["trust"]["score"] > 0
    assert d["tier"] == "full"


def test_subdomains_rendered_from_dns_name():
    """Regression: section 07 read s['host'] but dnsproject uses 'dns_name',
    so the count showed 10 while the table was blank."""
    legacy = {
        "domain": "riskyexample.com",
        "subdomains": [
            {"dns_name": "vpn.riskyexample.com", "risk_level": "high", "days_remaining": 9,
             "is_takeover_vulnerable": True},
            {"dns_name": "www.riskyexample.com", "risk_level": "info", "days_remaining": 250},
            {"dns_name": "support.riskyexample.com", "risk_level": "low",
             "cname_records": ["desk.zoho.com"]},
        ],
    }
    r = HealthReportRenderer(_sample_vm(), legacy=legacy)
    sample = r._build_subdomain_sample()
    hosts = [s["host"] for s in sample]
    assert "vpn.riskyexample.com" in hosts
    assert "—" not in hosts                       # names resolve, no blank rows
    html = r.to_html()
    assert "vpn.riskyexample.com" in html
    assert 'class="subdomain-sample-table-wrap"' in html
    # CNAME-based vendor detection now fires (host came from dns_name)
    assert ("support.riskyexample.com", "desk.zoho.com") in r._subdomain_cname_targets()


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
