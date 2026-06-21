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
    BrandCandidate,
    BrandExposure,
    BrandFunnel,
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
    # medallion ISP/country/risk + a live-scan MX/NS provider annotation
    legacy = {"domain": "riskyexample.com",
              "technographics": {"mx_provider_name": "Microsoft", "mx_mbp_category": "Email Service Provider",
                                 "ns_provider_name": "Cloudflare"}}
    r = HealthReportRenderer(vm, audience="flagship", legacy=legacy)
    ir = r._build_infra_routing()
    assert ir["asn"] == "AS64500"
    assert ir["rpki_class"] == "bad"          # rpki_state invalid
    assert ir["moas"] is True
    # ISP/country/risk (from the medallion facts) + providers (from live scan)
    assert ir["isp"] == "Evil Hosting Ltd"
    assert ir["country"] == "RU"
    assert ir["asn_risk"] == "high" and ir["asn_risk_class"] == "bad"
    assert ir["mx_provider"] == "Microsoft"
    assert ir["ns_provider"] == "Cloudflare"
    html2 = r.to_html()
    assert "Evil Hosting Ltd" in html2 and "Mailbox provider" in html2 and "Microsoft" in html2
    assert "Nameserver provider" in html2
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


def test_annotation_lake_overrides_providers():
    """`output["annotation"]` (the DuckLake v_annotated row) is authoritative for
    providers/labels — it outranks the live-scan technographics, and its
    annotation-only labels (hosting / TLD risk / trust) surface in the report."""
    vm = _sample_vm()
    legacy = {
        "domain": "riskyexample.com",
        # technographics says one thing...
        "technographics": {"mx_provider_name": "Old Guess", "ns_provider_name": "Old NS"},
        # ...the annotation lake says another (and wins).
        "annotation": {
            "domain": "riskyexample.com",
            "mailbox_provider": "Microsoft 365", "mailbox_category": "Enterprise mail",
            "ns_provider": "Cloudflare", "hosting_provider": "Amazon AWS",
            "asn_risk_level": "critical", "tld_risk_level": "high",
            "trust_label": "Low trust", "is_parked": False,
        },
    }
    r = HealthReportRenderer(vm, audience="flagship", legacy=legacy)
    ir = r._build_infra_routing()
    assert ir["mx_provider"] == "Microsoft 365"      # lake beats technographics
    assert ir["mx_category"] == "Enterprise mail"
    assert ir["ns_provider"] == "Cloudflare"
    assert ir["hosting_provider"] == "Amazon AWS"
    assert ir["asn_risk"] == "critical" and ir["asn_risk_class"] == "bad"
    assert ir["tld_risk"] == "high" and ir["tld_risk_class"] == "bad"
    assert ir["trust_label"] == "Low trust"
    html = r.to_html()
    assert "Microsoft 365" in html and "Amazon AWS" in html
    assert "Hosting provider" in html and "TLD risk" in html and "Infrastructure trust" in html
    assert "Old Guess" not in html and "Old NS" not in html
    md = r.to_markdown()
    assert "Hosting provider: Amazon AWS" in md and "TLD risk **high**" in md


def test_annotation_lake_drives_platform_stack():
    """The lake is authoritative for the vendor footprint. The MX-derived platform
    lives in the flat `mailbox_provider` field (the lake's platform_signals are
    SPF/TXT only) — folded in as a 'confirmed' MX signal that outranks a Google
    Workspace TXT verification token, which reads as 'indicative'."""
    vm = _sample_vm()
    legacy = {
        "domain": "riskyexample.com",
        "annotation": {
            "domain": "riskyexample.com",
            # MX-routed mailbox provider → the strong signal, via the flat field
            "mailbox_provider": "Microsoft 365",
            "platform_signals": [
                {"provider": "Google Workspace", "signal_type": "TXT",
                 "match_type": "regex", "confidence": 0.4,
                 "evidence": "google-site-verification=abc123"},
                # a non-platform token must be dropped, not rendered as a vendor
                {"provider": "SPF Policy", "signal_type": "TXT",
                 "match_type": "regex", "confidence": 0.3, "evidence": "v=spf1 -all"},
            ],
        },
    }
    r = HealthReportRenderer(vm, audience="flagship", legacy=legacy)
    vendors = r._build_vendor_list()
    names = [v["name"] for v in vendors]
    assert "Microsoft 365" in names and "Google Workspace" in names
    assert "SPF Policy" not in names          # stop-listed non-platform dropped
    # MX → confirmed and ranked ahead of the TXT-only Google Workspace
    ms = next(v for v in vendors if v["name"] == "Microsoft 365")
    goog = next(v for v in vendors if v["name"] == "Google Workspace")
    assert ms["confidence"] == "confirmed"
    assert goog["confidence"] == "indicative"
    assert names.index("Microsoft 365") < names.index("Google Workspace")
    # evidence pill carries the synthesised MX signal
    assert any(e["key"] == "MX" for e in ms["evidence"])
    assert any(e["key"] == "TXT" for e in goog["evidence"])


def test_no_annotation_falls_back_to_fingerprinting():
    """With no annotation block, the renderer uses the existing DNS/technographic
    fingerprinting path unchanged (regression guard)."""
    vm = _sample_vm()
    legacy = {"domain": "riskyexample.com",
              "dns_records": {"mx": [{"host": "riskyexample-com.mail.protection.outlook.com"}]}}
    r = HealthReportRenderer(vm, audience="flagship", legacy=legacy)
    assert not r.annotation.present
    vendors = r._build_vendor_list()
    assert any(v["name"] == "Microsoft 365" for v in vendors)


def _vm_with_funnel(funnel=None, own_brand=None, impersonations=None):
    """Build a view-model with a specific brand funnel / own-brand / platform set,
    for the free-report brand-page tests."""
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    return build_view_models(
        di,
        detected_platforms=["microsoft365"],
        impersonations=impersonations or [],
        own_brand=own_brand or BrandExposure(),
        brand_funnel=funnel or BrandFunnel(),
        findings=derive_findings(di, impersonations or []),
    )


def test_health_variant_empty_state_no_platform_leak():
    """The QBE case: no monitored history, a platform carries a large global count
    (the '157'), but the free brand page must show the empty-state funnel and never
    surface the platform-global figure as a brand claim."""
    impersonations = [PlatformImpersonation(platform="Google Workspace", count_7d=20, count_30d=157)]
    vm = _vm_with_funnel(own_brand=BrandExposure(count_30d=0), impersonations=impersonations)
    r = HealthReportRenderer(vm, audience="health", tier="teaser")
    bf = r._build_brand_funnel()
    assert bf["monitored"] is False and bf["present"] is False
    assert bf["own_brand_30d"] == 0
    # The brand page's data carries NO platform-global figure (the "157"): every
    # brand-scoped count is zero in the empty state.
    numeric = [bf["generated"], bf["registered"], bf["resolving"], bf["dga_flagged"], bf["own_brand_30d"]]
    assert 157 not in numeric and set(numeric) == {0}
    html = r.to_html()
    assert "not yet active" in html        # empty-state framing renders
    # platform-global counts are suppressed on the free variant: the "157" must
    # not appear anywhere in the rendered free report (cover/glance suppressed).
    assert "157" not in html


def test_health_variant_suppresses_platform_global_counts():
    """Cover + glance on the free `health` variant frame the detected stack as lures
    without citing the platform-global impersonation count; flagship still cites it."""
    impersonations = [PlatformImpersonation(platform="Google Workspace", count_7d=20, count_30d=157)]
    vm = _vm_with_funnel(own_brand=BrandExposure(count_30d=0), impersonations=impersonations)

    free = HealthReportRenderer(vm, audience="health", tier="teaser").to_html()
    assert "157" not in free
    assert "detected in your stack" in free                 # suppressed framing
    assert "Monitoring not yet active" in free              # honest brand scorecard

    # Flagship is unchanged — it still surfaces the platform-global activity.
    flagship = HealthReportRenderer(vm, audience="flagship", tier="full").to_html()
    assert "157" in flagship


def test_health_variant_renders_funnel_and_near_miss():
    funnel = BrandFunnel(
        candidates_generated=120, checked=50, registered=8, resolving=3, dga_flagged=1,
        near_miss=BrandCandidate(domain="qbeurope.com", status="nxdomain", registered=False),
        samples=[
            BrandCandidate(domain="qbe-support.com", status="resolving", has_cert=True),
            BrandCandidate(domain="qbeeurope-login.com", status="parked"),
        ],
    )
    vm = _vm_with_funnel(funnel=funnel)
    r = HealthReportRenderer(vm, audience="health", tier="teaser")
    html = r.to_html()
    assert "qbeurope.com" in html                 # near-miss shown
    assert "120" in html and "Patterns generated" in html
    assert "What Brand Impersonation Watch adds" in html   # §5 paid pitch
    assert "registrable now" in html or "registrable right now" in html
    md = r.to_markdown()
    assert "## Brand impersonation — active scan" in md
    assert "qbeurope.com" in md and "120" in md


def test_brand_guard_raises_on_platform_leak():
    """§7 guard: a brand count equal to a platform-global total with no brand-scoped
    evidence is the conflation bug — the renderer must refuse to render it."""
    impersonations = [PlatformImpersonation(platform="Google Workspace", count_30d=157)]
    # own_brand count == platform total, no samples, no funnel → must raise
    vm = _vm_with_funnel(own_brand=BrandExposure(count_30d=157), impersonations=impersonations)
    r = HealthReportRenderer(vm, audience="health", tier="full")
    import pytest
    with pytest.raises(ValueError, match="platform-global"):
        r._build_brand_funnel()


def test_brand_guard_allows_legit_brand_count():
    """A brand count backed by brand-scoped sample domains is legitimate even if it
    numerically coincides with a platform total — must NOT raise."""
    impersonations = [PlatformImpersonation(platform="Google Workspace", count_30d=3)]
    own = BrandExposure(count_30d=3, sample_domains=["qbe-login.com", "qbe-secure.net", "qbe-pay.com"])
    vm = _vm_with_funnel(own_brand=own, impersonations=impersonations)
    r = HealthReportRenderer(vm, audience="health", tier="full")
    bf = r._build_brand_funnel()          # does not raise
    assert bf["own_brand_30d"] == 3


def test_brand_funnel_teaser_masks_extra_candidates_keeps_near_miss():
    funnel = BrandFunnel(
        candidates_generated=10, near_miss=BrandCandidate(domain="qbeurope.com", status="nxdomain"),
        samples=[
            BrandCandidate(domain="qbeurope.com", status="nxdomain"),     # the near-miss — kept
            BrandCandidate(domain="qbe-payroll-login.com", status="resolving"),  # masked
        ],
    )
    vm = _vm_with_funnel(funnel=funnel)
    red = redact_for_teaser(vm)
    samples = {c.domain for c in red.external_threat.brand_funnel.samples}
    assert "qbeurope.com" in samples                      # near-miss survives in full
    assert "qbe-payroll-login.com" not in samples         # other candidate masked
    assert _mask_domain("qbe-payroll-login.com") in samples


_NARRATIVE = {
    "key_finding":          "KF: dangling CNAME on vpn exposes takeover.",
    "executive_summary":    "ES: composite driven by infrastructure risk.",
    "threat_narrative":     "TN: deep interpretive threat analysis here.",
    "positive_signals":     "PS: DMARC is enforced at reject.",
    "remediation_priority": "RP: 1) fix the dangling CNAME.",
    "insurer_signals":      "IS: direct premium-loading signal.",
    "saas_stack_analysis":  "SAAS: broad identity-heavy stack.",
}


def test_narrative_renders_and_respects_variant_keys():
    """The LLM narrative prose renders, gated by the variant's narrative_keys —
    flagship shows its favoured keys and withholds the rest even when present."""
    legacy = {"domain": "riskyexample.com", "narrative": _NARRATIVE}
    r = HealthReportRenderer(_sample_vm(), audience="flagship", tier="full", legacy=legacy)
    html = r.to_html()
    # flagship favours: key_finding, executive_summary, threat_narrative, positive_signals, remediation_priority
    for present in ("KF: dangling", "ES: composite", "TN: deep", "PS: DMARC", "RP: 1)"):
        assert present in html, present
    # flagship does NOT favour insurer_signals / saas_stack_analysis → must not render
    assert "IS: direct" not in html
    assert "SAAS: broad" not in html
    # markdown carries the favoured keys too
    md = r.to_markdown()
    assert "**Key finding.** KF: dangling" in md
    assert "**Threat analysis.** TN: deep" in md
    assert "IS: direct" not in md


def test_narrative_insurer_variant_shows_insurer_signals():
    legacy = {"domain": "riskyexample.com", "narrative": _NARRATIVE}
    html = HealthReportRenderer(_sample_vm(), audience="insurer", tier="full", legacy=legacy).to_html()
    assert "IS: direct" in html          # insurer favours insurer_signals


def test_narrative_teaser_keeps_hooks_only():
    """Teaser keeps key_finding + executive_summary (the lead-gen hooks); the
    deeper paid prose is withheld."""
    legacy = {"domain": "riskyexample.com", "narrative": _NARRATIVE}
    r = HealthReportRenderer(_sample_vm(), audience="flagship", tier="teaser", legacy=legacy)
    assert set(r.narrative) <= {"key_finding", "executive_summary"}
    html = r.to_html()
    assert "KF: dangling" in html and "ES: composite" in html
    assert "TN: deep" not in html and "RP: 1)" not in html


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

def test_external_threat_variant_is_one_compact_page():
    html = HealthReportRenderer(_sample_vm(), audience="external_threat").to_html()
    # a single dense page, not the 6-section deck
    assert html.count('class="page') == 1
    assert "Page 1 of 1" in html
    assert "External Threat Report" in html    # masthead label
    assert SENSITIVE_LURE in html              # impersonation facts still present
    assert "Who is impersonating" in html
    # none of the verbose shared sections leak in
    assert "Why attackers prefer trusted platforms" not in html
    assert "Certificate Transparency" not in html   # no glossary


def test_mx_outranks_txt_verification():
    """MX (live mail routing) → Microsoft 365 must outrank a Google Workspace
    TXT verification token, which is a weak/possibly-stale signal."""
    legacy = {
        "domain": "x.com",
        "dns_records": {
            "mx": [{"priority": 0, "host": "x-com.mail.protection.outlook.com"}],
            "txt": ["google-site-verification=abc123def"],
        },
        "txt_intelligence": {"identity_providers": ["Google Workspace"]},
    }
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = build_view_models(di, findings=derive_findings(di, []))
    r = HealthReportRenderer(vm, legacy=legacy)
    vendors = r._build_vendor_list()
    names = [v["name"] for v in vendors]
    assert names[0] == "Microsoft 365", names
    ms = vendors[0]
    assert ms["confidence"] == "confirmed" and any(e["key"] == "MX" for e in ms["evidence"])
    gw = next(v for v in vendors if v["name"] == "Google Workspace")
    assert gw["confidence"] == "indicative"     # TXT-only
    assert names.index("Google Workspace") > 0   # ranked below the MX-confirmed M365


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
