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
import re
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
    # 13 pages: the four-page external arc became one, plus the attack-economy page
    assert "Page 1 of 13" in html
    assert "Page 13 of 13" in html
    assert html.count('class="page') == 13
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


# ---------------------------------------------------------------------------
# A failed lookup must never render as an all-clear
# ---------------------------------------------------------------------------

def _unchecked_vm():
    """What the pipeline produces when the impersonation rollup is unreachable:
    zero counts, lookup_ok=False. Byte-identical to a clean result apart from
    the flag — which is the whole problem."""
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    return build_view_models(di, detected_platforms=["Google Workspace"],
                             impersonations=[], findings=derive_findings(di, []),
                             lookup_ok=False)


ALL_CLEARS = [
    "No active impersonation",
    "No lookalike domains",
    "no active campaign right now",
    "No live impersonation",
]


def test_failed_lookup_renders_no_all_clear():
    """Regression: the lake was down, every count came back 0, and the report told
    the customer "No active impersonation of your platforms in the last 30 days" —
    an all-clear built on a dropped database connection."""
    html = HealthReportRenderer(_unchecked_vm()).to_html()
    for claim in ALL_CLEARS:
        assert claim not in html, f"failed lookup still renders an all-clear: {claim!r}"
    assert "not checked" in html.lower()


def test_failed_lookup_markdown_says_not_checked():
    md = HealthReportRenderer(_unchecked_vm()).to_markdown()
    assert "No active impersonation" not in md
    assert "not checked" in md.lower()


def test_successful_empty_lookup_still_says_all_clear():
    """The other half: a lookup that ran and matched nothing IS an all-clear and
    must keep saying so — the flag distinguishes them, the counts cannot."""
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = build_view_models(di, detected_platforms=["Google Workspace"],
                           impersonations=[], findings=derive_findings(di, []))
    html = HealthReportRenderer(vm).to_html()
    assert "No active impersonation" in html


def test_failed_lookup_priority_makes_no_claim():
    r = HealthReportRenderer(_unchecked_vm())
    plat = next(p for p in r._build_priorities() if p["surface"] == "vendor")
    assert "No live impersonation" not in plat["action"]
    assert "not checked" in plat["title"].lower()


# ---------------------------------------------------------------------------
# External threat: one page, and it carries actions
# ---------------------------------------------------------------------------

def test_external_threat_is_a_single_page_with_the_data_and_actions():
    """The four-page external arc (why / vendor footprint / platform exposure /
    brand exposure) is one page. Three of those pages argued the general case and
    carried no domain-specific action, so they read the same for most domains."""
    html = HealthReportRenderer(_sample_vm()).to_html()
    assert html.count("Section 03 · External threat") == 1
    # the removed pages' headline copy is gone
    for gone in ("Why attackers prefer trusted platforms",
                 "Your stack, ordered by attacker preference",
                 "Active campaigns against your platforms",
                 "Attacks aimed at your customers"):
        assert gone not in html, f"four-page arc survives: {gone!r}"
    # but every piece of DATA those pages carried is still on the one page
    for kept in ("micros0ft-365-login.com",     # exact-match lure sample
                 "rnicrosoft365.com",           # fuzzy candidate sample
                 "riskyexample-support.com",    # own-brand lookalike
                 "41", "Platforms targeted", "Microsoft 365", "Okta", "Mailchimp"):
        assert kept in html, f"data lost in the merge: {kept!r}"
    # and it now tells the reader what to do, which the four pages never did
    assert "What to do" in html
    assert "Brief staff who use Microsoft 365" in html


def test_section_numbering_has_no_gaps():
    """Renumbering after the merge: a reader must not see 01 jump to 06."""
    import re
    html = HealthReportRenderer(_sample_vm()).to_html()
    nums = [int(n) for n in re.findall(r'class="section-num">Section (\d\d)<', html)]
    assert nums == sorted(nums), f"sections out of order: {nums}"
    assert nums == list(range(1, len(nums) + 1)), f"gap in section numbers: {nums}"


def test_every_section_reference_resolves():
    """Renumbering is easy to get wrong and invisible in a word count. Rather than
    ban particular numbers, derive the sections that exist and check every
    cross-reference in the copy against them."""
    html = HealthReportRenderer(_sample_vm()).to_html()
    body = re.sub(r"<style.*?</style>", "", html, flags=re.S)   # CSS comments aren't copy
    exists = {int(n) for n in re.findall(r'class="section-num">Section (\d\d)<', body)}
    assert exists, "no numbered sections found"
    referenced = {int(n) for n in re.findall(r"[Ss]ections?\s+(\d\d)\b", re.sub(r"<[^>]+>", " ", body))}
    dangling = referenced - exists
    assert not dangling, f"copy points at sections that do not exist: {sorted(dangling)} (have {sorted(exists)})"
    # and the page that was deleted must not be referred to by name
    assert "brand-exposure section" not in body


# ---------------------------------------------------------------------------
# Cover headline
# ---------------------------------------------------------------------------

def _clean_medallion() -> dict:
    """The sample domain is on a C2 feed, which now (correctly) leads the cover. To
    exercise the other branches the infrastructure has to be clean."""
    d = _load("medallion_sample.json")
    d["threat_feeds"] = {}
    d["routing"] = {**d.get("routing", {}), "rpki_state": "valid", "moas_detected": False}
    d["risk_assessment"] = {**d.get("risk_assessment", {}), "reason_codes": []}
    d["domain_dns_facts"] = {**d.get("domain_dns_facts", {}), "is_dangling_cname": False}
    d["certstream"] = {"hits": 0}
    d["concentration"] = {"pivot_findings": []}
    return d


def _hook(imps=None, own=None, lookup_ok=True, platforms=("microsoft365",), audience="flagship",
          medallion=None):
    di = DomainIntelligence.model_validate(medallion or _clean_medallion())
    vm = build_view_models(di, detected_platforms=list(platforms), impersonations=imps or [],
                           own_brand=own or BrandExposure(), findings=derive_findings(di, imps or []),
                           lookup_ok=lookup_ok)
    return HealthReportRenderer(vm, audience=audience)._cover_hook()


def test_cover_leads_with_the_most_serious_finding_not_the_most_marketable():
    """A domain on an active command-and-control feed has a bigger problem than
    lookalike domains. Leading with the impersonation count would bury it."""
    imps = [PlatformImpersonation(platform="microsoft365", count_7d=14, count_30d=41)]
    h = _hook(imps=imps, medallion=_load("medallion_sample.json"))   # C2-listed sample
    assert "Immediate investigation" in h["title"]
    assert "Feodo" in h["title"] or "Feodo" in h["deck"]
    # the impersonation is still reported, as secondary
    assert "41" in h["deck"] or "lookalike" in h["deck"]


def test_cover_lead_does_not_lowercase_an_acronym():
    d = _load("medallion_sample.json")
    d["threat_feeds"] = {}                      # leave RPKI invalid as the top finding
    h = _hook(medallion=d)
    assert "rPKI" not in h["title"], "acronym mangled by the lowercasing rule"


def test_cover_headline_leads_with_this_domains_numbers():
    """A cover that could sit on any report is a weak cover. It leads with a count."""
    imps = [PlatformImpersonation(platform="microsoft365", count_7d=14, count_30d=41)]
    h = _hook(imps=imps)
    assert "41" in h["title"] or "41" in h["deck"]
    assert "Microsoft 365" in h["deck"]          # display name, not the raw key
    assert "microsoft365" not in h["deck"]


def test_cover_headline_claims_nothing_when_the_lookup_failed():
    """The cover is the most-read line in the report; a failed lookup must not
    become a quiet all-clear there either."""
    h = _hook(imps=[], lookup_ok=False, platforms=("microsoft365", "okta"))
    assert "could not run" in h["deck"]
    for claim in ("None are being imitated", "no active", "No active"):
        assert claim not in h["deck"] and claim not in h["title"]


def test_cover_headline_all_clear_only_when_checked():
    h = _hook(imps=[], lookup_ok=True, platforms=("microsoft365", "okta"))
    assert "None are being imitated today" in h["deck"]


def test_cover_headline_free_tier_never_cites_a_platform_global_count():
    """The '157' must not reach the free cover, even as a headline number."""
    imps = [PlatformImpersonation(platform="Google Workspace", count_7d=20, count_30d=157)]
    h = _hook(imps=imps, audience="health")
    assert "157" not in h["title"] and "157" not in h["deck"]


def test_attack_economy_page_is_present_and_honest():
    """The free report's strongest context page, ported. Industry figures must stay
    labelled as industry figures — this page is the one place the report cites
    numbers it did not measure."""
    html = HealthReportRenderer(_sample_vm()).to_html()
    assert "How the cyber attack economy works." in html
    assert "spray and pray" in html
    assert "$10.5 trillion" in html
    assert "Industry context, not a Datazag measurement" in html, \
        "the cited figure must not read as a Datazag observation"
    # it names the reader's own top platform rather than a generic example
    assert "everyone who uses Microsoft 365" in html


def test_free_tier_gets_context_without_platform_global_counts():
    """The free tier suppresses platform-global impersonation counts
    (brand_page_data_contract.md). It gets this context page, which cites only
    industry figures, and NOT the external page, which reports those counts."""
    html = HealthReportRenderer(_sample_vm(), audience="health").to_html()
    assert "How the cyber attack economy works." in html
    assert "Section 03 · External threat" not in html


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
    # Landmark on each PAGE's own h1: the contents lists these titles too, so a
    # plain index() can match the table of contents instead of the section.
    glossary = html.index("Plain-English definitions.")
    assert roadmap < rem < glossary, (
        f"pages out of order: roadmap@{roadmap} remediation@{rem} glossary@{glossary}")
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
