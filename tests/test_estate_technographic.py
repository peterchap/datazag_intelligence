"""
tests/test_estate_technographic.py
----------------------------------
The SPF-observed technographic layer: the matcher, the honest denominator, the
minimum-coverage withholding, the exception's `members`, and — the one that matters most —
the pin that the technographic ⟂ impersonation join can NEVER suppress or downgrade an
alert.
"""

from __future__ import annotations

import pytest

from tests.estate_helpers import make_ref  # noqa: F401  (adds repo root to sys.path)

from crossestate.analytics import compute_concentration, compute_exposure
from crossestate.contract import EstateThresholds, EstateViewModel, Segment
from crossestate.exceptions import derive_estate_exceptions
from crossestate.technographic import (
    identity_critical,
    load_fingerprints,
    match_target,
    observability,
    signals_for,
    spf_terms,
)
from intelligence_contract import PlatformImpersonation


# ── the matcher ───────────────────────────────────────────────────────────────

def test_fingerprint_export_is_present_and_non_trivial():
    fps = load_fingerprints()
    assert len(fps) > 400
    assert any(f.signal_type == "SPF_INCLUDE" for f in fps)


def test_suffix_respects_the_label_boundary():
    """A bare endswith matched `notzoho.com` against the `zoho.com` fingerprint. The
    label-boundary rule is what makes `suffix` mean 'this host or a host under it'."""
    assert match_target("spf.zoho.com").provider == "Zoho Mail"
    assert match_target("zoho.com").provider == "Zoho Mail"
    assert match_target("notzoho.com") is None


def test_exact_separates_the_consumer_tier_from_m365():
    assert match_target("spf.protection.outlook.com").provider == "Microsoft 365"
    assert match_target("outlook.com").provider == "Outlook.com"


def test_longest_pattern_wins():
    """`qiye.aliyun.com` is Alibaba Mail even though shorter aliyun rows exist."""
    assert match_target("qiye.aliyun.com").provider == "Alibaba Mail"
    assert match_target("dm.aliyun.com").provider == "Alibaba DirectMail"


def test_macro_bearing_include_is_matched():
    """The enterprise tier publishes SPF delegation as a macro expansion. The corpus
    producer's `[a-z0-9._-]+` class drops these entirely, so a technographic layer built
    on `gold.dns_wide.spf_includes` reports 'no gateway observed' for exactly the
    population these reports are sold into."""
    spf = "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all"
    sigs = signals_for("ibm.com", spf)
    assert [s.provider for s in sigs] == ["Proofpoint"]
    assert sigs[0].identity_risk == "high"


def test_redirect_and_exists_mechanisms_are_read():
    assert signals_for("x.com", "v=spf1 redirect=_spf.google.com")[0].provider == "Google Workspace"
    assert signals_for("x.com", "v=spf1 exists:%{i}.spf.hc4673-96.iphmx.com -all")[0].provider \
        == "Cisco Secure Email"


def test_self_referential_shards_are_not_a_vendor():
    """'adidas.com uses adidas.com' is not a technographic fact, and counting it would
    put every self-hosting enterprise into the denominator with a junk value."""
    assert spf_terms("v=spf1 include:spf1.adidas.com include:spf2.adidas.com -all",
                     "adidas.com") == []
    assert signals_for("merck.com", "v=spf1 include:spf1.merck.com include:spf2.merck.com ~all") == []


def test_a_and_mx_mechanisms_are_not_vendor_claims():
    assert spf_terms("v=spf1 a:mail.example.net mx:mx.example.net -all", "x.com") == []


# ── observability: the four genuinely different reasons for an empty stack ─────

@pytest.mark.parametrize("spf,expected", [
    (None, "no_spf"),
    ("", "no_spf"),
    ("v=spf1 ip4:198.241.162.0/24 -all", "no_referral"),
    ("v=spf1 include:spf1.self.com -all", "no_referral"),          # self only
    ("v=spf1 include:_spf.some-unknown-vendor-xyz.example -all", "unattributed"),
    ("v=spf1 include:spf.protection.outlook.com -all", "attributed"),
])
def test_observability_states(spf, expected):
    assert observability("self.com", spf) == expected


# ── the concentration dimension ───────────────────────────────────────────────

_M365 = "v=spf1 include:spf.protection.outlook.com -all"
_PFPT = "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all"
_IPONLY = "v=spf1 ip4:203.0.113.0/24 -all"


def _refs(spec):
    """spec: list of (domain, spf_record)."""
    out = []
    for dom, spf in spec:
        r = make_ref(dom, "seg")
        r.vm.hygiene.spf_record = spf
        out.append(r)
    return out


def _dim(refs, th=None):
    th = th or EstateThresholds()
    return next(d for d in compute_concentration(refs, th) if d.dimension == "technographic")


def test_unobservable_domains_are_excluded_from_the_denominator_not_scored():
    """The rule the whole layer turns on: an unscanned/unobservable domain leaves the
    denominator, it is never scored as 'uses nothing'."""
    refs = _refs([("a.com", _PFPT), ("b.com", _PFPT), ("c.com", _IPONLY), ("d.com", None)])
    d = _dim(refs)
    assert d.denom == 2                      # not 4
    assert d.top_provider == "Proofpoint"
    assert d.top_pct == 1.0
    assert d.coverage_pct == 0.5
    assert "excluded from the denominator" in d.note


def test_thin_dimension_is_withheld_rather_than_rendered():
    """A 100% share computed on 1 of 10 domains is a real number about an
    unrepresentative subset. It must not render."""
    refs = _refs([("a.com", _PFPT)] + [(f"x{i}.com", _IPONLY) for i in range(9)])
    d = _dim(refs)
    assert d.withheld is True
    assert d.shares == [] and d.top_pct == 0.0 and d.flagged is False
    assert "Not a finding of absence" in d.note
    assert d.denom == 1 and d.coverage_pct == pytest.approx(0.1)


def test_withheld_dimension_emits_no_exception():
    refs = _refs([("a.com", _PFPT)] + [(f"x{i}.com", _IPONLY) for i in range(9)])
    est = _estate(refs)
    assert not [e for e in derive_estate_exceptions(est)
                if e.finding.startswith("technographic")]


def test_flag_fires_at_the_shared_threshold_and_names_the_domains():
    refs = _refs([("a.com", _PFPT), ("b.com", _PFPT), ("c.com", _M365), ("d.com", _M365),
                  ("e.com", _M365)])
    d = _dim(refs)
    assert d.withheld is False and d.denom == 5
    assert d.top_provider == "Microsoft 365" and d.top_pct == pytest.approx(0.6)
    assert d.flagged is True


def _estate(refs, th=None):
    th = th or EstateThresholds()
    est = EstateViewModel(group="g", thresholds=th, domain_count=len(refs),
                          assessed_count=len(refs),
                          segments=[Segment(key="seg", n_domains=len(refs), domains=refs)])
    est.concentration = compute_concentration(refs, th)
    est.exposure = compute_exposure(refs, th)
    return est


def test_exception_carries_the_affected_domains_so_it_can_inherit_materiality():
    """`scope="domain"` + `members` is what DILIGENCE_CUT_SPEC sums `limit` over to
    produce 'affects N% of portfolio value'."""
    refs = _refs([("a.com", _PFPT), ("b.com", _PFPT), ("c.com", _PFPT), ("d.com", _M365)])
    exc = [e for e in derive_estate_exceptions(_estate(refs))
           if e.finding == "technographic_concentration"]
    assert len(exc) == 1
    e = exc[0]
    assert e.scope == "domain"
    assert e.members == ["a.com", "b.com", "c.com"]
    assert "Proofpoint" in e.title


def test_identity_critical_selects_only_the_high_tier():
    sigs = signals_for("x.com", "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com "
                                "include:spf.protection.outlook.com -all")
    assert {s.provider for s in sigs} == {"Proofpoint", "Microsoft 365"}
    assert [s.provider for s in identity_critical(sigs)] == ["Proofpoint"]


# ── 🚨 THE PIN: the join ranks exposure, it never suppresses it ────────────────

def _imp(platform, c7, c30):
    return PlatformImpersonation(platform=platform, count_7d=c7, count_30d=c30,
                                 confidence="exact", sample_domains=[f"evil-{platform}.com"])


def test_stack_join_annotates_without_suppressing_or_reordering():
    """A DocuSign phish lands on staff at companies that do not use DocuSign. The join
    may weight, rank and explain exposure; it must never gate it. Relaxing this is the
    2.5%-precision failure `cc-task-pi-platform-scoring.md` opens by naming, and it would
    inherit every coverage gap in technographic.py as a silent false negative."""
    refs = _refs([("a.com", _PFPT), ("b.com", _PFPT)])
    # a.com is targeted by a platform it does NOT use, and by one it does.
    refs[0].vm.external_threat.impersonations = [_imp("DocuSign", 4, 40), _imp("Proofpoint", 1, 10)]

    baseline = compute_exposure(refs, EstateThresholds())
    order = [p.platform for p in baseline.by_platform]
    counts = {p.platform: (p.count_7d, p.count_30d, p.targeted_domains)
              for p in baseline.by_platform}

    # The unmatched platform is STILL THERE, at its full count, in its original position.
    assert "DocuSign" in order
    assert order == ["DocuSign", "Proofpoint"]          # ranked by volume, not by stack
    assert counts["DocuSign"] == (4, 40, 1)
    assert baseline.total_30d == 50 and baseline.total_7d == 5

    by = {p.platform: p for p in baseline.by_platform}
    assert by["DocuSign"].in_estate_stack is False       # annotation only
    assert by["Proofpoint"].in_estate_stack is True
    assert by["Proofpoint"].stack_identity_risk == "high"
    assert by["Proofpoint"].stack_domains == ["a.com", "b.com"]

    # The matched volume is carried PARALLEL — never subtracted from the headline.
    assert baseline.stack_matched_30d == 10
    assert baseline.total_30d == 50


def test_totals_are_identical_with_and_without_an_observable_stack():
    """The strongest form of the pin: strip the estate's entire technographic stack and
    every exposure number must be unchanged."""
    with_stack = _refs([("a.com", _PFPT)])
    with_stack[0].vm.external_threat.impersonations = [_imp("DocuSign", 4, 40),
                                                       _imp("Proofpoint", 1, 10)]
    without = _refs([("a.com", _IPONLY)])
    without[0].vm.external_threat.impersonations = [_imp("DocuSign", 4, 40),
                                                    _imp("Proofpoint", 1, 10)]

    a = compute_exposure(with_stack, EstateThresholds())
    b = compute_exposure(without, EstateThresholds())
    assert (a.total_7d, a.total_30d) == (b.total_7d, b.total_30d)
    assert [p.platform for p in a.by_platform] == [p.platform for p in b.by_platform]
    assert [p.count_30d for p in a.by_platform] == [p.count_30d for p in b.by_platform]
    assert a.targeting_concentration == b.targeting_concentration


def test_unmeasured_platforms_are_named_rather_than_read_as_zero():
    """M365 and Google Workspace are absent from the certstream `platform_hits`
    dictionary. Their exposure is UNMEASURED, not low, and the contract says so."""
    e = compute_exposure(_refs([("a.com", _M365)]), EstateThresholds())
    assert "Microsoft 365" in e.unmeasured_platforms
    assert "Google Workspace" in e.unmeasured_platforms


# ── the dead producer this pass reconnected ───────────────────────────────────

def test_lake_enrich_now_populates_platform_signals():
    """`Annotation.platform_signals` was declared on the contract and read by
    healthreport/renderer.py and freereport/compose.py, but PRODUCED BY NOTHING: verified
    2026-08-24 as empty on all 18 contracts of a collected estate. `_labels_fallback`
    reproduced `v_annotated` per-domain and never reproduced `v_technographic`."""
    from lake_enrich import to_view_models
    vms = to_view_models({"domain": "ibm.com",
                          "spf": "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all"},
                         {"labels": {}, "infra": {}})
    sigs = vms["annotation"].platform_signals
    assert [s.provider for s in sigs] == ["Proofpoint"]
    assert sigs[0].signal_type == "SPF_INCLUDE"
