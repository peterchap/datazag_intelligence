"""
test_intelligence_contract.py
-----------------------------
Regression guard for the riskscore -> report contract boundary.

Runs under pytest (`pytest tests/test_intelligence_contract.py`) or standalone
(`python tests/test_intelligence_contract.py`).
"""

from __future__ import annotations

import json
import os
import sys

# allow importing repo-root modules when run from tests/
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from intelligence_contract import (  # noqa: E402
    BrandExposure,
    DomainIntelligence,
    PlatformImpersonation,
    build_view_models,
)
from findings_rules import derive_findings  # noqa: E402

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _sample() -> DomainIntelligence:
    return DomainIntelligence.model_validate(_load("medallion_sample.json"))


def _impersonations() -> tuple[list[PlatformImpersonation], BrandExposure]:
    data = _load("platform_impersonation_sample.json")
    imps = [PlatformImpersonation.model_validate(p) for p in data["platforms"]]
    own = BrandExposure.model_validate(data["own_brand"])
    return imps, own


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_parse_sample():
    di = _sample()
    assert di.has_intelligence
    assert di.domain == "riskyexample.com"
    assert di.threat_feeds.feodo.listed is True
    assert di.threat_feeds.listed_feeds() == ["feodo"]
    assert di.risk_assessment.worst_subscore() == 0.8  # dangling_cname_risk


def test_parse_partial_defaults():
    di = DomainIntelligence.model_validate(_load("medallion_partial.json"))
    assert di.has_intelligence
    # missing nested structs default rather than raise
    assert di.routing.rpki_state == "unknown"
    assert di.email_security.mx_type == "unknown"
    assert di.concentration.pivot_findings == []
    # reason_codes None -> []
    assert di.risk_assessment.reason_codes == []


def test_parse_nxdomain():
    di = DomainIntelligence.model_validate(_load("medallion_nxdomain.json"))
    assert di.is_error
    assert di.code == 404
    assert not di.has_intelligence


def test_scale_clamping():
    di = DomainIntelligence.model_validate({
        "schema_version": "1.0", "domain": "x.test",
        "risk_assessment": {"infra_score": 5.0, "dga_risk": -2.0},
        "email_security": {"mx_risk_score": 9.9},
    })
    assert di.risk_assessment.infra_score == 1.0
    assert di.risk_assessment.dga_risk == 0.0
    assert di.email_security.mx_risk_score == 1.0


# ---------------------------------------------------------------------------
# Field coverage (drift guard): every path the renderer/narrative reads must
# resolve on the parsed model.
# ---------------------------------------------------------------------------

READ_PATHS = [
    "domain", "generated_at", "data_freshness",
    "facts.asn", "facts.prefix", "facts.is_manrs_member", "facts.manrs_status",
    "facts.is_manrs_culprit",
    "routing.moas_detected", "routing.prefixes_churn_total", "routing.rpki_state",
    "email_security.mx_type", "email_security.mx_risk_score", "email_security.dmarc_risk",
    "email_security.spf_risk", "email_security.modern_security_present",
    "threat_feeds.feodo.listed", "threat_feeds.urlhaus.listed", "threat_feeds.sslbl.listed",
    "threat_feeds.threatfox.listed", "threat_feeds.spamhaus.listed",
    "certstream.hits",
    "concentration.pivot_findings",
    "domain_dns_facts.lowest_ttl", "domain_dns_facts.a_record_count",
    "domain_dns_facts.is_dangling_cname", "domain_dns_facts.cname_target",
    "domain_dns_facts.dga_entropy",
    "historical_velocity.ip_changes_30d", "historical_velocity.asn_diversity_30d",
    "historical_velocity.geo_diversity_30d", "historical_velocity.ip_churn_score",
    "risk_assessment.infra_score", "risk_assessment.ip_direct_threat_score",
    "risk_assessment.reason_codes", "risk_assessment.fast_flux_risk",
    "risk_assessment.dga_risk", "risk_assessment.concentration_risk",
    "risk_assessment.certstream_risk", "risk_assessment.dangling_cname_risk",
]


def test_field_coverage():
    di = _sample()
    missing = []
    for path in READ_PATHS:
        obj = di
        for part in path.split("."):
            if not hasattr(obj, part):
                missing.append(path)
                break
            obj = getattr(obj, part)
    assert not missing, f"contract missing fields the renderer reads: {missing}"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def test_findings_thresholds():
    di = _sample()
    imps, _ = _impersonations()
    findings = derive_findings(di, imps)
    by_key = {f["finding"]: f for f in findings}

    # threat pillar
    assert by_key["fast_flux_detected"]["severity"] == "high"          # 0.7
    assert "dga_pattern_detected" in by_key                            # 0.65
    assert "malicious_concentration" in by_key                         # 0.75
    assert "certstream_domain_risk" in by_key                          # 0.6
    assert by_key["corpus_dangling_cname_risk"]["severity"] == "high"
    assert by_key["threat_feed_feodo"]["severity"] == "critical"
    assert "certstream_infra_hit" in by_key
    assert by_key["cotenancy_asn_64500"]["severity"] == "high"         # 30 >= 25
    assert "high_ip_churn" in by_key                                   # 0.7

    # trust pillar
    assert by_key["no_dmarc_enforcement"]["severity"] == "high"
    assert by_key["rpki_invalid"]["severity"] == "critical"
    assert "moas_anomaly" in by_key

    # external threat
    assert by_key["platform_impersonation_microsoft365"]["severity"] == "high"  # 41
    assert by_key["platform_impersonation_okta"]["severity"] == "high"          # 25
    assert by_key["platform_impersonation_mailchimp"]["severity"] == "info"     # 4

    # reason-code passthrough — nothing dropped, including unmapped codes
    assert "reason_high_bgp_churn" in by_key
    assert "reason_some_new_unmapped_code" in by_key


def test_findings_empty_on_nxdomain():
    di = DomainIntelligence.model_validate(_load("medallion_nxdomain.json"))
    assert derive_findings(di, []) == []


# ---------------------------------------------------------------------------
# View-model / scoring
# ---------------------------------------------------------------------------

def test_view_model_scoring():
    di = _sample()
    imps, own = _impersonations()
    findings = derive_findings(di, imps)
    vm = build_view_models(di, ["microsoft365", "okta", "mailchimp"], imps, own, findings)

    assert vm.has_intelligence
    assert vm.composite_score >= 80
    assert vm.grade.letter in ("E", "F")
    assert vm.trust.score > 0 and vm.threat.score > 0
    assert vm.threat.listed_feeds == ["feodo"]
    # platform impersonations only — own-brand is reported separately
    assert vm.external_threat.total_30d == 41 + 25 + 4
    assert vm.external_threat.own_brand.count_30d == 3
    assert vm.findings  # carried through


def test_view_model_nxdomain_not_all_clear():
    di = DomainIntelligence.model_validate(_load("medallion_nxdomain.json"))
    vm = build_view_models(di, [], [], BrandExposure(), [])
    assert vm.has_intelligence is False
    assert vm.grade.letter == "?"     # not a misleading "A"
    assert vm.findings == []


def test_impersonation_trend():
    # 14 in 7d vs prior weekly avg (41-14)/3 = 9.0 -> up
    assert PlatformImpersonation(platform="ms", count_7d=14, count_30d=41).trend == "up"
    # 2 in 7d vs (25-2)/3 = 7.67 -> down
    assert PlatformImpersonation(platform="okta", count_7d=2, count_30d=25).trend == "down"


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
