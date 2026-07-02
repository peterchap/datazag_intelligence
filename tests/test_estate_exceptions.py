"""Tests for the rule-based cross-estate exception register."""

from __future__ import annotations

from datetime import datetime, timezone

from estate_helpers import ESTATE_MANIFEST  # noqa: E402

from crossestate.build import build_estate_from_manifest  # noqa: E402

NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)
_FINDING_KEYS = {"finding", "severity", "title", "evidence", "detail",
                 "remediation", "category", "scope", "members"}


def _estate():
    return build_estate_from_manifest(ESTATE_MANIFEST, now=NOW)


def test_exceptions_have_finding_dict_shape():
    e = _estate()
    assert e.exceptions
    for x in e.exceptions:
        assert _FINDING_KEYS.issubset(set(x.model_dump().keys()))
        assert x.severity in ("critical", "high", "elevated", "medium", "low", "info")


def test_exceptions_sorted_most_severe_first():
    e = _estate()
    order = {"critical": 0, "high": 1, "elevated": 2, "medium": 3, "low": 4, "info": 5}
    sev = [order[x.severity] for x in e.exceptions]
    assert sev == sorted(sev)


def test_expected_rules_fire_on_fixture_estate():
    e = _estate()
    findings = {x.finding for x in e.exceptions}
    assert "estate_concentration" in findings         # dominant provider
    assert "posture_outlier_segment" in findings       # acquired segment
    assert "active_impersonation" in findings          # exact impersonations
    assert "overdue_lapses" in findings                # expired domain/cert
    assert "red_domains" in findings                   # E/F grades
    assert "segment_tag_disagreement" in findings      # acmeretail apex conflict


def test_clustered_weakness_is_segment_scoped():
    e = _estate()
    clustered = [x for x in e.exceptions if x.finding.startswith("clustered_")]
    assert clustered
    for x in clustered:
        assert x.scope == "segment" and x.members


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
