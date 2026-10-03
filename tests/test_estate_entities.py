"""
tests/test_estate_entities.py
-----------------------------
Phase 2 (docs/report-editions/PLAN.md §4): the estate spec, the owner kept out of
its own estate, and the entities[] model.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from crossestate.estate_spec import EstateSpec, load_estate_spec  # noqa: E402
from tests.estate_helpers import make_ref, no_observatory  # noqa: E402

NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)
OSNEY = os.path.join(_ROOT, "fixtures", "osney", "estate.yaml")


# ── estate spec ─────────────────────────────────────────────────────────────

def test_osney_spec_loads_owner_and_thirteen_entities():
    spec = load_estate_spec(OSNEY)
    assert spec.owner.name == "Osney Capital" and spec.owner.domain == "osneycapital.com"
    assert len(spec.entities) == 13
    rows = spec.manifest_rows()
    assert len(rows) == 14
    assert [r for r in rows if r["role"] == "owner"] == [
        {"domain": "osneycapital.com", "entity": "Osney Capital", "role": "owner",
         "primary": True, "contract_path": "contracts/osneycapital.com.json"}]
    assert {r["entity"] for r in rows if r["domain"] == "ploy.io"} == {"Ploy"}


def test_a_domain_cannot_belong_to_two_entities():
    with pytest.raises(ValueError):
        EstateSpec.model_validate({"entities": [{"name": "A", "domain": "x.com"},
                                                {"name": "B", "domain": "y.com",
                                                 "domains": ["x.com"]}]})


def test_bad_domain_is_rejected():
    with pytest.raises(ValueError):
        EstateSpec.model_validate({"entities": [{"name": "A", "domain": "not a domain"}]})


def test_manifest_doc_keeps_spec_fields_and_owner_and_drops_failures():
    from estate_collect import manifest_doc
    spec = load_estate_spec(OSNEY)
    statuses = {r["domain"]: "ok" for r in spec.manifest_rows()}
    statuses["aviel.tech"] = "error"
    doc = manifest_doc("Osney Capital", spec.manifest_rows(), statuses, spec.owner_block())
    assert doc["owner"] == {"name": "Osney Capital", "domain": "osneycapital.com"}
    assert len(doc["domains"]) == 13
    assert not any(d["domain"] == "aviel.tech" for d in doc["domains"])
    assert all("segment" not in d for d in doc["domains"])      # left for inference


# ── owner exclusion ─────────────────────────────────────────────────────────

def _write_estate(refs_roles, owner=None):
    """[(ref, role, entity)] -> (manifest path, tempdir). Real files, real loader."""
    d = tempfile.mkdtemp()
    rows = []
    for ref, role, entity in refs_roles:
        p = os.path.join(d, f"{ref.domain}.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(ref.vm.model_dump(mode="json"), fh)
        rows.append({"domain": ref.domain, "contract_path": p, "role": role, "entity": entity})
    doc = {"group": "g", "domains": rows}
    if owner:
        doc["owner"] = owner
    m = os.path.join(d, "manifest.json")
    with open(m, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return m


def _owner_estate():
    # The owner is deliberately the WORST domain, on a provider nobody else uses,
    # with an expiry and no lock, so any leak shows up in every aggregate.
    owner = make_ref("osneycapital.com", "x", score=80, dmarc="none", caa=False, dnssec=False,
                     ns="OwnerDNS", registrar="Amazon Registrar", mailbox="OwnerMail",
                     status="ok", expires="2026-07-10")
    a = make_ref("ploy.io", "x", score=10, ns="Cloudflare", registrar="GoDaddy", mailbox="Google")
    b = make_ref("aisy.ai", "x", score=12, ns="Cloudflare", registrar="GoDaddy", mailbox="Google")
    return _write_estate([(owner, "owner", "Osney Capital"), (a, "portfolio", "Ploy"),
                          (b, "portfolio", "Aisy")],
                         owner={"name": "Osney Capital", "domain": "osneycapital.com"})


def test_owner_is_excluded_from_every_estate_aggregate():
    from crossestate.build import build_estate_from_manifest
    mvp = build_estate_from_manifest(_owner_estate(), now=NOW)
    assert mvp.owner == {"name": "Osney Capital", "domain": "osneycapital.com"}
    assert [r.domain for r in mvp.owner_refs] == ["osneycapital.com"]
    assert mvp.domain_count == mvp.assessed_count == 2
    assert sum(mvp.grade_distribution.values()) == 2
    assert all(d.domain != "osneycapital.com" for s in mvp.segments for d in s.domains)
    for dim in mvp.concentration:
        assert dim.denom <= 2
        assert all(sh.provider not in ("OwnerDNS", "OwnerMail", "Amazon Registrar")
                   for sh in dim.shares)
    assert all(w.n_assessed == 2 for w in mvp.correlated_weakness)
    assert not any(it.domain == "osneycapital.com" for it in mvp.calendar.items)


def test_owner_is_excluded_from_the_report_grade_and_worksheet():
    from estatereport.build import build_estate_report_from_manifest
    rep = build_estate_report_from_manifest(_owner_estate(), now=NOW, observatory=no_observatory())
    assert rep.grade.domain_count == 2
    assert rep.discovery.declared_count == 2
    assert all(e.domain != "osneycapital.com" for p in rep.remediation for e in p.entries)


# ── controls vocabulary ─────────────────────────────────────────────────────

from estatereport.controls import CONTROL_ORDER, VOCAB, controls_for  # noqa: E402
from intelligence_contract import DnsHygiene, DnsRecordSet, PlatformSignal  # noqa: E402


def _vm(**hyg):
    vm = make_ref("x.com", "s").vm
    vm.hygiene = DnsHygiene(**hyg)
    return vm


@pytest.mark.parametrize("hyg,control,expected", [
    ({"dmarc_policy": "reject"}, "dmarc", "reject"),
    ({"dmarc_policy": "none", "dmarc_record": "v=DMARC1; p=none"}, "dmarc", "monitor"),
    ({}, "dmarc", "missing"),
    ({"dmarc_record": "v=DMARC1; rua=mailto:x@y"}, "dmarc", "invalid"),
    ({"spf_record": "v=spf1 include:_spf.google.com -all"}, "spf", "hardfail"),
    ({"spf_record": "v=spf1 include:_spf.google.com ~all"}, "spf", "softfail"),
    ({"spf_record": "v=spf1 ?all"}, "spf", "neutral"),
    ({"spf_record": "v=spf1 +all"}, "spf", "permissive"),
    ({"spf_record": "v=spf1 redirect=_spf.example.com"}, "spf", "delegated"),
    ({}, "spf", "missing"),
    ({"mta_sts_mode": "enforce"}, "mta_sts", "enforce"),
    ({"mta_sts_txt_present": True}, "mta_sts", "invalid"),
    ({}, "mta_sts", "missing"),
    ({"bimi_present": True}, "bimi", "present"),
])
def test_control_values(hyg, control, expected):
    assert controls_for(_vm(**hyg))[control] == expected


def test_every_control_uses_its_fixed_vocabulary():
    for kw in ({}, {"dmarc_policy": "quarantine", "spf_record": "v=spf1 -all", "caa_present": True,
                    "dnssec": True, "mta_sts_mode": "testing", "bimi_present": True}):
        ctl = controls_for(_vm(**kw))
        assert tuple(ctl) == CONTROL_ORDER
        assert all(ctl[c] in VOCAB[c] for c in CONTROL_ORDER)


def test_unassessed_domain_is_unknown_on_every_control_never_missing():
    vm = make_ref("x.com", "s", has_intel=False).vm
    assert set(controls_for(vm).values()) == {"unknown"}
    vm = make_ref("y.com", "s").vm
    assert set(controls_for(vm, load_error="live DNS scan did not finish").values()) == {"unknown"}


def test_registrar_lock_unknown_when_rdap_gave_no_status():
    assert controls_for(make_ref("x.com", "s", status=None).vm)["registrar_lock"] == "unknown"
    assert controls_for(make_ref("x.com", "s", status="ok").vm)["registrar_lock"] == "unlocked"
    assert controls_for(make_ref("x.com", "s", status="client transfer prohibited").vm)[
        "registrar_lock"] == "locked"


def test_controls_doc_lists_every_vocabulary_value():
    with open(os.path.join(_ROOT, "docs", "report-editions", "controls.md"), encoding="utf-8") as fh:
        doc = fh.read()
    for control, values in VOCAB.items():
        assert f"`{control}`" in doc, control
        for v in values:
            assert f"`{v}`" in doc, f"{control}: {v}"


# ── entities[] ──────────────────────────────────────────────────────────────

def _report(path=None, corpus_index=None):
    from estatereport.build import build_estate_report_from_manifest
    from crossestate.build import build_estate_from_manifest
    from estatereport.build import build_estate_report
    mvp = build_estate_from_manifest(path or _owner_estate(), now=NOW)
    return build_estate_report(mvp, now=NOW, observatory=no_observatory(),
                               corpus_index=corpus_index)


def test_entities_owner_first_then_portfolio_each_graded_with_seven_controls():
    rep = _report()
    assert rep.owner.name == "Osney Capital"
    assert [(e.name, e.role) for e in rep.entities] == [
        ("Osney Capital", "owner"), ("Aisy", "portfolio"), ("Ploy", "portfolio")]
    for e in rep.entities:
        assert e.grade and e.score is not None
        assert tuple(e.controls) == CONTROL_ORDER
        assert e.records[0].primary and e.records[0].domain == e.primary_domain
    owner = rep.entities[0]
    assert owner.top_issue == "No registrar lock"           # urgency order: lock first
    assert owner.cert_issues == [] and owner.domains == ["osneycapital.com"]


def test_owner_calendar_rows_reach_only_the_owner_record():
    rep = _report()
    assert not any(c.domain == "osneycapital.com" for c in rep.calendar)


def _vm_surface():
    ref = make_ref("ploy.io", "s", mailbox="Google Workspace", subs=[
        {"dns_name": "auth.ploy.io"}, {"dns_name": "staging-api.ploy.io"},
        {"dns_name": "www.ploy.io"}, {"dns_name": "*.ploy.io"}, {"dns_name": "ploy.io"},
        {"dns_name": "dev2.eu.ploy.io"}, {"dns_name": "other.com"}])
    ref.vm.dns_records = DnsRecordSet(mx=["10 ploy-io.mail.protection.outlook.com"])
    ref.vm.annotation.platform_signals = [
        PlatformSignal(provider="HubSpot", category="Marketing", signal_type="SPF_INCLUDE",
                       evidence="include:hubspotemail.net"),
        PlatformSignal(provider="Atlassian", category="Dev", signal_type="TXT",
                       evidence="atlassian-domain-verification=abc"),
    ]
    return ref


def test_subdomains_are_ct_observed_with_notable_names():
    from estatereport.entities import subdomain_summary
    s = subdomain_summary(_vm_surface().vm, "ploy.io")
    assert s.source == "observed in certificate transparency"
    assert s.count == 4                            # wildcard, apex and foreign names dropped
    assert s.notable == ["auth.ploy.io", "dev2.eu.ploy.io", "staging-api.ploy.io"]


def test_saas_never_counts_ownership_tokens():
    from estatereport.entities import saas_platforms
    names = [p.provider for p in saas_platforms(_vm_surface().vm)]
    assert "HubSpot" in names and "Atlassian" not in names


def test_email_gateway_prefers_a_security_gateway_over_the_mailbox():
    from estatereport.entities import email_gateway
    ref = _vm_surface()
    ref.vm.dns_records = DnsRecordSet(mx=["10 mx1-eu1.ppe-hosted.com"])
    g = email_gateway(ref.vm)
    assert g.kind == "gateway" and g.provider == "Proofpoint"
    ref.vm.dns_records = DnsRecordSet(mx=[])
    assert email_gateway(ref.vm) is None


# ── linked domains + brand same-name registrations ─────────────────────────

def test_linked_domains_attach_to_the_entity_that_produced_them():
    a = make_ref("ploy.io", "x", cert={"cross_domain_sans": [{"dns_name": "ploy.co.uk"}]})
    b = make_ref("aisy.ai", "x")
    rep = _report(_write_estate([(a, "portfolio", "Ploy"), (b, "portfolio", "Aisy")]))
    by = {e.name: e for e in rep.entities}
    assert [l.domain for l in by["Ploy"].linked_domains] == ["ploy.co.uk"]
    assert by["Aisy"].linked_domains == []


class _FakeCorpus:
    def __init__(self, rows):
        self.rows = rows

    def stem_matches(self, stem, include_hyphen=True, exclude=None, limit=500):
        return [r for r in self.rows if r.stem == stem]


def test_brand_lookalikes_none_without_an_index():
    assert all(e.brand_lookalikes is None for e in _report().entities)


def test_brand_lookalikes_rule():
    from crossestate.corpus_index import CorpusRow as R
    rows = [
        R("ploy.io", "ploy", "io", ns_domain="cloudflare.com", mx_domain="google.com", ip="1.1.1.1"),
        R("ploy.com", "ploy", "com", mx_domain="outlook.com", ip="2.2.2.2"),          # 0.9
        R("ploy.de", "ploy", "de", ip="3.3.3.3"),                                      # 0.6
        R("ploy.net", "ploy", "net"),                                                  # 0.4: hidden
        R("ploy.co", "ploy", "co", ns_domain="cloudflare.com", ip="4.4.4.4"),         # shares NS
        R("ploy.org", "ploy", "org", mx_domain="x.com", ip="5.5.5.5"),
        R("ploy.app", "ploy", "app", mx_domain="y.com", ip="6.6.6.6"),
        R("ploy.xyz", "ploy", "xyz", mx_domain="z.com", ip="7.7.7.7"),
        R("ploy.ai", "ploy", "ai", mx_domain="w.com", ip="8.8.8.8"),
    ]
    a = make_ref("ploy.io", "x")
    rep = _report(_write_estate([(a, "portfolio", "Ploy")]), corpus_index=_FakeCorpus(rows))
    bl = rep.entities[0].brand_lookalikes
    assert bl.label == "ploy"
    assert bl.total_matches == 7                 # own ploy.io and NS-sharing ploy.co excluded
    assert bl.active_matches == 6                # ploy.net has no activity
    assert len(bl.shown) == 5
    assert bl.shown[0].confidence == 0.9 and "ploy.de" not in [s.domain for s in bl.shown]
    assert "Exact brand label" in rep.provenance["entities.brand_lookalikes"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
