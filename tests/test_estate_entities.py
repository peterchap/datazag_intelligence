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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
