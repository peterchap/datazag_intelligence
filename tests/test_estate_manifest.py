"""Tests for manifest loading (JSON + CSV) and the contract loader fallback."""

from __future__ import annotations

import json
import os

from estate_helpers import ESTATE_MANIFEST, make_vm  # noqa: E402

from crossestate.manifest import (  # noqa: E402
    contract_from_payload,
    load_contract,
    load_manifest,
)


def test_load_json_manifest_and_resolve_paths():
    group, entries = load_manifest(ESTATE_MANIFEST)
    assert group == "Acme Group"
    assert len(entries) == 9
    e = next(x for x in entries if x.domain == "acme.com")
    assert e.segment == "corp"
    # contract_path resolved to an absolute path next to the manifest
    assert os.path.isabs(e.contract_path) and e.contract_path.endswith("acme.com.json")


def test_load_csv_manifest(tmp_path):
    csv = tmp_path / "m.csv"
    csv.write_text("# group: CsvCo\n"
                   "domain,segment,contract_path\n"
                   "a.com,corp,contracts/a.json\n"
                   "b.com,,contracts/b.json\n", encoding="utf-8")
    group, entries = load_manifest(str(csv))
    assert group == "CsvCo"
    assert [e.domain for e in entries] == ["a.com", "b.com"]
    assert entries[0].segment == "corp"
    assert entries[1].segment in (None, "")


def test_load_contract_view_model_dump(tmp_path):
    vm = make_vm("x.com", score=40)
    p = tmp_path / "x.json"
    p.write_text(json.dumps(vm.model_dump(mode="json"), default=str), encoding="utf-8")
    loaded = load_contract(str(p))
    assert loaded.domain == "x.com" and loaded.composite_score == 40


def test_contract_from_payload_medallion_fallback():
    medallion = {
        "schema_version": "1.0", "domain": "m.com",
        "risk_assessment": {"infra_score": 0.1},
        "email_security": {"dmarc_risk": True},
    }
    vm = contract_from_payload(medallion)
    assert vm.domain == "m.com" and vm.has_intelligence is True


def _run_all():
    import sys
    import tempfile
    from pathlib import Path
    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    passed = 0
    for fn in fns:
        if "tmp_path" in fn.__code__.co_varnames[:fn.__code__.co_argcount]:
            with tempfile.TemporaryDirectory() as d:
                fn(Path(d))
        else:
            fn()
        print(f"ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed} passed")


if __name__ == "__main__":
    _run_all()
