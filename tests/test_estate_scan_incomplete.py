"""A domain whose live DNS scan did not finish is counted, not assessed.

canonical_collect(strict=False) returns {"scan_incomplete": True} for a scan that
never finished. Its hygiene block is empty because nothing was seen. Before
2026-10-02 the estate read that as "no DMARC, no CAA, no DNSSEC" and counted it
in every control prevalence. It now goes through the same not-assessed path as a
contract that failed to load.
"""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone

from estate_helpers import ESTATE_MANIFEST  # noqa: E402  (puts the repo root on sys.path)

from crossestate.build import build_estate_from_manifest  # noqa: E402

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
TARGET = "acmeretail.com"


def _estate(tmp_path, *, incomplete: bool):
    src = os.path.dirname(ESTATE_MANIFEST)
    dst = tmp_path / "estate"
    shutil.copytree(src, dst)
    contract = dst / "contracts" / f"{TARGET}.json"
    payload = json.loads(contract.read_text(encoding="utf-8"))
    if incomplete:
        payload["scan_incomplete"] = True
        payload["hygiene"] = {}  # what an unfinished scan leaves behind
    contract.write_text(json.dumps(payload), encoding="utf-8")
    return build_estate_from_manifest(str(dst / "manifest.json"), now=NOW)


def _ref(estate, domain):
    return next(d for s in estate.segments for d in s.domains if d.domain == domain)


def test_unfinished_scan_is_counted_but_not_assessed(tmp_path):
    full = _estate(tmp_path / "a", incomplete=False)
    part = _estate(tmp_path / "b", incomplete=True)
    assert part.domain_count == full.domain_count
    assert part.assessed_count == full.assessed_count - 1
    assert _ref(part, TARGET).load_error == "live DNS scan did not finish"
    assert _ref(full, TARGET).load_error is None


def test_unfinished_scan_adds_no_control_weakness(tmp_path):
    full = {w.control: w for w in _estate(tmp_path / "a", incomplete=False).correlated_weakness}
    part = {w.control: w for w in _estate(tmp_path / "b", incomplete=True).correlated_weakness}
    for control in ("dmarc", "spf", "dnssec", "caa"):
        f, p = full[control], part[control]
        # Out of the denominator, and never added to the affected count.
        assert p.n_assessed == f.n_assessed - 1, control
        assert p.n_affected <= f.n_affected, control
