"""One domain that never finishes must not stall the estate (2026-10-02)."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# estate_collect loads .env at import. CI runs a minimal venv without python-dotenv;
# skip there rather than break collection (same pattern as test_free_report_teaser_score).
pytest.importorskip("dotenv", reason="estate_collect imports python-dotenv at module level")

import estate_collect  # noqa: E402
import report_pipeline  # noqa: E402


def test_a_domain_that_hangs_times_out_as_an_error(monkeypatch):
    async def never(*a, **k):
        await asyncio.sleep(3600)

    monkeypatch.setattr(report_pipeline, "build_view_model", never)
    monkeypatch.setenv("ESTATE_DOMAIN_TIMEOUT", "0.2")
    with tempfile.TemporaryDirectory() as d:
        res = asyncio.run(estate_collect.collect_one(SimpleNamespace(), "slow.example", Path(d), False, True))
    assert res["status"] == "error" and "timed out" in res["error"]


def test_dns_phase_scans_each_domain_once_and_never_raises(monkeypatch):
    import canonical_collect
    calls = []

    async def fake_collect(d, strict=True, **k):
        calls.append((d, strict))
        if d == "bad.example":
            raise RuntimeError("resolver down")
        return {"domain": d, "status": "ALIVE"}

    monkeypatch.setattr(canonical_collect, "collect", fake_collect)
    out = asyncio.run(estate_collect.collect_dns(["a.example", "b.example", "bad.example"], 2))
    assert sorted(d for d, _ in calls) == ["a.example", "b.example", "bad.example"]
    assert all(strict is False for _, strict in calls)
    assert out["a.example"]["status"] == "ALIVE"
    assert out["bad.example"]["scan_incomplete"] is True


def test_assembly_starts_from_the_batched_dns(monkeypatch):
    seen = {}

    async def fake_build(domain, client, *, live=False, live_output=None, **k):
        seen[domain] = live_output
        return SimpleNamespace(has_intelligence=False)

    monkeypatch.setattr(report_pipeline, "build_view_model", fake_build)
    rec = {"domain": "a.example", "status": "ALIVE", "caa": "0 issue \"letsencrypt.org\""}
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(estate_collect.collect_one(SimpleNamespace(), "a.example", Path(d), False, True, live_output=rec))
    assert seen["a.example"] is rec
