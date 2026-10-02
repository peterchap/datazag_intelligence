"""One domain that never finishes must not stall the estate (2026-10-02)."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
