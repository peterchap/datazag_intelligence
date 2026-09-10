"""
test_observatory.py
-------------------
The Observatory is the daily corpus measurement Datazag publishes to R2. It is
what replaced the licensed feeds as the source of context in the reports: "you do
not publish DMARC, and neither does 76.5% of the 364.2M domains we track" is a
claim only Datazag can make, from its own data.

Two properties matter more than the plumbing:

  * a share must carry its denominator. `dmarc_enforced` is 49.6% OF DOMAINS
    PUBLISHING DMARC and 11.5% of all resolving domains — quoting the first as if
    it were the second is not a rounding difference, it is a wrong number;
  * unavailable must be a normal outcome. A report that cannot reach the
    observatory omits the comparison; it never guesses a corpus figure.

Runs under pytest or standalone (`python tests/test_observatory.py`).
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import observatory  # noqa: E402

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "observatory")


def _loaded() -> observatory.Observatory:
    return observatory.load(FIXTURE_DIR.rstrip("/") + "/")


def _with_date(fn):
    """The fixture is a single dated snapshot; pin the loader to it."""
    def wrapper(*a, **kw):
        old = os.environ.get("OBSERVATORY_DATE")
        os.environ["OBSERVATORY_DATE"] = "20260908"
        try:
            return fn(*a, **kw)
        finally:
            if old is None:
                os.environ.pop("OBSERVATORY_DATE", None)
            else:
                os.environ["OBSERVATORY_DATE"] = old
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@_with_date
def test_loads_the_daily_statistics():
    obs = _loaded()
    assert obs.available
    assert obs.as_of == "2026-09-06"
    assert obs.get("corpus_domains").value > 300_000_000


@_with_date
def test_a_share_always_carries_its_denominator():
    obs = _loaded()
    published = obs.get("dmarc_present")
    enforced = obs.get("dmarc_enforced")
    # the two DMARC figures are shares of DIFFERENT populations
    assert published.denominator_label != enforced.denominator_label
    assert "resolving domains" in published.denominator_label
    assert "publishing DMARC" in enforced.denominator_label
    for stat in (published, enforced):
        assert stat.denominator_label in stat.sentence(), \
            "a benchmark sentence without its denominator is a wrong number"


@_with_date
def test_share_without_is_the_complement_and_only_for_percentages():
    obs = _loaded()
    assert obs.share_without("dmarc_present") == round(100 - obs.get("dmarc_present").value, 1)
    assert obs.share_without("corpus_domains") is None      # a count has no complement


@_with_date
def test_unmeasured_rows_are_not_benchmarks():
    obs = _loaded()
    assert all(s.stat_id for s in obs._stats.values())
    # every loaded stat came from a measured row
    import pyarrow.parquet as pq
    rows = pq.read_table(os.path.join(
        FIXTURE_DIR, "observatory_20260908_observatory_statistics.parquet")).to_pylist()
    unmeasured = {r["stat_id"] for r in rows if not r.get("is_measured", True)}
    assert not (unmeasured & set(obs._stats)), "an unmeasured row was offered as a benchmark"


def test_unavailable_is_a_normal_outcome():
    """No observatory, no benchmark — never a raise, never a guess."""
    obs = observatory.load("/nonexistent/path/that/does/not/exist/")
    assert obs.available is False
    assert obs.get("dmarc_present") is None
    assert obs.share_without("dmarc_present") is None


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
