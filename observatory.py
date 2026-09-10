"""
observatory.py
--------------
Datazag Observatory: the daily corpus-wide measurements, published to R2 at
`datazag-observatory-public/observatory/{date}/`.

The reports use it for one job — telling a reader where they sit against the
internet as Datazag measures it. "You do not publish DMARC" is a fact about a
domain; "you are in the 76% that do not, across 364 million we track" is the
thing only Datazag can say, and it comes from our own measurement rather than a
feed we would have to license.

Every statistic arrives with `source`, `method`, `caveat`, `denominator_label`
and `prior_value`, and this module keeps them attached. That matters more than it
looks: `dmarc_enforced` is 49.55% OF DOMAINS PUBLISHING DMARC and 11.47% of all
resolving domains. A benchmark that drops its denominator is not a benchmark, it
is a wrong number, so `Stat.sentence()` always states what the share is of.

Availability is best-effort by design. No observatory, no benchmark line — the
report never guesses at a corpus figure, and `Observatory.unavailable()` is a
normal outcome rather than an error.

Env:
    OBSERVATORY_PATH   directory or URI holding the daily parquet files.
                       Default: r2://datazag-observatory-public/observatory/{date}/
    OBSERVATORY_DATE   pin a specific snapshot (YYYYMMDD); default is the most
                       recent of the last OBSERVATORY_LOOKBACK_DAYS.
"""
from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass
from typing import Optional

DEFAULT_PATH = "r2://datazag-observatory-public/observatory/{date}/"
LOOKBACK_DAYS = int(os.environ.get("OBSERVATORY_LOOKBACK_DAYS", "7"))


@dataclass(frozen=True)
class Stat:
    """One corpus measurement, with the context that makes it quotable."""
    stat_id: str
    label: str
    value: float
    unit: str
    denominator_label: str
    as_of: str
    source: str
    caveat: str
    prior_value: Optional[float]
    higher_is_better: bool

    @property
    def is_percent(self) -> bool:
        return self.unit == "percent"

    def formatted(self) -> str:
        return f"{self.value:.1f}%" if self.is_percent else f"{self.value:,.0f}"

    def sentence(self) -> str:
        """A quotable line that carries its own denominator."""
        of = f" of {self.denominator_label}" if self.denominator_label else ""
        return f"{self.formatted()}{of}"


class Observatory:
    """Loaded daily statistics, keyed by stat_id. Absent is a valid state."""

    def __init__(self, stats: dict[str, Stat], as_of: str = ""):
        self._stats = stats
        self.as_of = as_of

    @property
    def available(self) -> bool:
        return bool(self._stats)

    @classmethod
    def unavailable(cls) -> "Observatory":
        return cls({}, "")

    def get(self, stat_id: str) -> Optional[Stat]:
        return self._stats.get(stat_id)

    def share_without(self, stat_id: str) -> Optional[float]:
        """The complement of an adoption rate — "the 76% that do not publish DMARC".
        Only meaningful for a percentage, so anything else returns None."""
        s = self.get(stat_id)
        if s is None or not s.is_percent:
            return None
        return round(100.0 - s.value, 1)


def _candidate_dates() -> list[str]:
    pinned = os.environ.get("OBSERVATORY_DATE")
    if pinned:
        return [pinned]
    today = _dt.date.today()
    return [(today - _dt.timedelta(days=n)).strftime("%Y%m%d")
            for n in range(0, max(1, LOOKBACK_DAYS))]


def _rows_from_parquet(uri: str) -> list[dict]:
    """Read one parquet by whichever reader this host has. duckdb first: the
    pipeline machine already depends on it for the lake, and it can read r2://
    and https:// as well as local paths."""
    try:
        import duckdb  # type: ignore
    except Exception:
        duckdb = None
    if duckdb is not None:
        con = duckdb.connect(":memory:")
        try:
            if uri.startswith(("r2://", "s3://")):
                # Reuse the lake's R2 credentials rather than re-deriving them.
                from lake_enrich import _add_s3_over_r2_secret  # type: ignore
                con.execute("INSTALL httpfs; LOAD httpfs;")
                _add_s3_over_r2_secret(con)
            elif uri.startswith("http"):
                con.execute("INSTALL httpfs; LOAD httpfs;")
            cur = con.execute(f"SELECT * FROM read_parquet('{uri}')")
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            con.close()
    import pyarrow.parquet as pq  # type: ignore
    return pq.read_table(uri).to_pylist()


def _statistics_uri(base: str, date: str) -> str:
    base = base.format(date=date) if "{date}" in base else base
    if not base.endswith("/"):
        base += "/"
    return f"{base}observatory_{date}_observatory_statistics.parquet"


def load(path: Optional[str] = None) -> Observatory:
    """Load the most recent daily statistics. Never raises: a report that cannot
    reach the observatory simply omits the comparison."""
    base = path or os.environ.get("OBSERVATORY_PATH") or DEFAULT_PATH
    for date in _candidate_dates():
        uri = _statistics_uri(base, date)
        try:
            rows = _rows_from_parquet(uri)
        except Exception:
            continue
        if not rows:
            continue
        stats = {}
        for r in rows:
            if not r.get("is_measured", True):
                continue          # an unmeasured row is not a benchmark
            stats[r["stat_id"]] = Stat(
                stat_id=r["stat_id"], label=r.get("label", ""),
                value=float(r.get("value") or 0.0), unit=r.get("unit", ""),
                denominator_label=r.get("denominator_label", "") or "",
                as_of=r.get("as_of", "") or "", source=r.get("source", "") or "",
                caveat=r.get("caveat", "") or "",
                prior_value=(float(r["prior_value"]) if r.get("prior_value") is not None else None),
                higher_is_better=bool(r.get("higher_is_better", True)),
            )
        if stats:
            return Observatory(stats, next(iter(stats.values())).as_of)
    return Observatory.unavailable()
