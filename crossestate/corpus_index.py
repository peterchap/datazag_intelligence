"""
crossestate/corpus_index.py
---------------------------
The tailored discovery index — a stem-prefix-partitioned parquet built once from
the gold corpus (`domains.parquet`, ~323M rows) so estate discovery gets
predictable lookup latency and deterministic results instead of scanning the whole
corpus per run.

Layout (the design the user chose):
  index_dir/
    stem_prefix=ac/  *.parquet      # every domain whose registrable stem starts "ac"
    stem_prefix=ex/  *.parquet
    ...
Each row: domain · stem (registrable label) · suffix (public suffix) · stem_prefix
plus the key DNS match-columns carried through from the source when present
(ns_domain / mx_domain / registrar / asn / ip) — those are what let discovery
corroborate a candidate's OWNERSHIP (does it share the estate's NS/MX/registrar/
ASN?) straight from the file, with no live per-candidate lookup.

A stem lookup reads ONE partition, so latency is flat regardless of corpus size.
The sweep is deliberately bounded to `stem` and `stem-*` hyphen variants (same
partition) — broad "contains brand" matching is both unpredictable and FP-heavy,
which the discovery gate rule warns against.

Built and queried with DuckDB (out-of-core; no full-corpus materialisation in
Python). `build_index` streams the transform; `ParquetCorpusIndex` reads one
partition per stem.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

# Two-label public suffixes so `a.co.uk` → stem "a". Kept in sync with
# crossestate.segments; a fuller PSL can replace this without changing callers.
from crossestate.segments import _TWO_LABEL_SUFFIXES

# DNS columns we carry through for ownership corroboration, if the source has them.
_DNS_MATCH_COLUMNS = ("ns_domain", "mx_domain", "registrar", "asn", "ip", "a")


def _sql_list(vals) -> str:
    return "(" + ", ".join("'" + v.replace("'", "''") + "'" for v in sorted(vals)) + ")"


def _stem_prefix(stem: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", (stem or "")[:2].lower()) or "_"


# The stem / suffix / stem_prefix expressions, computed in DuckDB SQL so the build
# streams over 323M rows out-of-core. `L` is the split label list (1-based; DuckDB
# supports negative indices).
def _transform_sql(src_expr: str, dns_cols: list[str]) -> str:
    tl = _sql_list(_TWO_LABEL_SUFFIXES)
    dns_select = ("," + ",".join(dns_cols)) if dns_cols else ""
    return f"""
    WITH base AS (
        SELECT *, string_split(lower(domain), '.') AS L FROM {src_expr}
    ), sfx AS (
        SELECT *,
            CASE WHEN len(L) >= 3 AND (L[-2] || '.' || L[-1]) IN {tl}
                 THEN L[-3] ELSE L[-2] END AS stem,
            CASE WHEN len(L) >= 3 AND (L[-2] || '.' || L[-1]) IN {tl}
                 THEN L[-2] || '.' || L[-1] ELSE L[-1] END AS suffix
        FROM base WHERE len(L) >= 2
    )
    SELECT domain, stem, suffix,
           regexp_replace(lower(stem[1:2]), '[^a-z0-9]', '_') AS stem_prefix
           {dns_select}
    FROM sfx
    """


def build_index(source_parquet: str, out_dir: str,
                dns_columns: Optional[list[str]] = None,
                con=None) -> str:
    """Build the stem-prefix-partitioned index from a source parquet (the corpus,
    optionally already enriched with DNS columns). Returns `out_dir`.

    `dns_columns` are carried through for corroboration; when None they are
    auto-detected from the source schema (`ns_domain`/`mx_domain`/`registrar`/
    `asn`/`ip`/`a`). Idempotent per partition (OVERWRITE_OR_IGNORE)."""
    import duckdb
    con = con or duckdb.connect()
    src = f"read_parquet('{source_parquet}')"
    have = {c[0] for c in con.execute(f"DESCRIBE SELECT * FROM {src}").fetchall()}
    dns = [c for c in (dns_columns or _DNS_MATCH_COLUMNS) if c in have]
    os.makedirs(out_dir, exist_ok=True)
    con.execute(f"""
        COPY ({_transform_sql(src, dns)})
        TO '{out_dir}' (FORMAT parquet, PARTITION_BY (stem_prefix), OVERWRITE_OR_IGNORE);
    """)
    return out_dir


@dataclass
class CorpusRow:
    domain: str
    stem: str
    suffix: str
    ns_domain: Optional[str] = None
    mx_domain: Optional[str] = None
    registrar: Optional[str] = None
    asn: Optional[str] = None
    ip: Optional[str] = None


class ParquetCorpusIndex:
    """Reads the tailored index one partition at a time — predictable latency."""

    def __init__(self, index_dir: str, con=None):
        import duckdb
        self.index_dir = index_dir
        self.con = con or duckdb.connect()

    def _partition_glob(self, stem: str) -> Optional[str]:
        pfx = _stem_prefix(stem)
        path = os.path.join(self.index_dir, f"stem_prefix={pfx}")
        return os.path.join(path, "*.parquet") if os.path.isdir(path) else None

    def stem_matches(self, stem: str, *, include_hyphen: bool = True,
                     exclude: Optional[set] = None, limit: int = 500) -> list[CorpusRow]:
        """Domains sharing this registrable stem (all TLDs) plus `stem-*` hyphen
        variants — a single-partition, bounded read. `exclude` drops the declared
        estate. Returns [] when the partition is absent (stem not in corpus)."""
        glob = self._partition_glob(stem)
        if not glob:
            return []
        stem = stem.lower()
        where = ["stem = ?"]
        params: list = [stem]
        if include_hyphen:
            where.append("stem LIKE ?")            # stem-group, stem-uk, …
            params.append(stem + "-%")
        cols = {c[0] for c in self.con.execute(f"DESCRIBE SELECT * FROM read_parquet('{glob}')").fetchall()}
        sel = ["domain", "stem", "suffix"] + [c for c in ("ns_domain", "mx_domain", "registrar", "asn", "ip") if c in cols]
        rows = self.con.execute(
            f"SELECT {', '.join(sel)} FROM read_parquet('{glob}') "
            f"WHERE ({' OR '.join(where)}) LIMIT {int(limit)}", params).fetchall()
        out = []
        ex = {d.lower() for d in (exclude or set())}
        for r in rows:
            rec = dict(zip(sel, r))
            if rec["domain"].lower() in ex:
                continue
            out.append(CorpusRow(**{k: rec.get(k) for k in
                                    ("domain", "stem", "suffix", "ns_domain", "mx_domain", "registrar", "asn", "ip")}))
        return out


if __name__ == "__main__":  # tiny build CLI
    import argparse
    ap = argparse.ArgumentParser(description="Build the tailored discovery index")
    ap.add_argument("--source", required=True, help="Corpus parquet (domain [+ DNS columns])")
    ap.add_argument("--out", required=True, help="Output index directory")
    args = ap.parse_args()
    print("Built index at", build_index(args.source, args.out))
