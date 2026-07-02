"""
Tailored-corpus discovery tests — the index builder + stem lookup, entropy/DGA,
and the corpus-backed multi-source discovery pass. Needs duckdb (available in the
venv); skips cleanly if absent. Standalone runner.
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from crossestate.entropy import dga_score, is_typosquat, shannon_entropy  # noqa: E402

MANIFEST = os.path.join(_ROOT, "tests", "fixtures", "estate", "manifest.json")
NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)

try:
    import duckdb  # noqa: F401
    _HAVE_DUCKDB = True
except Exception:
    _HAVE_DUCKDB = False

# A synthetic corpus: the estate's declared acme.com + brand-family rows with DNS.
_CORPUS = [
    ("acme.com", "cloudflare.com", "google.com"),          # declared → estate infra fingerprint
    ("acme.co.uk", "cloudflare.com", "google.com"),        # shares NS → owned strong
    ("acme.net", "otherdns.net", "outlook.com"),           # exact stem, clean → owned strong
    ("acme-group.com", "cloudflare.com", "google.com"),    # hyphen + shared NS → owned strong
    ("acme-store.info", "somerandom.io", "zoho.com"),      # hyphen, no infra, low dga → possible
    ("acme-9284756.com", "parking.ru", "parking.ru"),      # hyphen, high dga → hostile
]


def _build_index(tmp):
    seed = os.path.join(tmp, "seed.parquet").replace("\\", "/")
    idx = os.path.join(tmp, "idx").replace("\\", "/")
    con = duckdb.connect()
    con.execute("CREATE TABLE c(domain VARCHAR, ns_domain VARCHAR, mx_domain VARCHAR)")
    con.executemany("INSERT INTO c VALUES (?,?,?)", _CORPUS)
    con.execute(f"COPY c TO '{seed}' (FORMAT parquet)")
    from crossestate.corpus_index import build_index, ParquetCorpusIndex
    build_index(seed, idx, con=con)
    return ParquetCorpusIndex(idx)


# ── entropy / DGA (no duckdb needed) ────────────────────────────────────────

def test_entropy_and_dga_ordering():
    assert shannon_entropy("aaaa") < shannon_entropy("abcd")
    assert dga_score("x7k2p9qmz") > dga_score("example")     # random > word
    assert dga_score("microsoft") < 0.55


def test_typosquat_detection():
    assert is_typosquat("examp1e", "example") is True        # digit-for-letter
    assert is_typosquat("example-group", "example") is False  # legit extension, not a typo


# ── corpus index (needs duckdb) ─────────────────────────────────────────────

def test_index_build_and_bounded_stem_lookup():
    if not _HAVE_DUCKDB:
        print("  (skipped: duckdb absent)"); return
    with tempfile.TemporaryDirectory() as tmp:
        ix = _build_index(tmp)
        rows = {r.domain for r in ix.stem_matches("acme", exclude={"acme.com"})}
        assert "acme.co.uk" in rows and "acme-group.com" in rows
        assert "acme.com" not in rows                        # excluded
        # a stem absent from the corpus → empty, no error
        assert ix.stem_matches("zzzznotpresent") == []


# ── corpus-backed discovery (needs duckdb) ──────────────────────────────────

def test_corpus_discovery_classifies_owned_candidate_and_hostile():
    if not _HAVE_DUCKDB:
        print("  (skipped: duckdb absent)"); return
    with tempfile.TemporaryDirectory() as tmp:
        ix = _build_index(tmp)
        from crossestate.build import build_estate_from_manifest
        from crossestate.discovery import ConnectedDomainDiscoveryProvider
        prov = ConnectedDomainDiscoveryProvider(corpus=ix)
        mvp = build_estate_from_manifest(MANIFEST, discovery=prov, now=NOW)
        owned = {d["domain"] for d in mvp.completeness.delta}
        cands = {d["domain"] for d in mvp.completeness.candidates}
        # ONLY infra-corroborated (shared NS) domains are owned — the gate rule
        assert {"acme.co.uk", "acme-group.com"} <= owned
        # exact brand stem but NO shared infra → held for review, never claimed owned
        assert "acme.net" in cands and "acme.net" not in owned
        assert "acme-store.info" in cands
        # DGA lookalike → NOT owned (hostile lane, mapped to defensive tier)
        assert "acme-9284756.com" not in owned

        from estatereport.build import build_estate_report
        d = build_estate_report(mvp, discovery=prov, now=NOW).discovery
        assert "acme-9284756.com" in {x.domain for x in d.tiers["defensive"]}
        strong = {x.domain for x in d.tiers["strong"]}
        assert "acme.co.uk" in strong and "acme.net" not in strong


def _run_all():
    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
