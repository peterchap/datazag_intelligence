"""The CT-archive cert source (2026-10-02): rows match CertSpotter's normalise()
shape, the read dedups precert/final and repeat sightings, and one query serves
a whole estate."""
from __future__ import annotations

import os
import sys
from datetime import date, datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cert_stream  # noqa: E402

TODAY = date(2026, 10, 2)
NORMALISE_KEYS = {
    "cert_id", "logged_at", "not_before", "not_after", "common_name", "dns_name",
    "is_wildcard", "issuer_org", "issuer_cn", "issuer_category", "validity_days",
    "days_remaining", "is_expired", "san_count",
}


def _ts(y, m, d):
    return datetime(y, m, d, tzinfo=timezone.utc)


def test_rows_have_the_certspotter_shape_one_per_san():
    rows = cert_stream.rows_from_certs([{
        "issuer_o": "Let's Encrypt", "issuer_cn": "R11", "cert_serial": "abc",
        "not_before": _ts(2026, 9, 1), "not_after": _ts(2026, 11, 30),
        "logged_at": _ts(2026, 9, 1), "san_entries": ["datazag.com", "*.Datazag.com."],
    }], today=TODAY)
    assert [r["dns_name"] for r in rows] == ["datazag.com", "*.datazag.com"]
    assert all(set(r) == NORMALISE_KEYS for r in rows)
    r = rows[0]
    assert r["cert_id"] == "abc" and r["issuer_category"] == "letsencrypt"
    assert r["days_remaining"] == 59 and r["is_expired"] is False
    assert r["validity_days"] == 90 and r["san_count"] == 2
    assert rows[1]["is_wildcard"] is True


def test_query_dedups_and_serves_every_domain_in_one_pass(tmp_path, monkeypatch):
    duckdb = pytest.importorskip("duckdb")
    con = duckdb.connect()
    con.execute("""CREATE TABLE t (apex_domain VARCHAR, issuer_o VARCHAR, issuer_cn VARCHAR,
                   cert_serial VARCHAR, not_before TIMESTAMPTZ, not_after TIMESTAMPTZ,
                   seen_at TIMESTAMPTZ, san_entries VARCHAR[], update_type VARCHAR)""")
    rows = [
        # precert + final cert, same serial, seen on two days -> one certificate
        ("a.com", "Let's Encrypt", "R11", "s1", "2026-09-01", "2026-11-30", "2026-09-01", ["a.com", "www.a.com"], "PrecertLogEntry"),
        ("a.com", "Let's Encrypt", "R11", "s1", "2026-09-01", "2026-11-30", "2026-09-02", ["a.com", "www.a.com"], "X509LogEntry"),
        ("b.com", "Google Trust Services", "WE1", "s2", "2026-09-10", "2026-12-09", "2026-09-10", ["b.com"], "X509LogEntry"),
        ("c.com", "Sectigo", "x", "s3", "2026-09-10", "2026-12-09", "2026-09-10", ["c.com"], "X509LogEntry"),
    ]
    # Explicit UTC noon, so the test does not depend on the machine's time zone.
    rows = [r[:4] + tuple(f"{v} 12:00:00+00" for v in r[4:7]) + r[7:] for r in rows]
    con.executemany("INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    # The precert lands in one partition, the final cert and the rest in the next.
    for dt, where in (("2026-09-01", "update_type = 'PrecertLogEntry'"),
                      ("2026-09-02", "update_type <> 'PrecertLogEntry'")):
        part = tmp_path / f"dt={dt}"
        part.mkdir()
        con.execute(f"COPY (SELECT * FROM t WHERE {where}) "
                    f"TO '{(part / 'sorted_1.parquet').as_posix()}' (FORMAT PARQUET)")
    monkeypatch.setattr(cert_stream, "_archive_glob", lambda: f"{tmp_path.as_posix()}/*/*.parquet")

    got = cert_stream.query_certs(con, ["a.com", "b.com", "none.com"], date(2026, 7, 23))
    assert set(got) == {"a.com", "b.com", "none.com"}        # c.com not asked for
    assert len(got["a.com"]) == 1                              # deduped across rows and days
    assert cert_stream._as_date(got["a.com"][0]["logged_at"]) == date(2026, 9, 1)  # first sighting
    assert len(got["b.com"]) == 1 and got["none.com"] == []


def test_unsafe_names_never_reach_the_sql():
    class Boom:
        def execute(self, *a, **k):
            raise AssertionError("must not query")
    assert cert_stream.query_certs(Boom(), ["x'); DROP TABLE t; --"], date(2026, 7, 23)) == {
        "x'); DROP TABLE t; --": []}


def test_analysis_output_matches_the_certspotter_pipeline():
    pytest.importorskip("dnsproject.intelligence.cert_pipeline")
    rows = cert_stream.rows_from_certs([{
        "issuer_o": "Let's Encrypt", "issuer_cn": "R11", "cert_serial": "abc",
        "not_before": _ts(2026, 9, 1), "not_after": _ts(2026, 11, 30),
        "logged_at": _ts(2026, 9, 1), "san_entries": ["datazag.com", "mail.datazag.com"],
    }])
    out = cert_stream.analyse(rows, "datazag.com")
    assert [s["dns_name"] for s in out["subdomains"]] == ["mail.datazag.com"]
    assert out["cert_analysis"]["coverage"]["window_start"] == "2026-07-23"
    assert out["cert_analysis"]["issuer_breakdown"][0]["issuer_category"] == "letsencrypt"
