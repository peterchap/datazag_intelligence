"""
test_secret_redaction.py
------------------------
The DuckLake DSN is interpolated into the ATTACH statement, so DuckDB echoes it —
password and all — inside the connection error. Every caller that logged that error
wrote the live Postgres password to stdout and journald.

Runs under pytest or standalone (`python tests/test_secret_redaction.py`).
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from secret_redaction import redact, redacted_error  # noqa: E402

# Shaped exactly like the error that leaked, with a stand-in password.
PW = "npg_NOTAREALSECRET"
REAL_ERROR = (
    'IO Error: Failed to attach DuckLake MetaData "__ducklake_metadata_datazag_lake2" '
    'at path + "postgres:postgresql://neondb_owner:' + PW + '@ep-jolly-truth-al0gned8-'
    'pooler.c-3.eu-central-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require"'
    'Unable to connect to Postgres at "postgresql://neondb_owner:' + PW + '@ep-jolly-truth'
    '.neon.tech/neondb": connection to server at "ep-jolly-truth.neon.tech" (2a05:d014), '
    "port 5432 failed: ERROR:  password authentication failed for user 'neondb_owner'"
)


def test_dsn_password_never_survives():
    out = redact(REAL_ERROR)
    assert PW not in out
    assert out.count("***") >= 2          # both occurrences, not just the first


def test_diagnosis_survives():
    """Redaction that eats the error is no better than the leak."""
    out = redact(REAL_ERROR)
    for keep in ("ep-jolly-truth", "neondb_owner", "port 5432",
                 "password authentication failed", "IO Error"):
        assert keep in out, f"redaction destroyed diagnostic detail: {keep!r}"


def test_conninfo_and_env_and_duckdb_secret_forms():
    assert redact("dbname=neondb host=h user=u password=hunter2 sslmode=require") == \
        "dbname=neondb host=h user=u password=*** sslmode=require"
    assert "zzz" not in redact("R2_SECRET_ACCESS_KEY=zzz R2_ACCESS_KEY_ID=abc")
    # DuckDB's CREATE SECRET separates key and value with a space
    out = redact("CREATE OR REPLACE SECRET r2_lake (TYPE R2, KEY_ID abc, SECRET zzz);")
    assert "zzz" not in out and "abc" not in out
    assert "r2_lake" in out               # the secret's NAME is not a secret


def test_never_raises():
    class Exploding:
        def __str__(self): raise RuntimeError("boom")
    assert redact(Exploding()) == "<unprintable>"
    assert redact(None) == "None"
    assert redact(redact(REAL_ERROR)) == redact(REAL_ERROR)   # idempotent
    assert redacted_error(ValueError(f"pw={PW}")) == "pw=***"


def test_impersonation_failure_log_is_redacted(capsys):
    """The site that actually leaked: local_intelligence swallows the lake error and
    prints it. Exercised through the real client method, not a copy of the string."""
    import asyncio

    from local_intelligence import LocalIntelligenceClient

    class Down(LocalIntelligenceClient):
        def __init__(self): pass
        def _query_impersonations(self, platforms, brand=None):
            raise RuntimeError(REAL_ERROR)

    ext = asyncio.run(Down().fetch_platform_impersonations(["Microsoft 365"], brand="x.com"))
    printed = capsys.readouterr().out
    assert PW not in printed, "the impersonation failure log still leaks the DSN password"
    assert "impersonation lookup failed" in printed
    assert ext.lookup_ok is False          # and it is still marked NOT CHECKED


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
