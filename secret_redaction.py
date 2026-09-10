"""
secret_redaction.py
-------------------
Scrub credentials out of text that is about to be printed or logged.

The DuckLake DSN is interpolated into the ATTACH statement, so DuckDB echoes it
back verbatim inside the connection error — password included. Every caller that
logged that error therefore wrote the live Postgres password into stdout and into
journald, for all five workers:

    IO Error: Failed to attach DuckLake MetaData "..." at path +
    "postgres:postgresql://neondb_owner:<password>@ep-....neon.tech/neondb?..."

Redaction happens at the point of RAISE (lake_connect) so the scrubbed message is
what propagates, and again at each log site as belt-and-braces — a leak only needs
one unredacted path.

Stdlib only, and deliberately dependency-free: it is imported from except-blocks
whose own failure mode may be that a heavier module could not be imported.

What is kept: host, port, database, user. Those are what you need to diagnose a
connection failure, and none of them is the secret.
"""
from __future__ import annotations

import re

_MASK = "***"

# postgresql://user:secret@host  /  postgres://user:secret@host  (any scheme)
_URI_CREDS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^:/@\s]+):(?P<pw>[^@\s]*)@")
# libpq conninfo `password=secret`, URI query `?password=secret&`, and the short
# spellings that turn up in hand-rolled log lines. Over-masking a harmless `pw=`
# costs nothing; missing one costs a credential.
_KV_PASSWORD = re.compile(
    r"(?P<key>password|passwd|pwd|pw)\s*=\s*(?P<val>'[^']*'|\"[^\"]*\"|[^\s&'\"]+)",
    re.IGNORECASE)
# Env-style credential assignments (R2_SECRET_ACCESS_KEY=..., API_TOKEN: ...)
_KV_SECRET = re.compile(
    r"(?P<key>(?:[A-Za-z0-9_]*(?:SECRET|PASSWORD|TOKEN)[A-Za-z0-9_]*|KEY_ID|ACCESS_KEY(?:_ID)?))"
    r"(?P<sep>\s*[:=]\s*)(?P<val>'[^']*'|\"[^\"]*\"|[^\s,;)'\"]+)",
    re.IGNORECASE)
# DuckDB CREATE SECRET syntax separates key and value with a SPACE:
#   CREATE SECRET r2 (TYPE R2, KEY_ID abc, SECRET xyz, ACCOUNT_ID 42)
# Uppercase-only and never right after CREATE/REPLACE, so prose keeps its meaning:
# "password authentication failed" and the secret's own NAME stay readable.
_DUCKDB_SECRET = re.compile(
    r"(?<!CREATE )(?<!REPLACE )\b(?P<key>KEY_ID|SECRET)\s+(?P<val>'[^']*'|[^\s,;)]+)")


def redact(text) -> str:
    """Return `text` with credentials masked. Never raises: a redaction failure
    must not become the error you see instead of the one you were reporting."""
    try:
        s = text if isinstance(text, str) else str(text)
    except Exception:
        return "<unprintable>"
    try:
        s = _URI_CREDS.sub(lambda m: f"{m['scheme']}{m['user']}:{_MASK}@", s)
        s = _KV_PASSWORD.sub(lambda m: f"{m['key']}={_MASK}", s)
        s = _KV_SECRET.sub(lambda m: f"{m['key']}{m['sep']}{_MASK}", s)
        s = _DUCKDB_SECRET.sub(lambda m: f"{m['key']} {_MASK}", s)
        return s
    except Exception:
        # Something pathological in the input — better an unhelpful string than a
        # leaked one.
        return "<redaction failed>"


def redacted_error(e: BaseException) -> str:
    """`str(e)` with credentials masked, for log lines."""
    return redact(str(e))
