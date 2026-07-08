"""
scope_worker.py
---------------
WU20 "Scope my estate" worker. The portal /scope form inserts a row into
`scope_requests` (portal Neon); this worker claims it, collects the declared
domains (1-3), runs the discovery walk in COUNTS mode (full walk, truncated
output), composes the TeaserViewModel and writes the teaser back:

  pending -> running -> teaser_ready   (tier counts, <=3 strong proofs,
                                        indicative price band)
                     -> delayed        (walk errored / SLA exceeded: the user
                                        is emailed "taking longer", internal
                                        alert printed — never a dying spinner)

Run on the master:
    DATABASE_URL=<portal Neon DSN> python scope_worker.py

Env (mirrors free_report_worker):
    DATABASE_URL / PORTAL_DATABASE_URL   portal Neon DSN (required)
    INTELLIGENCE_BASE_URL, INTELLIGENCE_API_KEY
    PUBLIC_BASE_URL                      default https://portal.datazag.com
    RESEND_API_KEY, EMAIL_FROM
    CORPUS_INDEX_DIR                     enables the corpus stem-sweep
    SCOPE_SLA_SECONDS                    default 300 (doc: target < 5 min)
    SCOPE_WORKER_POLL_SECONDS            default 10
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import traceback
from dataclasses import asdict
from types import SimpleNamespace

from dotenv import load_dotenv
load_dotenv()

try:
    import psycopg2 as _pg
    _DRIVER = "psycopg2"
except ImportError:  # pragma: no cover
    import psycopg as _pg  # type: ignore
    _DRIVER = "psycopg"

import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scopeteaser.compose import build_teaser, estate_set_hash, tiers_from_discovery_result   # noqa: E402
from scopeteaser.renderer import render_email_html, render_teaser_html     # noqa: E402

DSN = os.environ.get("PORTAL_DATABASE_URL") or os.environ.get("DATABASE_URL")
POLL = int(os.environ.get("SCOPE_WORKER_POLL_SECONDS", "10"))
SLA_SECONDS = int(os.environ.get("SCOPE_SLA_SECONDS", "300"))
BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://portal.datazag.com").rstrip("/")

if not DSN:
    print("FATAL: DATABASE_URL (portal Neon) not set", file=sys.stderr)
    sys.exit(1)


def _connect():
    return _pg.connect(DSN)


def claim_one(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scope_requests SET status='running', updated_at=now()
            WHERE id = (
                SELECT id FROM scope_requests WHERE status='pending'
                ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
            )
            RETURNING id, token, domains, crn, email, src
            """
        )
        row = cur.fetchone()
    conn.commit()
    return row


async def _load_refs(domains: list[str]):
    """Collect each declared domain and build its view-model (same pipeline as
    the free report) — discovery walks the signals on these contracts."""
    import canonical_collect
    from report_pipeline import build_view_model
    from intelligence_client import IntelligenceClient

    client = IntelligenceClient()
    refs = []
    for domain in domains:
        output = await canonical_collect.collect(domain)
        vm = await build_view_model(domain, client, live_output=output)
        refs.append(SimpleNamespace(domain=domain, vm=vm))
    return refs


def _run_discovery(group: str, refs):
    from crossestate.discovery import default_discovery
    return default_discovery().discover(group, refs)


def result_url(token: str, src: str | None) -> str:
    url = f"{BASE_URL}/scope/result/{token}"
    return f"{url}?src={src}" if src else url


def write_teaser(conn, rid, vm, html, set_hash):
    band = asdict(vm.band) if vm.band else None
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE scope_requests SET status='teaser_ready', declared_count=%s, delta=%s,
                   tier_counts=%s::jsonb, proof_domains=%s::jsonb, band=%s::jsonb,
                   teaser_html=%s, set_hash=%s, expires_at=%s, completed_at=now(), updated_at=now()
               WHERE id=%s""",
            (vm.declared_count, vm.delta, json.dumps(vm.tier_counts),
             json.dumps([asdict(p) for p in vm.proof_domains]),
             json.dumps(band), html, set_hash, vm.expires, rid),
        )
    conn.commit()


def mark_delayed(conn, rid, err):
    with conn.cursor() as cur:
        cur.execute("UPDATE scope_requests SET status='delayed', error=%s, updated_at=now() WHERE id=%s",
                    (err[:2000], rid))
    conn.commit()


def _send(to_addr: str, subject: str, body_html: str, token: str | None = None):
    key = os.environ.get("RESEND_API_KEY")
    if not key:
        print("  (RESEND_API_KEY unset — skipping email)")
        return
    payload = {
        "from": os.environ.get("EMAIL_FROM", "Datazag Reports <reports@notifications.datazag.com>"),
        "to": [to_addr], "subject": subject, "html": body_html,
    }
    # A real User-Agent is required: Cloudflare (in front of api.resend.com)
    # blocks the default "Python-urllib/*" signature with a 403 (error 1010).
    req = urllib.request.Request("https://api.resend.com/emails",
                                 data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                                          "User-Agent": "Datazag-Report-Worker/1.0"})
    try:
        urllib.request.urlopen(req, timeout=20)
        if token:
            with _connect() as c2, c2.cursor() as cur:
                cur.execute("UPDATE scope_requests SET emailed_at=now() WHERE token=%s", (token,))
                c2.commit()
        print(f"  emailed {to_addr}")
    except Exception as e:
        detail = ""
        if hasattr(e, "read"):
            try:
                detail = f" — {e.read().decode('utf-8', 'replace')[:300]}"
            except Exception:
                pass
        print(f"  (email failed: {e}{detail})")


def process(conn, claimed):
    rid, token, domains_raw, crn, email, src = claimed
    domains = domains_raw if isinstance(domains_raw, list) else json.loads(domains_raw or "[]")
    print(f"[scope_worker] {domains} (id={rid}, crn={crn or '-'})")
    started = time.monotonic()
    try:
        refs = asyncio.run(_load_refs(domains))
        result = _run_discovery(email.split("@", 1)[-1], refs)
        tiers = tiers_from_discovery_result(result)
        vm = build_teaser(tiers, declared_count=len(domains), requested_by=email, src=src)
        link = result_url(token, src)
        html = render_teaser_html(vm, link)
        write_teaser(conn, rid, vm, html, estate_set_hash(tiers))
        elapsed = time.monotonic() - started
        if elapsed > SLA_SECONDS:
            print(f"  WARNING: walk exceeded SLA ({elapsed:.0f}s > {SLA_SECONDS}s)", file=sys.stderr)
        _send(email, f"Your Datazag estate scope — {vm.evidenced_count} domains evidenced",
              render_email_html(vm, link), token=token)
        print(f"  teaser_ready: declared {vm.declared_count} → evidenced {vm.evidenced_count} "
              f"({vm.band.label if vm.band else 'no band'}) in {elapsed:.0f}s")
    except Exception as e:
        # Failure path (doc): email "taking longer", alert internally,
        # never a spinner that dies.
        err = f"{e}\n{traceback.format_exc()}"
        print(f"  SCOPE FAILED (id={rid}): {e}", file=sys.stderr)
        mark_delayed(conn, rid, err)
        _send(email, "Your Datazag estate scope is taking a little longer",
              "<p>Your estate scope is taking longer than usual — we'll email it to you "
              "as soon as it's ready. No action needed.</p>")


def main():
    print(f"[scope_worker] polling every {POLL}s (SLA {SLA_SECONDS}s)")
    while True:
        try:
            with _connect() as conn:
                claimed = claim_one(conn)
                if claimed:
                    process(conn, claimed)
                    continue
        except Exception as e:
            print(f"[scope_worker] loop error: {e}", file=sys.stderr)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
