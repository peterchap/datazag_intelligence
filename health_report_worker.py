"""
health_report_worker.py
-----------------------
Polls the Customer Portal Neon DB for pending health-report orders, renders each
via the v8 healthreport pipeline, and writes the PDF (+ Trust Grade) back into
the `health_reports` row for the portal to serve.

Run on the master (where the pipeline, Chromium, and API keys live):

    DATABASE_URL=<portal Neon DSN> python health_report_worker.py

Env:
    DATABASE_URL / PORTAL_DATABASE_URL  portal Neon connection string (required)
    HEALTH_WORKER_POLL_SECONDS          poll interval (default 20)
    HEALTH_WORKER_TIMEOUT               per-report subprocess timeout sec (default 900)
    (plus the pipeline's own: ANTHROPIC_API_KEY, CERTSPOTTER_TOKEN, SHODAN_API_KEY)

Claim is atomic via FOR UPDATE SKIP LOCKED, so multiple workers are safe.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

try:
    import psycopg2 as _pg
    _DRIVER = "psycopg2"
except ImportError:  # pragma: no cover
    import psycopg as _pg  # type: ignore
    _DRIVER = "psycopg"

DSN = os.environ.get("PORTAL_DATABASE_URL") or os.environ.get("DATABASE_URL")
POLL = int(os.environ.get("HEALTH_WORKER_POLL_SECONDS", "20"))
TIMEOUT = int(os.environ.get("HEALTH_WORKER_TIMEOUT", "900"))
HERE = Path(__file__).resolve().parent

if not DSN:
    print("FATAL: DATABASE_URL (portal Neon) not set", file=sys.stderr)
    sys.exit(1)


def _connect():
    return _pg.connect(DSN)


def _binary(b: bytes):
    # psycopg2 needs Binary(); psycopg3 takes bytes directly.
    return _pg.Binary(b) if _DRIVER == "psycopg2" else b


def claim_one(conn):
    """Atomically claim the oldest pending order -> 'running'."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE health_reports SET status='running', updated_at=now()
            WHERE id = (
                SELECT id FROM health_reports
                WHERE status='pending'
                ORDER BY created_at
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id, domain, prepared_for
            """
        )
        row = cur.fetchone()
    conn.commit()
    return row  # (id, domain, prepared_for) or None


def render_report(domain: str, prepared_for: str | None) -> tuple[bytes, dict]:
    """Run the v8 healthreport CLI; return (pdf_bytes, metadata)."""
    out_dir = Path(tempfile.mkdtemp(prefix="healthrpt_"))
    cmd = [sys.executable, "-m", "healthreport.run", "--domain", domain, "--output", str(out_dir)]
    if prepared_for:
        cmd += ["--prepared-for", prepared_for]
    proc = subprocess.run(cmd, cwd=str(HERE), capture_output=True, text=True, timeout=TIMEOUT)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-1500:]
        raise RuntimeError(f"render failed (exit {proc.returncode}): {tail}")

    dom_dir = out_dir / domain.replace(".", "_")
    pdf_path = dom_dir / "health.pdf"
    if not pdf_path.exists():
        raise RuntimeError(f"no PDF produced at {pdf_path}")
    pdf_bytes = pdf_path.read_bytes()

    # Best-effort metadata from health.json.
    meta: dict = {}
    json_path = dom_dir / "health.json"
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            grade = data.get("grade") or (data.get("trust_grade") or {}).get("letter")
            score = data.get("score", data.get("composite_score", data.get("display_score")))
            summary = (
                data.get("summary")
                or data.get("headline")
                or (data.get("narrative") or {}).get("key_finding")
            )
            meta = {
                "grade": grade,
                "score": int(score) if isinstance(score, (int, float)) else None,
                "summary": (summary or "")[:1000] or None,
            }
        except Exception as e:  # metadata is non-fatal
            print(f"  (could not parse health.json: {e})")
    return pdf_bytes, meta


def mark_ready(conn, report_id: str, pdf: bytes, meta: dict):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE health_reports
            SET status='ready', pdf=%s, content_type='application/pdf',
                grade=%s, score=%s, summary=%s, error=NULL,
                completed_at=now(), updated_at=now()
            WHERE id=%s
            """,
            (_binary(pdf), meta.get("grade"), meta.get("score"), meta.get("summary"), report_id),
        )
    conn.commit()


def mark_failed(conn, report_id: str, err: str):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE health_reports SET status='failed', error=%s, updated_at=now() WHERE id=%s",
            (err[:2000], report_id),
        )
    conn.commit()


def main():
    print(f"[health_report_worker] starting (driver={_DRIVER}, poll={POLL}s)")
    conn = _connect()
    while True:
        try:
            if conn.closed:
                conn = _connect()
            claimed = claim_one(conn)
            if not claimed:
                time.sleep(POLL)
                continue
            report_id, domain, prepared_for = claimed
            print(f"[health_report_worker] rendering {domain} (id={report_id})")
            try:
                pdf, meta = render_report(domain, prepared_for)
                mark_ready(conn, report_id, pdf, meta)
                print(f"  ✅ ready: {domain} grade={meta.get('grade')} bytes={len(pdf)}")
            except Exception as e:
                print(f"  ❌ failed: {domain}: {e}")
                traceback.print_exc()
                try:
                    mark_failed(conn, report_id, str(e))
                except Exception:
                    conn = _connect()
                    mark_failed(conn, report_id, str(e))
        except KeyboardInterrupt:
            print("\n[health_report_worker] stopping")
            break
        except Exception as loop_err:
            print(f"[health_report_worker] loop error: {loop_err}", file=sys.stderr)
            time.sleep(POLL)
    try:
        conn.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
