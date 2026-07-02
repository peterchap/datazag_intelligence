"""
free_report_worker.py
---------------------
Generates the FREE external threat report for public lead-gen requests created by
the Customer Portal (`free_reports` table on Neon).

Runs the SAME refactored pipeline the paid report uses (report_pipeline) to build
the view-model, then renders the 5-page **Free Single-Domain Cyber Exposure
Report** (freereport) — the lead magnet whose page-5 seam upsells the Cross-Estate
Report. Shares the design system and the medallion/CT-log impersonation data:

  1. live DNS scan (~1s) -> build_view_model (medallion + platform impersonations)
     -> write teaser (grade + detected platforms + 7/30-day counts), status='teaser_ready'
  2. render the 5-page free report (HTML + MD) -> PDF
     -> status='ready', email the /r/<token> link

Run on the master:
    DATABASE_URL=<portal Neon DSN> python free_report_worker.py

Env:
    DATABASE_URL / PORTAL_DATABASE_URL   portal Neon DSN (required)
    INTELLIGENCE_BASE_URL, INTELLIGENCE_API_KEY   riskscore medallion endpoint
    PUBLIC_BASE_URL                      e.g. https://datazag.com (for the /r/<token> link)
    RESEND_API_KEY, EMAIL_FROM           outbound email (optional)
    FREE_REPORT_AUDIENCE                 default 'external_threat'
    FREE_REPORT_TIER                     default 'teaser'
    FREE_WORKER_POLL_SECONDS             default 10
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import traceback

from dotenv import load_dotenv
load_dotenv()

try:
    import psycopg2 as _pg
    _DRIVER = "psycopg2"
except ImportError:  # pragma: no cover
    import psycopg as _pg  # type: ignore
    _DRIVER = "psycopg"

import urllib.request

# Refactored report pipeline (same as run.py / health report) + the free renderer.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical_collect                                # noqa: E402
from report_pipeline import build_view_model            # noqa: E402
from freereport.renderer import FreeReportRenderer      # noqa: E402
from intelligence_client import IntelligenceClient, IntelligenceUnavailable  # noqa: E402
from branding import BrandConfig                        # noqa: E402

DSN = os.environ.get("PORTAL_DATABASE_URL") or os.environ.get("DATABASE_URL")
POLL = int(os.environ.get("FREE_WORKER_POLL_SECONDS", "10"))
BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://datazag.com").rstrip("/")

if not DSN:
    print("FATAL: DATABASE_URL (portal Neon) not set", file=sys.stderr)
    sys.exit(1)


def _connect():
    return _pg.connect(DSN)


def _binary(b: bytes):
    return _pg.Binary(b) if _DRIVER == "psycopg2" else b


def claim_one(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE free_reports SET status='running', updated_at=now()
            WHERE id = (
                SELECT id FROM free_reports WHERE status='pending'
                ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
            )
            RETURNING id, token, scanned_domain, email
            """
        )
        row = cur.fetchone()
    conn.commit()
    return row


async def _collect(domain: str):
    """Live scan + medallion view-model. Returns (vm, legacy_output, teaser)."""
    output = await canonical_collect.collect(domain)
    client = IntelligenceClient()
    vm = await build_view_model(domain, client, live_output=output)
    ext = vm.external_threat
    teaser = {
        "grade": getattr(vm.grade, "letter", None),
        "score": int(vm.composite_score or 0),
        "summary": getattr(vm.grade, "headline", None),
        "platforms": list(ext.detected_platforms or []),
        "impersonation": {
            "sevenDay": int(ext.total_7d or 0),
            "thirtyDay": int(ext.total_30d or 0),
            "perPlatform": {
                imp.platform: {"sevenDay": int(imp.count_7d or 0), "thirtyDay": int(imp.count_30d or 0)}
                for imp in (ext.impersonations or [])
            },
        },
    }
    return vm, output, teaser


async def _html_to_pdf(html: str):
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            pg = await b.new_page()
            await pg.set_content(html, wait_until="networkidle")
            pdf = await pg.pdf(format="A4", print_background=True, prefer_css_page_size=True,
                               margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
            await b.close()
            return pdf
    except Exception as e:
        print(f"  (PDF generation skipped: {e})")
        return None


def write_teaser(conn, rid, t):
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE free_reports SET status='teaser_ready', grade=%s, score=%s, summary=%s,
                   platforms=%s::jsonb, impersonation=%s::jsonb, updated_at=now() WHERE id=%s""",
            (t["grade"], t["score"], t["summary"], json.dumps(t["platforms"]),
             json.dumps(t["impersonation"]), rid),
        )
    conn.commit()


def finalize(conn, rid, html, md, pdf):
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE free_reports SET status='ready', html=%s, md=%s, pdf=%s,
                   completed_at=now(), updated_at=now() WHERE id=%s""",
            (html, md, _binary(pdf) if pdf else None, rid),
        )
    conn.commit()


def mark_failed(conn, rid, err):
    with conn.cursor() as cur:
        cur.execute("UPDATE free_reports SET status='failed', error=%s, updated_at=now() WHERE id=%s",
                    (err[:2000], rid))
    conn.commit()


def send_email(to_addr, domain, token):
    key = os.environ.get("RESEND_API_KEY")
    if not key:
        print("  (RESEND_API_KEY unset — skipping email)")
        return
    link = f"{BASE_URL}/r/{token}"
    payload = {
        "from": os.environ.get("EMAIL_FROM", "noreply@datazag.com"),
        "to": [to_addr],
        "subject": f"Your Datazag threat report for {domain}",
        "html": f"<p>Your free external threat report for <strong>{domain}</strong> is ready.</p>"
                f'<p><a href="{link}">View your report</a> (PDF &amp; Markdown downloads available there).</p>',
    }
    req = urllib.request.Request("https://api.resend.com/emails",
                                 data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=20)
        with _connect() as c2, c2.cursor() as cur:
            cur.execute("UPDATE free_reports SET emailed_at=now() WHERE token=%s", (token,))
            c2.commit()
        print(f"  📧 emailed {to_addr}")
    except Exception as e:
        print(f"  (email failed: {e})")


def process(conn, claimed):
    rid, token, domain, email = claimed
    print(f"[free_report_worker] {domain} (id={rid})")
    # Stage 1: live scan + medallion -> teaser
    vm, output, teaser = asyncio.run(_collect(domain))
    write_teaser(conn, rid, teaser)
    # Stage 2: render the 5-page free report (pure/sync) -> PDF -> finalize -> email
    brand = BrandConfig.load() if hasattr(BrandConfig, "load") else BrandConfig.default()
    renderer = FreeReportRenderer(vm, brand=brand)
    html = renderer.to_html(brand=brand)
    md = renderer.to_markdown()
    pdf = asyncio.run(_html_to_pdf(html))
    finalize(conn, rid, html, md, pdf)
    send_email(email, domain, token)
    print(f"  ✅ ready: {domain} grade={teaser['grade']}")


def main():
    print(f"[free_report_worker] starting (driver={_DRIVER}, poll={POLL}s, report=free_single_domain/v1.3)")
    conn = _connect()
    while True:
        try:
            if conn.closed:
                conn = _connect()
            claimed = claim_one(conn)
            if not claimed:
                time.sleep(POLL)
                continue
            try:
                process(conn, claimed)
            except IntelligenceUnavailable as e:
                print(f"  ❌ medallion unavailable: {e}")
                mark_failed(conn, claimed[0], f"intelligence unavailable: {e}")
            except Exception as e:
                print(f"  ❌ failed: {claimed[2]}: {e}")
                traceback.print_exc()
                try:
                    mark_failed(conn, claimed[0], str(e))
                except Exception:
                    conn = _connect(); mark_failed(conn, claimed[0], str(e))
        except KeyboardInterrupt:
            print("\n[free_report_worker] stopping"); break
        except Exception as loop_err:
            print(f"[free_report_worker] loop error: {loop_err}", file=sys.stderr)
            time.sleep(POLL)
    try:
        conn.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
