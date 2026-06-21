"""
free_report_worker.py
---------------------
Generates the FREE external threat report for public lead-gen requests created by
the Customer Portal (`free_reports` table on Neon).

Two-stage per order so the portal can show an instant teaser while the full
report renders:
  1. detect platforms from DNS + compute 7/30-day impersonation counts ->
     write teaser fields, status='teaser_ready'
  2. render HTML + Markdown + PDF -> write artifacts, status='ready', email link

Run on the master:
    DATABASE_URL=<portal Neon DSN> python free_report_worker.py

Env:
    DATABASE_URL / PORTAL_DATABASE_URL   portal Neon DSN (required)
    PUBLIC_BASE_URL                      e.g. https://datazag.com (for the /r/<token> link)
    RESEND_API_KEY, EMAIL_FROM           outbound email (optional; skips email if unset)
    FREE_WORKER_POLL_SECONDS             default 10
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

try:
    import psycopg2 as _pg
    _DRIVER = "psycopg2"
except ImportError:  # pragma: no cover
    import psycopg as _pg  # type: ignore
    _DRIVER = "psycopg"

import urllib.request

DSN = os.environ.get("PORTAL_DATABASE_URL") or os.environ.get("DATABASE_URL")
POLL = int(os.environ.get("FREE_WORKER_POLL_SECONDS", "10"))
BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://datazag.com").rstrip("/")

if not DSN:
    print("FATAL: DATABASE_URL (portal Neon) not set", file=sys.stderr)
    sys.exit(1)


# Map detected platform names -> watchlist terms that carry impersonation data.
PLATFORM_TERM_MAP = {
    "microsoft 365": ["microsoft", "office365", "sharepoint", "onedrive", "outlook"],
    "microsoft":     ["microsoft", "office365", "sharepoint", "onedrive", "outlook"],
    "google workspace": ["google", "gmail"],
    "google":        ["google", "gmail"],
    "okta":          ["okta"],
    "salesforce":    ["salesforce"],
    "zoom":          ["zoom"],
    "dropbox":       ["dropbox"],
    "docusign":      ["docusign"],
    "atlassian":     ["atlassian", "jira", "confluence"],
    "paypal":        ["paypal"],
    "stripe":        ["stripe"],
}


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


def detect_platforms(domain: str) -> list[str]:
    """Identify platforms a domain relies on, reusing the dnsproject fingerprinting.
    Returns display names. Falls back to [] if the pipeline isn't importable."""
    try:
        import asyncio
        from dnsproject.scripts.compile_intelligence import run as compile_intel  # type: ignore
        out = asyncio.run(compile_intel(domain=domain, audience="it"))
        names: list[str] = []
        txt = (out or {}).get("txt_intelligence", {}) or {}
        names += txt.get("all_identified", []) or []
        tech = (out or {}).get("technographics", {}) or {}
        for k in ("mx_provider_name", "ns_provider_name"):
            if tech.get(k):
                names.append(tech[k])
        # de-dup, preserve order
        seen, uniq = set(), []
        for n in names:
            key = n.strip().lower()
            if key and key not in seen:
                seen.add(key); uniq.append(n.strip())
        return uniq
    except Exception as e:
        print(f"  (platform detection unavailable: {e})")
        return []


def impersonation_counts(conn, platforms: list[str]) -> dict:
    """7/30-day impersonation activity for the detected platforms, from watchlist_hits."""
    terms = set()
    for p in platforms:
        key = p.strip().lower()
        terms.update(PLATFORM_TERM_MAP.get(key, [key.replace(" ", "")]))
    terms = [t for t in terms if t]
    if not terms:
        return {"sevenDay": 0, "thirtyDay": 0, "perPlatform": {}}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT term,
                   count(distinct domain) FILTER (WHERE last_seen >= now() - interval '7 days')  AS d7,
                   count(distinct domain) FILTER (WHERE last_seen >= now() - interval '30 days') AS d30
            FROM watchlist_hits
            WHERE term = ANY(%s)
            GROUP BY term
            """,
            (terms,),
        )
        rows = cur.fetchall()
    per = {t: {"sevenDay": int(d7 or 0), "thirtyDay": int(d30 or 0)} for (t, d7, d30) in rows}
    return {
        "sevenDay": sum(v["sevenDay"] for v in per.values()),
        "thirtyDay": sum(v["thirtyDay"] for v in per.values()),
        "perPlatform": per,
    }


def grade_from(counts: dict) -> tuple[str, int, str]:
    """Lightweight exposure grade for the FREE report (higher impersonation = worse).
    Replace with the canonical scorer if desired."""
    m = counts.get("thirtyDay", 0)
    score = min(100, m * 4)  # crude exposure proxy
    bands = [(5, "A", "Minimal impersonation activity"), (15, "B", "Low impersonation activity"),
             (35, "C", "Moderate impersonation activity"), (60, "D", "Elevated impersonation activity"),
             (85, "E", "High impersonation activity"), (101, "F", "Critical impersonation activity")]
    for cutoff, letter, headline in bands:
        if score < cutoff:
            return letter, score, headline
    return "F", 100, "Critical impersonation activity"


def write_teaser(conn, rid, grade, score, summary, platforms, counts):
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE free_reports SET status='teaser_ready', grade=%s, score=%s, summary=%s,
                   platforms=%s::jsonb, impersonation=%s::jsonb, updated_at=now() WHERE id=%s""",
            (grade, score, summary, json.dumps(platforms), json.dumps(counts), rid),
        )
    conn.commit()


def build_html(domain, grade, score, summary, platforms, counts) -> str:
    rows = "".join(
        f"<tr><td>{t}</td><td style='text-align:right'>{v['sevenDay']}</td><td style='text-align:right'>{v['thirtyDay']}</td></tr>"
        for t, v in (counts.get("perPlatform") or {}).items()
    ) or "<tr><td colspan=3 style='color:#888'>No impersonation activity recorded for your platforms in this window.</td></tr>"
    plats = ", ".join(platforms) if platforms else "None detected"
    return f"""<!doctype html><html><head><meta charset=utf-8>
<style>body{{font-family:Arial,Helvetica,sans-serif;color:#0f172a;max-width:760px;margin:40px auto;padding:0 24px}}
h1{{font-size:28px}} .grade{{font-size:64px;font-weight:800}} table{{width:100%;border-collapse:collapse;margin:16px 0}}
td,th{{border-bottom:1px solid #e2e8f0;padding:8px;text-align:left}} .muted{{color:#64748b}}
.cta{{margin-top:28px;padding:18px;background:#f1f5f9;border-radius:8px}}</style></head><body>
<p class=muted>Datazag — Free External Threat Report</p>
<h1>{domain}</h1>
<div class=grade>{grade}</div>
<p>{summary} (exposure score {score}/100)</p>
<h3>Platforms detected on your domain</h3><p>{plats}</p>
<h3>Platform impersonation activity</h3>
<table><tr><th>Platform</th><th style='text-align:right'>Last 7 days</th><th style='text-align:right'>Last 30 days</th></tr>{rows}</table>
<p class=muted>Counts are distinct look-alike domains observed impersonating these platforms across the Datazag corpus.</p>
<div class=cta><strong>Want the full picture?</strong><br>The full report adds your DNS defensive posture,
step-by-step remediation, and subdomain exposure with issues highlighted — plus continuous monitoring.
<br><br><a href="{BASE_URL}/register?domain={domain}">Get continuous monitoring →</a></div>
</body></html>"""


def build_md(domain, grade, score, summary, platforms, counts) -> str:
    lines = [f"# Datazag Free External Threat Report — {domain}", "",
             f"**Trust grade: {grade}** (exposure score {score}/100)", "", summary, "",
             "## Platforms detected", ", ".join(platforms) or "None detected", "",
             "## Platform impersonation activity", "", "| Platform | 7 days | 30 days |", "|---|---:|---:|"]
    for t, v in (counts.get("perPlatform") or {}).items():
        lines.append(f"| {t} | {v['sevenDay']} | {v['thirtyDay']} |")
    lines += ["", f"Get the full report + monitoring: {BASE_URL}/register?domain={domain}"]
    return "\n".join(lines)


def html_to_pdf(html: str) -> bytes | None:
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _render():
            async with async_playwright() as p:
                b = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                pg = await b.new_page()
                await pg.set_content(html, wait_until="networkidle")
                pdf = await pg.pdf(format="A4", print_background=True, margin={"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"})
                await b.close()
                return pdf
        return asyncio.run(_render())
    except Exception as e:
        print(f"  (PDF generation skipped: {e})")
        return None


def finalize(conn, rid, html, md, pdf):
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE free_reports SET status='ready', html=%s, md=%s, pdf=%s,
                   completed_at=now(), updated_at=now() WHERE id=%s""",
            (html, md, _binary(pdf) if pdf else None, rid),
        )
    conn.commit()


def send_email(to_addr: str, domain: str, token: str):
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
                f'<p><a href="{link}">View your report</a> (PDF & Markdown downloads available there).</p>',
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


def mark_failed(conn, rid, err):
    with conn.cursor() as cur:
        cur.execute("UPDATE free_reports SET status='failed', error=%s, updated_at=now() WHERE id=%s", (err[:2000], rid))
    conn.commit()


def main():
    print(f"[free_report_worker] starting (driver={_DRIVER}, poll={POLL}s, base={BASE_URL})")
    conn = _connect()
    while True:
        try:
            if conn.closed:
                conn = _connect()
            claimed = claim_one(conn)
            if not claimed:
                time.sleep(POLL)
                continue
            rid, token, domain, email = claimed
            print(f"[free_report_worker] {domain} (id={rid})")
            try:
                platforms = detect_platforms(domain)
                counts = impersonation_counts(conn, platforms)
                grade, score, headline = grade_from(counts)
                summary = headline
                write_teaser(conn, rid, grade, score, summary, platforms, counts)

                html = build_html(domain, grade, score, summary, platforms, counts)
                md = build_md(domain, grade, score, summary, platforms, counts)
                pdf = html_to_pdf(html)
                finalize(conn, rid, html, md, pdf)
                send_email(email, domain, token)
                print(f"  ✅ ready: {domain} grade={grade}")
            except Exception as e:
                print(f"  ❌ failed: {domain}: {e}")
                traceback.print_exc()
                try:
                    mark_failed(conn, rid, str(e))
                except Exception:
                    conn = _connect(); mark_failed(conn, rid, str(e))
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
