"""
report_order_worker.py
----------------------
WU16 delivery worker. Polls the Customer Portal Neon DB for pending paid
`report_orders` and renders each, writing the PDF (+ grade/summary) back into
the row for the portal to serve. Mirrors health_report_worker.

Two SKUs:
  * domain_risk_report  — single domain. Rendered via the paid healthreport
    pipeline (`python -m healthreport.run`), the executive-core + technical-
    remediation single-domain assessment. [MAPPING: the paid single-domain
    report == the healthreport renderer. If a distinct Domain Risk Report
    renderer lands, swap the CLI in render_domain_risk().]
  * cross_estate_report — the scope's declared domains are collected into
    contracts, an estate manifest is built, and the v2.2 Cross-Estate report is
    rendered to PDF. The delivered set hash is recomputed and compared to the
    hash frozen at purchase; a mismatch (estate changed since scope) is surfaced
    in the summary, never silently delivered as if unchanged.

Run on the master (pipeline + Chromium + API keys):
    DATABASE_URL=<portal Neon DSN> python report_order_worker.py

Env:
    DATABASE_URL / PORTAL_DATABASE_URL   portal Neon DSN (required)
    REPORT_WORKER_POLL_SECONDS           poll interval (default 20)
    REPORT_WORKER_TIMEOUT                per-order render timeout sec (default 900)
    (plus the pipeline's own: INTELLIGENCE_*, ANTHROPIC_API_KEY, CERTSPOTTER_TOKEN…)

Claim is atomic via FOR UPDATE SKIP LOCKED, so multiple workers are safe.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv
load_dotenv()

try:
    import psycopg2 as _pg
    _DRIVER = "psycopg2"
except ImportError:  # pragma: no cover
    import psycopg as _pg  # type: ignore
    _DRIVER = "psycopg"

DSN = os.environ.get("PORTAL_DATABASE_URL") or os.environ.get("DATABASE_URL")
POLL = int(os.environ.get("REPORT_WORKER_POLL_SECONDS", "20"))
TIMEOUT = int(os.environ.get("REPORT_WORKER_TIMEOUT", "900"))
HERE = Path(__file__).resolve().parent

if not DSN:
    print("FATAL: DATABASE_URL (portal Neon) not set", file=sys.stderr)
    sys.exit(1)


def _connect():
    return _pg.connect(DSN)


def _binary(b: bytes):
    return _pg.Binary(b) if _DRIVER == "psycopg2" else b


def claim_one(conn):
    """Atomically claim the oldest pending order -> 'running'."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE report_orders SET status='running', updated_at=now()
            WHERE id = (
                SELECT id FROM report_orders WHERE status='pending'
                ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
            )
            RETURNING id, product_key, domain, scope_token, prepared_for, frozen_set_hash
            """
        )
        row = cur.fetchone()
    conn.commit()
    return row


def _scope_domains(conn, scope_token: str) -> tuple[list[str], str | None]:
    with conn.cursor() as cur:
        cur.execute("SELECT domains, email FROM scope_requests WHERE token=%s", (scope_token,))
        row = cur.fetchone()
    if not row:
        raise RuntimeError(f"scope {scope_token} not found for cross-estate order")
    domains, email = row
    domains = domains if isinstance(domains, list) else json.loads(domains or "[]")
    return domains, email


# ── domain_risk_report: paid single-domain assessment ────────────────────────

def render_domain_risk(domain: str, prepared_for: str | None) -> tuple[bytes, dict]:
    out_dir = Path(tempfile.mkdtemp(prefix="drr_"))
    cmd = [sys.executable, "-m", "healthreport.run", "--domain", domain, "--output", str(out_dir)]
    if prepared_for:
        cmd += ["--prepared-for", prepared_for]
    proc = subprocess.run(cmd, cwd=str(HERE), capture_output=True, text=True, timeout=TIMEOUT)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-1500:]
        raise RuntimeError(f"domain-risk render failed (exit {proc.returncode}): {tail}")
    dom_dir = out_dir / domain.replace(".", "_")
    pdf_path = dom_dir / "health.pdf"
    if not pdf_path.exists():
        raise RuntimeError(f"no PDF produced at {pdf_path}")
    meta: dict = {}
    json_path = dom_dir / "health.json"
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            grade = data.get("grade") or (data.get("trust_grade") or {}).get("letter")
            score = data.get("score", data.get("composite_score", data.get("display_score")))
            summary = data.get("summary") or data.get("headline") or (data.get("narrative") or {}).get("key_finding")
            meta = {"grade": grade,
                    "score": int(score) if isinstance(score, (int, float)) else None,
                    "summary": (summary or "")[:1000] or None}
        except Exception as e:
            print(f"  (could not parse health.json: {e})")
    return pdf_path.read_bytes(), meta


# ── cross_estate_report: collect declared domains → estate report ────────────

async def _collect_contracts(domains: list[str], out_dir: Path) -> None:
    """Collect each declared domain into a ReportViewModel dump the estate
    manifest points at (same collect path as the scope worker)."""
    import canonical_collect
    from report_pipeline import build_view_model
    from intelligence_client import IntelligenceClient

    client = IntelligenceClient()
    for domain in domains:
        output = await canonical_collect.collect(domain)
        vm = await build_view_model(domain, client, live_output=output)
        (out_dir / f"{domain}.json").write_text(
            json.dumps(vm.model_dump(mode="json"), default=str), encoding="utf-8")


def render_cross_estate(domains: list[str], group: str, frozen_hash: str | None) -> tuple[bytes, dict]:
    from estatereport.build import build_estate_report_from_manifest
    from estatereport.renderer import EstateReportRenderer
    from scopeteaser.compose import estate_set_hash

    if not domains:
        raise RuntimeError("cross-estate order has no declared domains")
    work = Path(tempfile.mkdtemp(prefix="estate_"))
    asyncio.run(_collect_contracts(domains, work))
    manifest = {"group": group, "domains": [
        {"domain": d, "segment": None, "contract_path": f"{d}.json"} for d in domains]}
    manifest_path = work / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = build_estate_report_from_manifest(str(manifest_path))
    renderer = EstateReportRenderer(report)
    html_path = work / "estate_report.html"
    html_path.write_text(renderer.to_html(), encoding="utf-8")
    pdf = _html_to_pdf(html_path)

    # Drift check: the delivered graded estate vs what was priced/bought.
    tiers = {"declared": report.discovery.tiers.get("declared", []),
             "strong": report.discovery.tiers.get("strong", [])}
    delivered_hash = estate_set_hash(tiers)
    summary = (f"Estate grade {report.grade.grade} ({report.grade.score:.0f}/100); "
               f"{report.grade.domain_count} graded.")
    if frozen_hash and delivered_hash != frozen_hash:
        summary += (" NOTE: the estate changed since scope confirmation — review scope "
                    "before sending (possible-tier confirmations expand scope by agreement).")
        print(f"  ⚠ set-hash drift: frozen={frozen_hash[:12]} delivered={delivered_hash[:12]}")
    return pdf, {"grade": report.grade.grade, "score": int(report.grade.score),
                 "summary": summary[:1000]}


def _html_to_pdf(html_path: Path) -> bytes:
    async def _run() -> bytes:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"])
            page = await browser.new_page()
            await page.goto(f"file:///{html_path.absolute().as_posix()}", wait_until="networkidle")
            pdf = await page.pdf(format="A4", print_background=True, prefer_css_page_size=True,
                                 margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
            await browser.close()
            return pdf
    return asyncio.run(_run())


# ── write-back ───────────────────────────────────────────────────────────────

def mark_ready(conn, order_id: str, pdf: bytes, meta: dict):
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE report_orders SET status='ready', pdf=%s, content_type='application/pdf',
                   grade=%s, score=%s, summary=%s, error=NULL, completed_at=now(), updated_at=now()
               WHERE id=%s""",
            (_binary(pdf), meta.get("grade"), meta.get("score"), meta.get("summary"), order_id),
        )
    conn.commit()


def mark_failed(conn, order_id: str, err: str):
    with conn.cursor() as cur:
        cur.execute("UPDATE report_orders SET status='failed', error=%s, updated_at=now() WHERE id=%s",
                    (err[:2000], order_id))
    conn.commit()


def process(conn, claimed):
    order_id, product_key, domain, scope_token, prepared_for, frozen_hash = claimed
    print(f"[report_order_worker] {product_key} (id={order_id})")
    if product_key == "domain_risk_report":
        if not domain:
            raise RuntimeError("domain_risk_report order has no domain")
        return render_domain_risk(domain, prepared_for)
    if product_key == "cross_estate_report":
        domains, email = _scope_domains(conn, scope_token)
        group = prepared_for or (domains[0].split(".")[0].title() if domains else "Estate")
        return render_cross_estate(domains, group, frozen_hash)
    raise RuntimeError(f"unknown product_key {product_key!r}")


def main():
    print(f"[report_order_worker] starting (driver={_DRIVER}, poll={POLL}s)")
    conn = _connect()
    while True:
        try:
            if conn.closed:
                conn = _connect()
            claimed = claim_one(conn)
            if not claimed:
                time.sleep(POLL)
                continue
            order_id = claimed[0]
            try:
                pdf, meta = process(conn, claimed)
                mark_ready(conn, order_id, pdf, meta)
                print(f"  ✅ ready: id={order_id} grade={meta.get('grade')} bytes={len(pdf)}")
            except Exception as e:
                print(f"  ❌ failed: id={order_id}: {e}")
                traceback.print_exc()
                try:
                    mark_failed(conn, order_id, str(e))
                except Exception:
                    conn = _connect()
                    mark_failed(conn, order_id, str(e))
        except KeyboardInterrupt:
            print("\n[report_order_worker] stopping")
            break
        except Exception as loop_err:
            print(f"[report_order_worker] loop error: {loop_err}", file=sys.stderr)
            time.sleep(POLL)
    try:
        conn.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
