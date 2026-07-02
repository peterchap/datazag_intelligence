"""
free_run.py — Free Single-Domain Cyber Exposure Report generator
----------------------------------------------------------------
Renders the 5-page free report from a per-domain ReportViewModel. Mirrors run.py.

Usage:
    # Render a saved contract (ReportViewModel dump or medallion payload):
    python free_run.py --input_json payloads/qbeeurope.com.json

    # Live: assess a domain via the riskscore service, then render:
    python free_run.py --domain qbeeurope.com

Outputs HTML + Markdown + JSON (+ PDF via Playwright) to ./output/<domain>/free.*
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from freereport.renderer import FreeReportRenderer

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", Path(__file__).parent / "output"))


def _vm_from_payload(payload: dict):
    """ReportViewModel dump (preferred) or medallion payload (fallback). Built
    from the contract primitives so this CLI doesn't require the render stack for
    the offline path."""
    from intelligence_contract import ReportViewModel
    if "risk_assessment" in payload and "schema_version" in payload:
        from findings_rules import derive_findings
        from intelligence_contract import DomainIntelligence, build_view_models
        di = DomainIntelligence.model_validate(payload)
        return build_view_models(di, findings=derive_findings(di, []))
    return ReportViewModel.model_validate(payload)


async def run(input_json: str = None, domain: str = None, live: bool = True,
              output_dir: Path = None, skip_pdf: bool = False) -> dict:
    if input_json:
        with open(input_json, "r", encoding="utf-8") as fh:
            vm = _vm_from_payload(json.load(fh))
        domain = vm.domain
    elif domain:
        from intelligence_client import IntelligenceUnavailable
        from local_intelligence import LocalIntelligenceClient
        from report_pipeline import build_view_model
        client = LocalIntelligenceClient()
        try:
            vm = await build_view_model(domain, client, live=live)
        except IntelligenceUnavailable as e:
            raise SystemExit(f"  Intelligence unavailable: {e}")
    else:
        raise ValueError("Must provide either --input_json or --domain")

    renderer = FreeReportRenderer(vm)
    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "free.html").write_text(renderer.to_html(), encoding="utf-8")
    (out_dir / "free.md").write_text(renderer.to_markdown(), encoding="utf-8")
    (out_dir / "free.json").write_text(renderer.to_json(), encoding="utf-8")
    print(f"  {domain} · free report → {out_dir}/free.{{html,md,json}}")

    if not skip_pdf:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"])
            page = await browser.new_page()
            html_path = out_dir / "free.html"
            await page.goto(f"file:///{html_path.absolute().as_posix()}", wait_until="networkidle")
            await page.pdf(path=str(out_dir / "free.pdf"), format="A4", print_background=True,
                           prefer_css_page_size=True,
                           margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
            await browser.close()
        print(f"  → {out_dir / 'free.pdf'}")

    return {"domain": domain, "pages": 5}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag Free Single-Domain report generator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input_json", help="ReportViewModel dump or medallion payload")
    group.add_argument("--domain", help="Domain to assess via the riskscore service")
    parser.add_argument("--live", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--skip-pdf", action="store_true")
    args = parser.parse_args()
    asyncio.run(run(input_json=args.input_json, domain=args.domain, live=args.live,
                    output_dir=Path(args.output_dir) if args.output_dir else None,
                    skip_pdf=args.skip_pdf))
