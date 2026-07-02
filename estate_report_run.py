"""
estate_report_run.py — Cross-Estate Domain Risk Report (v2.2) generator
-----------------------------------------------------------------------
Consumes a manifest of per-domain contract JSON, computes the cross-estate
analytics via the committed crossestate engine, enriches with the v2.2 layers
(resilience severity, discovery tiers, exception collapse, remediation
worksheet), and renders the 6-page + Appendix A design-continuous report.

Usage:
    python estate_report_run.py --manifest estate.json
    python estate_report_run.py --manifest estate.json --format json,html,markdown

Outputs to ./output/estate/<group>/estate_report.{html,md,json,pdf}.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from estatereport.build import build_estate_report_from_manifest
from estatereport.renderer import EstateReportRenderer

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", Path(__file__).parent / "output"))


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "estate").strip()) or "estate"


async def run(manifest: str, formats: list[str], output_dir: Path = None,
              skip_pdf: bool = False) -> dict:
    report = build_estate_report_from_manifest(manifest)
    print(f"  Group: {report.group} · grade {report.grade.grade} "
          f"({report.grade.score:.0f}/100) · {report.grade.domain_count} graded")
    print(f"  Exceptions: {len(report.exceptions)} · remediation patterns: "
          f"{len(report.remediation)} · appendix pages: {report.appendix_pages}")

    renderer = EstateReportRenderer(report)
    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / "estate" / _slug(report.group)
    out_dir.mkdir(parents=True, exist_ok=True)

    if "json" in formats:
        (out_dir / "estate_report.json").write_text(renderer.to_json(), encoding="utf-8")
    if "markdown" in formats:
        (out_dir / "estate_report.md").write_text(renderer.to_markdown(), encoding="utf-8")
    html_path = None
    if "html" in formats:
        html_path = out_dir / "estate_report.html"
        html_path.write_text(renderer.to_html(), encoding="utf-8")
    print(f"  Output → {out_dir}/estate_report.*")

    if html_path and not skip_pdf:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"])
            page = await browser.new_page()
            await page.goto(f"file:///{html_path.absolute().as_posix()}", wait_until="networkidle")
            await page.pdf(path=str(out_dir / "estate_report.pdf"), format="A4",
                           print_background=True, prefer_css_page_size=True,
                           margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
            await browser.close()
        print(f"  → {out_dir / 'estate_report.pdf'}")

    return {"group": report.group, "grade": report.grade.grade,
            "exceptions": len(report.exceptions), "appendix_pages": report.appendix_pages}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag Cross-Estate Domain Risk Report (v2.2)")
    parser.add_argument("--manifest", required=True, help="Estate manifest (JSON or CSV)")
    parser.add_argument("--format", default="json,html,markdown", help="Comma-separated formats")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--skip-pdf", action="store_true")
    args = parser.parse_args()
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    asyncio.run(run(manifest=args.manifest, formats=formats,
                    output_dir=Path(args.output_dir) if args.output_dir else None,
                    skip_pdf=args.skip_pdf))
