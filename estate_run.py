"""
estate_run.py — Datazag cross-estate (portfolio) report generator
-----------------------------------------------------------------
Consumes a manifest of per-domain contract JSON files, computes the cross-estate
analytics, and renders the exception-first summary-of-summaries. Mirrors run.py.

Usage:
    # Both human cuts + JSON from a manifest:
    python estate_run.py --manifest estate.json --cut all --format json,html,markdown

    # Oversight cut only (insurer/board), JSON always complete regardless:
    python estate_run.py --manifest estate.json --cut oversight

    # Custom thresholds:
    python estate_run.py --manifest estate.json --thresholds thresholds.json

Outputs to ./output/estate/<group>/:
    estate.json                 (complete payload — cut-independent)
    estate.<cut>.md / .html / .pdf
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from crossestate.build import build_estate_from_manifest
from crossestate.contract import EstateThresholds
from crossestate.cuts import CUT_KEYS
from crossestate.renderer import CrossEstateRenderer

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", Path(__file__).parent / "output"))


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "estate").strip()) or "estate"


async def run(
    manifest: str,
    cuts: list[str],
    formats: list[str],
    thresholds_path: str | None = None,
    output_dir: Path | None = None,
    brand_profile: str | None = None,
    skip_pdf: bool = False,
) -> dict:
    thresholds = None
    if thresholds_path:
        with open(thresholds_path, "r", encoding="utf-8") as fh:
            thresholds = EstateThresholds.model_validate(json.load(fh))

    estate = build_estate_from_manifest(manifest, thresholds=thresholds)
    print(f"  Group: {estate.group} · {estate.domain_count} domains "
          f"({estate.assessed_count} assessed) · grade {estate.estate_grade} "
          f"({estate.estate_score}/100)")
    print(f"  Exceptions: {len(estate.exceptions)} · outlier segments: "
          f"{', '.join(estate.variance.outlier_segments) or 'none'}")

    brand = None
    if brand_profile:
        from branding import BrandConfig
        brand = BrandConfig.load(brand_profile)

    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / "estate" / _slug(estate.group)
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON is complete and cut-independent — write it once.
    if "json" in formats:
        renderer = CrossEstateRenderer(estate, cut=cuts[0], brand=brand)
        (out_dir / "estate.json").write_text(renderer.to_json(), encoding="utf-8")

    html_paths: list[tuple[Path, Path]] = []
    for cut in cuts:
        renderer = CrossEstateRenderer(estate, cut=cut, brand=brand)
        if "markdown" in formats:
            (out_dir / f"estate.{cut}.md").write_text(renderer.to_markdown(), encoding="utf-8")
        if "html" in formats:
            html_path = out_dir / f"estate.{cut}.html"
            html_path.write_text(renderer.to_html(), encoding="utf-8")
            html_paths.append((html_path, out_dir / f"estate.{cut}.pdf"))

    if html_paths and not skip_pdf:
        from playwright.async_api import async_playwright
        print(f"\n  Converting {len(html_paths)} HTML reports to PDF...")
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            for html_path, pdf_path in html_paths:
                print(f"  → {pdf_path.name}")
                page = await browser.new_page()
                await page.goto(f"file:///{html_path.absolute().as_posix()}", wait_until="networkidle")
                await page.pdf(path=str(pdf_path), format="A4", print_background=True,
                               prefer_css_page_size=True,
                               margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
            await browser.close()

    print(f"\n  Output written to {out_dir}/")
    return {"group": estate.group, "cuts": cuts, "grade": estate.estate_grade,
            "domains": estate.domain_count, "exceptions": len(estate.exceptions)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag cross-estate report generator")
    parser.add_argument("--manifest", required=True, help="Estate manifest (JSON or CSV)")
    parser.add_argument("--cut", default="all", choices=list(CUT_KEYS) + ["all"],
                        help="Human render cut (default: all). JSON is always complete.")
    parser.add_argument("--format", default="json,html,markdown",
                        help="Comma-separated: json,html,markdown (default: all)")
    parser.add_argument("--thresholds", default=None, help="EstateThresholds JSON override")
    parser.add_argument("--output-dir", default=None, help="Output directory (overrides OUTPUT_DIR)")
    parser.add_argument("--brand", default=None, help="Brand profile name")
    parser.add_argument("--skip-pdf", action="store_true", help="Skip Playwright PDF generation")
    args = parser.parse_args()

    cuts = list(CUT_KEYS) if args.cut == "all" else [args.cut]
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    asyncio.run(run(
        manifest=args.manifest, cuts=cuts, formats=formats,
        thresholds_path=args.thresholds,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        brand_profile=args.brand, skip_pdf=args.skip_pdf,
    ))
