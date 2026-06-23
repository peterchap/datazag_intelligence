"""
run.py — Datazag Trust + Threat Surface report generator
--------------------------------------------------------
Post-split entry point. The medallion intelligence comes from the riskscore
HTTP service (intelligence_client); the live DNS scan (optional, --live) comes
from dnsproject and is POSTed for the server-side merge. Rendering is the
healthreport flagship engine across audience variants and tiers.

Usage:
    # Live scan (default) on the dnsproject host, then fetch medallion + impersonations:
    python run.py --domain example.com --audience all --tier full

    # Snapshot-only (skip the live scan), single variant:
    python run.py --domain example.com --no-live --audience flagship

    # Render a medallion payload captured earlier (no network):
    python run.py --input_json payloads/example.com.json --audience flagship

Outputs HTML + PDF + Markdown per requested audience to ./output/<domain>/.
Requires INTELLIGENCE_BASE_URL + INTELLIGENCE_API_KEY for the --domain paths.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from branding import BrandConfig
from intelligence_client import IntelligenceClient, IntelligenceUnavailable
from report_pipeline import (
    DEFAULT_AUDIENCES,
    build_view_model,
    is_medallion_payload,
    render_variants,
    view_model_from_legacy_output,
    view_model_from_medallion,
)

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", Path(__file__).parent / "output"))

# format → file extension; pdf is derived from html via Playwright
_EXT = {"html": "html", "markdown": "md"}


async def run(
    input_json: str = None,
    domain: str = None,
    audiences: list[str] = None,
    tier: str = "full",
    live: bool = True,
    partner_context: str = None,
    threat_context: str = None,
    output_dir: Path = None,
    brand_profile: str = None,
    skip_pdf: bool = False,
) -> dict:
    brand = BrandConfig.load(brand_profile)
    print(f"  Brand: {brand.brand_name}")
    audiences = audiences or list(DEFAULT_AUDIENCES)

    legacy: dict | None = None

    # ── Resolve a view-model ─────────────────────────────────────────────
    if input_json:
        with open(input_json, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        if is_medallion_payload(payload):
            print("  Input: medallion payload")
            vm = view_model_from_medallion(payload)
            domain = vm.domain
        else:
            # A legacy compiled `output` dict: render enrichment-only, deriving
            # the medallion from its embedded infrastructure_intelligence.
            print("  Input: legacy compiled output")
            legacy = payload
            domain = payload.get("domain", domain or "unknown")
            vm = view_model_from_legacy_output(payload)
    elif domain:
        # In-process riskscore (imports DomainIntelligenceAPI; no HTTP service needed).
        from local_intelligence import LocalIntelligenceClient
        client = LocalIntelligenceClient()
        try:
            # The backend collects the live scan (when --live) AND assembles the
            # complete view-model; run.py stays presentation-only — no raw `legacy`
            # rec threaded through. The renderer reads everything from the contract.
            vm = await build_view_model(domain, client, live=live)
        except IntelligenceUnavailable as e:
            raise SystemExit(
                f"  Intelligence unavailable: {e}\n"
                "  (check RISKSCORE_PATH / REPORTING_SNAPSHOT_DB)")
    else:
        raise ValueError("Must provide either --input_json or --domain")

    print(f"  Domain: {domain} · grade {vm.grade.letter} ({vm.composite_score}/100)"
          + ("" if vm.has_intelligence else " · not yet assessed"))

    # ── Render variants ──────────────────────────────────────────────────
    reports = render_variants(
        vm, audiences=audiences, tier=tier,
        formats=("html", "markdown"), legacy=legacy, brand=brand,
    )

    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    suffix = "" if tier == "full" else f".{tier}"
    html_paths: list[tuple[Path, Path]] = []
    for aud, formats in reports.items():
        for fmt, content in formats.items():
            path = out_dir / f"{aud}{suffix}.{_EXT[fmt]}"
            path.write_text(content, encoding="utf-8")
            if fmt == "html":
                html_paths.append((path, out_dir / f"{aud}{suffix}.pdf"))

    # ── PDF via Playwright ───────────────────────────────────────────────
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
                await page.goto(f"file:///{html_path.absolute().as_posix()}",
                                wait_until="networkidle")
                await page.pdf(path=str(pdf_path), format="A4", print_background=True,
                               prefer_css_page_size=True,
                               margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
            await browser.close()

    n_fmt = len(_EXT) + (0 if skip_pdf else 1)
    print(f"\n  Output written to {out_dir}/")
    print(f"  {len(reports) * n_fmt} files — {len(reports)} audiences × "
          f"{n_fmt} formats (HTML, Markdown{'' if skip_pdf else ', PDF'})")
    return {"domain": domain, "tier": tier, "audiences": audiences,
            "grade": vm.grade.letter, "composite_score": vm.composite_score}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag Trust + Threat Surface report generator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input_json", help="Medallion payload JSON (or a legacy compiled output dict)")
    group.add_argument("--domain", help="Domain to assess via the riskscore intelligence service")
    parser.add_argument("--audience", default="all",
                        choices=DEFAULT_AUDIENCES + ["all"],
                        help="Report variant (default: all)")
    parser.add_argument("--tier", default="full", choices=["teaser", "full"],
                        help="teaser = lead-gen edition (redacted); full = paid edition")
    parser.add_argument("--live", action=argparse.BooleanOptionalAction, default=True,
                        help="Run dnsproject's live DNS scan and POST it for the server-side merge "
                             "(default: on; use --no-live for a snapshot-only report)")
    parser.add_argument("--partner", default=None, help="Partner context for the live scan")
    parser.add_argument("--threat", default=None, help="Threat context for the live scan")
    parser.add_argument("--output-dir", default=None, help="Output directory (overrides OUTPUT_DIR)")
    parser.add_argument("--brand", default=None, help="Brand profile name")
    parser.add_argument("--skip-pdf", action="store_true", help="Skip Playwright PDF generation")
    args = parser.parse_args()

    audiences = list(DEFAULT_AUDIENCES) if args.audience == "all" else [args.audience]
    asyncio.run(run(
        input_json=args.input_json,
        domain=args.domain,
        audiences=audiences,
        tier=args.tier,
        live=args.live,
        partner_context=args.partner,
        threat_context=args.threat,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        brand_profile=args.brand,
        skip_pdf=args.skip_pdf,
    ))
