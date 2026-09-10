"""
healthreport/run.py
-------------------
Entry point for the v8 master Health Report.

Usage
-----
From the project root (so existing imports resolve):

    python -m healthreport.run --domain coffeecupsolutions.com
    python -m healthreport.run --dns_file excis.json

Outputs to ./output/<domain>/health.{html,pdf,json,md} alongside (not replacing)
the existing four-audience output.

Architecture
------------
This script does NOT reimplement the upstream pipeline. It imports the same
build_output(...) flow used by the original run.py — same DNS resolution,
findings, scorer, narrative — then dispatches to HealthReportRenderer instead
of render_all().

If the existing run.py refactors its build_output into a callable, we can
import that directly and shrink this to ~30 lines.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

# Re-use parent project's pipeline.
# The upstream run() function builds the canonical output dict AND writes the
# existing four-audience output. Calling it preserves the parallel-coexistence
# guarantee Peter wanted (old keeps producing; new produces alongside under
# different filenames).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from playwright.async_api import async_playwright  # noqa: E402

from branding import BrandConfig                   # noqa: E402
from healthreport.renderer import HealthReportRenderer  # noqa: E402
from intelligence_client import IntelligenceClient  # noqa: E402
from report_pipeline import (                       # noqa: E402
    build_view_model,
    is_medallion_payload,
    view_model_from_legacy_output,
    view_model_from_medallion,
)

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "./output"))


# ---------------------------------------------------------------------------
# Render + write
# ---------------------------------------------------------------------------

async def render_health(
    domain: str | None = None,
    dns_file: str | None = None,
    output_dir: Path | None = None,
    audience: str = "insurer",      # used upstream for narrative tuning only
    partner: str | None = None,
    threat: str | None = None,
    skip_pdf: bool = False,
    skip_legacy: bool = False,
    prepared_for: str | None = None,
    variant: str = "flagship",
    tier: str = "full",
) -> Path:
    """
    Build the medallion-backed view-model for the given domain or dns_file, then
    render the Health Report (HTML + PDF + JSON + MD) to health.* files.

    `variant`/`tier` select the report edition (default flagship/full — the paid
    report the portal worker orders). `audience` is retained for CLI
    back-compat but no longer drives content (narrative is medallion-derived).

    The `prepared_for` parameter sets the "Prepared for" line on the report
    cover. When unset, the cover shows the domain itself. Set this when the
    report is being prepared for a specific buyer (e.g. an MSSP delivering it
    to their client, or a Datazag-direct customer who has provided their
    company name).

    Returns the output directory.
    """
    if not domain and not dns_file:
        raise ValueError("Provide --domain or --dns_file")

    print(f"\n[healthreport] Pipeline run starting for {domain or dns_file}")

    # ── Step 1: build the medallion-backed view-model (same flow as run.py) ─
    # `--dns_file` is a pre-collected payload (a medallion JSON or a legacy scan
    # output dict); `--domain` runs the live scan + fetches the medallion.
    legacy: dict | None = None
    if dns_file:
        with open(dns_file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        if is_medallion_payload(payload):
            vm = view_model_from_medallion(payload)
            resolved_domain = vm.domain
        else:                       # a legacy compiled scan-output dict
            legacy = payload
            resolved_domain = payload.get("domain", domain or "unknown")
            vm = view_model_from_legacy_output(payload)
    else:
        # In-process: celery_app_realtime collection + riskscore (imported) + lake.
        from local_intelligence import LocalIntelligenceClient
        import canonical_collect
        client = LocalIntelligenceClient()
        legacy = await canonical_collect.collect(domain)
        vm = await build_view_model(domain, client, live_output=legacy)
        resolved_domain = domain

    # Prepared-for override (the renderer reads it from the legacy output dict).
    if prepared_for and legacy is not None:
        legacy["prepared_for"] = prepared_for

    # ── Step 2: render the Health Report ─────────────────────────────────
    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / resolved_domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    brand = BrandConfig.load() if hasattr(BrandConfig, "load") else BrandConfig.default()
    renderer = HealthReportRenderer(vm, audience=variant, tier=tier, legacy=legacy or {})

    formats = {
        "html": ("health.html", renderer.to_html(brand=brand)),
        "json": ("health.json", renderer.render(fmt="json", brand=brand)),
        "md":   ("health.md",   renderer.to_markdown(brand=brand)),
    }
    for ext, (filename, content) in formats.items():
        path = out_dir / filename
        path.write_text(content, encoding="utf-8")
        print(f"  → {path}")

    # ── Step 3: PDF via Playwright ────────────────────────────────────────
    if not skip_pdf:
        html_path = out_dir / "health.html"
        pdf_path  = out_dir / "health.pdf"
        print(f"\n[healthreport] Converting HTML to PDF...")
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            page = await browser.new_page()
            await page.goto(
                f"file:///{html_path.absolute().as_posix()}",
                wait_until="networkidle",
            )
            await page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                prefer_css_page_size=True,
                margin={"top": "0", "right": "0", "bottom": "0", "left": "0"},
            )
            await browser.close()
        print(f"  → {pdf_path}")

    print(f"\n[healthreport] Output: {out_dir}/")
    return out_dir


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate the v8 master Datazag Health Report.",
    )
    parser.add_argument("--domain",   help="Domain to assess (e.g. coffeecupsolutions.com)")
    parser.add_argument("--dns_file", help="Pre-resolved DNS JSON file")
    parser.add_argument("--audience", default="insurer",
                        help="Upstream narrative audience (insurer/consultant/it/sales). "
                             "Affects the LLM-generated narrative strings the new renderer pulls from. "
                             "Default: insurer.")
    parser.add_argument("--partner",  help="Optional partner brand override")
    parser.add_argument("--threat",   help="Optional threat context override")
    parser.add_argument("--output",   help="Output directory (defaults to ./output)")
    parser.add_argument("--skip-pdf", action="store_true",
                        help="Skip Playwright PDF generation")
    parser.add_argument("--prepared-for",
                        help="Override the 'Prepared for' line on the report cover. "
                             "When unset, the cover shows the domain itself. Set this when "
                             "preparing the report for a specific named buyer.")
    parser.add_argument("--variant", default="flagship",
                        choices=["flagship", "insurer", "advisory", "remediation", "external_threat"],
                        help="Report variant to render. Default: flagship.")
    parser.add_argument("--tier", default="full", choices=["teaser", "full"],
                        help="teaser = lead-gen edition (specifics redacted); full = paid edition.")
    args = parser.parse_args()

    out = Path(args.output) if args.output else None
    asyncio.run(render_health(
        domain=args.domain,
        dns_file=args.dns_file,
        output_dir=out,
        audience=args.audience,
        partner=args.partner,
        threat=args.threat,
        skip_pdf=args.skip_pdf,
        prepared_for=args.prepared_for,
        variant=args.variant,
        tier=args.tier,
    ))


if __name__ == "__main__":
    main()
