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
from run import run as upstream_run  # type: ignore  # noqa: E402

from playwright.async_api import async_playwright  # noqa: E402

from branding import BrandConfig                   # noqa: E402
from healthreport.renderer import HealthReportRenderer  # noqa: E402

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
) -> Path:
    """
    Run the upstream pipeline against the given domain or dns_file, then
    render the v8 Health Report (HTML + PDF + JSON + MD).

    By default the upstream pipeline ALSO writes the existing four-audience
    output (insurer/consultant/it/sales) to the same directory. Pass
    skip_legacy=True if you only want the v8 health files. (Currently a no-op
    placeholder until upstream run.py is refactored to split data-build from
    rendering.)

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

    # ── Step 1: run upstream pipeline (also writes legacy four-audience) ─
    output = await upstream_run(
        domain=domain,
        dns_file=dns_file,
        audience=audience,
        partner_context=partner,
        threat_context=threat,
        output_dir=output_dir,
    )

    # Inject the prepared_for override into the output dict if provided.
    # The renderer reads this from output["prepared_for"].
    if prepared_for:
        output["prepared_for"] = prepared_for
    resolved_domain = output["domain"]

    # ── Step 2: render v8 Health Report ───────────────────────────────────
    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / resolved_domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    brand = BrandConfig.load() if hasattr(BrandConfig, "load") else BrandConfig.default()
    renderer = HealthReportRenderer(output)

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
    ))


if __name__ == "__main__":
    main()
