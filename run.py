"""
run.py — Datazag DNS Intelligence Renderer
-----------------------------------------
Usage:
    python run.py --input_json ../dnsproject/scripts/output/normcyber_com__20261021.json --audience insurer

Outputs JSON + Markdown + HTML + PDF for each of 4 audiences to ./output/<domain>/
"""

import argparse
import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from narrative import enrich_with_narrative
from renderers import render_all
from playwright.async_api import async_playwright
from branding import BrandConfig

DEFAULT_OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "./output"))

async def run(
    input_json: str     = None,
    domain: str         = None,
    audience: str       = "insurer",
    partner_context: str = None,
    threat_context: str  = None,
    skip_narrative: bool = False,
    output_dir: Path    = None,
    brand_profile: str  = None,
) -> dict:

    brand = BrandConfig.load(brand_profile)
    print(f"  Brand: {brand.brand_name}")
    
    if input_json:
        with open(input_json, "r") as fh:
            output = json.load(fh)
    elif domain:
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from dnsproject.scripts.compile_intelligence import run as compile_intel
        output = await compile_intel(
            domain=domain,
            audience=audience,
            partner_context=partner_context,
            threat_context=threat_context,
            output_dir=output_dir
        )
    else:
        raise ValueError("Must provide either --input_json or --domain")
    
    domain = output.get("domain", domain or "unknown")
    findings = output.get("findings", [])
    
    output["audience"] = audience
    
    # ── Step 6: Narrative enrichment ─────────────────────────────────────
    if not skip_narrative and os.environ.get("ANTHROPIC_API_KEY"):
        if audience == "all":
            audiences = ["insurer", "consultant", "it", "sales"]
        else:
            audiences = [audience]
            
        narratives = {}
        
        async def fetch_narrative(aud):
            print(f"  Generating narrative ({aud} audience)...")
            return aud, await enrich_with_narrative(
                domain=domain,
                score=output.get("display_score", 0),
                risk_band=output.get("display_risk_band", "unknown"),
                findings=findings,
                output=output,
                partner_context=partner_context,
                threat_context=threat_context,
                audience=aud,
            )
            
        results = await asyncio.gather(*[fetch_narrative(a) for a in audiences])
        for aud, nar in results:
            narratives[aud] = nar
            
        output["narratives"] = narratives
        output["narrative"] = narratives.get(audience if audience != "all" else "insurer", {})
        print(f"  Key finding: {output['narrative'].get('key_finding', '')[:80]}...")
    else:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("  Skipping narrative — ANTHROPIC_API_KEY not set")

    # ── Step 7: Render reports ────────────────────────────────────────────
    all_reports = render_all(output, brand=brand)

    out_dir = (output_dir or DEFAULT_OUTPUT_DIR) / domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    html_paths: list[tuple[Path, Path]] = []
    for aud, formats in all_reports.items():
        for fmt, content in formats.items():
            ext  = {"json": "json", "markdown": "md", "html": "html"}[fmt]
            path = out_dir / f"{aud}.{ext}"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            if ext == "html":
                html_paths.append((path, out_dir / f"{aud}.pdf"))

    # ── Step 8: PDF generation via Playwright ────────────────────────────
    if html_paths:
        print(f"\n  Converting {len(html_paths)} HTML reports to PDF...")
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            for html_path, pdf_path in html_paths:
                print(f"  → {pdf_path.name}")
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

    print(f"\n  Output written to {out_dir}/")
    print("  16 files — 4 audiences × 4 formats (JSON, Markdown, HTML, PDF)")

    return output

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Datazag DNS Intelligence Renderer")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input_json",
                        help="Path to pre-collected Datazag Intelligence JSON payload (from compile_intelligence.py)")
    input_group.add_argument("--domain",
                        help="Domain to scan and compile live before rendering")
    parser.add_argument("--audience",     default="all",
                        choices=["insurer", "consultant", "it", "sales", "all"])
    parser.add_argument("--partner",      default=None,
                        help="Partner context e.g. 'Atlassian Platinum Partner'")
    parser.add_argument("--threat",       default=None,
                        help="Threat context e.g. 'Subject of ransom demand'")
    parser.add_argument("--output-dir",   default=None,
                        help="Output directory (overrides OUTPUT_DIR in .env)")
    parser.add_argument("--no-narrative", action="store_true",
                        help="Skip Claude API narrative generation")
    parser.add_argument("--brand",        default=None,
                        help="Brand profile name e.g. 'acme_mssp'")

    args = parser.parse_args()

    asyncio.run(run(
        input_json=args.input_json,
        domain=args.domain,
        audience=args.audience,
        partner_context=args.partner,
        threat_context=args.threat,
        skip_narrative=args.no_narrative,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        brand_profile=args.brand,
    ))