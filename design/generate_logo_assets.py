"""Bake the email header logo PNGs (@2x, dark + light) from the generated SVGs.

Email clients strip background-clip:text unreliably, and the outbound stack
hits exactly those clients — the baked raster is required, not optional.
PNG rasterisation needs Chromium (Playwright), so this runs on the master
alongside PDF rendering; the SVGs themselves are deterministic generator
targets covered by the drift guard. Re-run whenever logo.* tokens change.

    python design/generate_logo_assets.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

GENERATED = Path(__file__).resolve().parent / "generated"
VARIANTS = {"logo-dark": "#0F1923", "logo-light": "#FFFFFF"}  # backdrop = token navy / paper


async def bake() -> None:
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        page = await browser.new_page(viewport={"width": 440, "height": 96},
                                      device_scale_factor=2)  # @2x
        for name, backdrop in VARIANTS.items():
            svg = (GENERATED / f"{name}.svg").read_text(encoding="utf-8")
            await page.set_content(
                f'<body style="margin:0;background:{backdrop}">{svg}</body>',
                wait_until="networkidle",
            )
            await page.screenshot(path=str(GENERATED / f"{name}@2x.png"))
            print(f"baked {name}@2x.png")
        await browser.close()


if __name__ == "__main__":
    asyncio.run(bake())
