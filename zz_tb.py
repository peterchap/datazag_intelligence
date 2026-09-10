"""Locate the IndexError for a live-zone-but-no-apex-A domain."""
import asyncio
import traceback

from dotenv import load_dotenv
load_dotenv()

import report_pipeline


async def _no_certs(domain):
    return {"subdomains": [], "cert_analysis": {}}


report_pipeline._ensure_cert_intel = _no_certs

from local_intelligence import LocalIntelligenceClient
from report_pipeline import build_view_model


async def main():
    c = LocalIntelligenceClient()
    try:
        await build_view_model("btplc.com", c, live=True)
        print("NO ERROR")
    except Exception:
        traceback.print_exc()


asyncio.run(main())
