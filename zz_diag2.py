"""Diagnostic: do the provider labels (ns/mailbox/hosting) populate with a live
DNS scan? Cert intel is patched out — it blocks on CertSpotter rate-limit backoff
and is irrelevant to this question."""
import asyncio
from dotenv import load_dotenv
load_dotenv()

import report_pipeline


async def _no_certs(domain):
    return {"subdomains": [], "cert_analysis": {}}


report_pipeline._ensure_cert_intel = _no_certs

from local_intelligence import LocalIntelligenceClient
from report_pipeline import build_view_model

DOMAINS = ("bt.com", "revolut.com", "kidsplanetdaynurseries.co.uk", "poppyandjacks.co.uk")


async def main():
    c = LocalIntelligenceClient()
    for dom in DOMAINS:
        try:
            vm = await build_view_model(dom, c, live=True)
            d = vm.model_dump(mode="json")
            a = d.get("annotation") or {}
            t = d.get("trust") or {}
            r = d.get("registration") or {}
            h = d.get("hygiene") or {}
            g = d.get("grade") or {}
            print(
                f"RESULT {dom}"
                f" | ns={a.get('ns_provider')}"
                f" | mbx={a.get('mailbox_provider')}"
                f" | host={a.get('hosting_provider')}"
                f" | asn={a.get('asn') or a.get('asn_name')}"
                f" | mx_type={t.get('mx_type')}"
                f" | registrar={r.get('registrar')}"
                f" | dmarc={h.get('dmarc_policy')}"
                f" | spf={h.get('spf_strict')}"
                f" | grade={g.get('letter')}/{d.get('composite_score')}"
            )
        except Exception as e:
            print(f"RESULT {dom} | FAILED {type(e).__name__}: {e}")


asyncio.run(main())
