"""
report_data_check.py
---------------------
Step-1 diagnostic: does the backend hand run.py a COMPLETE data package?

Runs the real in-process report pipeline for one domain (the same path run.py
uses: canonical_collect.collect -> build_view_model) and prints, source by
source, what is actually populated vs empty — so we can see the gaps before
re-architecting around a clean data contract.

It reports three things:
  1. RAW REC          — the celery DNSRecords the live scan produced.
  2. LAKE ENRICH      — whether lake_enrich.enrich() SUCCEEDS or throws (the
                        all-or-nothing failure that blanks hygiene+annotation).
  3. CONTRACT (vm)    — per-field populated/empty for every ReportViewModel
                        sub-model the renderer is supposed to read.
  4. CONTRACT HOLES   — data the renderer needs that has no contract field
                        (raw DNS records, cert analysis, subdomains, ...).

Usage (on the master, with the report venv):
    python report_data_check.py qbeeurope.com
    python report_data_check.py qbeeurope.com --json   # also dump the full vm
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


def _present(v) -> bool:
    if v is None:
        return False
    if isinstance(v, (str, list, dict, tuple, set)):
        return len(v) > 0
    if isinstance(v, bool):
        return True          # a bool IS a value (False is meaningful here)
    return v != 0


def _dump_model(label: str, model) -> None:
    print(f"\n── {label} ──")
    if model is None:
        print("  (None)")
        return
    data = model.model_dump() if hasattr(model, "model_dump") else dict(model)
    if not data:
        print("  (empty)")
        return
    width = max(len(k) for k in data)
    for k, v in data.items():
        mark = "✓" if _present(v) else "·"
        shown = v if not isinstance(v, (list, dict)) else f"<{type(v).__name__} len={len(v)}>"
        print(f"  {mark} {k:<{width}}  {shown}")


async def main(domain: str, as_json: bool) -> int:
    import canonical_collect

    print(f"=== data-package check: {domain} ===")

    # 1. RAW REC ----------------------------------------------------------
    rec = await canonical_collect.collect(domain)
    dns_keys = ["a", "aaaa", "ns1", "mx", "mx_host_final", "mx_regdom_final",
                "spf", "dmarc", "bimi", "caa", "dnssec", "mta_sts_mode",
                "tlsrpt_rua", "https_cert_issuer"]
    print("\n── 1. RAW REC (celery DNSRecords) ──")
    print(f"  status: {rec.get('status', '?')}  · total keys: {len(rec)}")
    for k in dns_keys:
        v = rec.get(k)
        print(f"  {'✓' if _present(v) else '·'} {k:<16} {v!r}")

    # 2. LAKE ENRICH (the all-or-nothing step) ---------------------------
    print("\n── 2. LAKE ENRICH (lake_enrich.enrich) ──")
    try:
        import lake_enrich
        from report_pipeline import detect_platforms
    except Exception as e:
        print(f"  import failed: {type(e).__name__}: {e}")
        lake_enrich = None
    enr = {}
    if lake_enrich is not None:
        try:
            platforms = detect_platforms(rec) or []
        except Exception:
            platforms = []
        try:
            bundle = lake_enrich.enrich(domain, rec, platforms)
            enr = lake_enrich.to_view_models(rec, bundle)
            print("  enrich(): OK")
            lbl = (bundle.get("labels") or {})
            print(f"    labels keys: {sorted(lbl)[:12]}{' …' if len(lbl) > 12 else ''}")
            print(f"    mailbox_provider={lbl.get('mailbox_provider')!r}  "
                  f"ns_provider={lbl.get('ns_provider')!r}  asn_name={(bundle.get('infra') or {}).get('asn_name')!r}")
        except Exception as e:
            print(f"  enrich(): THREW -> {type(e).__name__}: {e}")
            print("    => build_view_model swallows this; hygiene+annotation arrive EMPTY.")

    # 3. CONTRACT (the assembled view-model run.py renders) --------------
    print("\n── 3. CONTRACT (ReportViewModel) ──")
    try:
        from local_intelligence import LocalIntelligenceClient
        from report_pipeline import build_view_model
        client = LocalIntelligenceClient()
        vm = await build_view_model(domain, client, live_output=rec)
    except Exception as e:
        print(f"  build_view_model failed: {type(e).__name__}: {e}")
        return 1
    print(f"  domain={vm.domain}  has_intelligence={vm.has_intelligence}  "
          f"grade={vm.grade.letter} ({vm.composite_score})")
    _dump_model("hygiene  (email-auth: dmarc/spf/dnssec/caa/...)", vm.hygiene)
    _dump_model("annotation  (providers / asn / labels)", vm.annotation)
    _dump_model("registration", vm.registration)
    _dump_model("abuse", vm.abuse)
    print("\n── trust (isp/asn/prefix the infra block needs) ──")
    for f in ("isp", "isp_country", "asn", "asn_risk_level", "prefix", "mx_type"):
        v = getattr(vm.trust, f, None)
        print(f"  {'✓' if _present(v) else '·'} trust.{f:<14} {v!r}")

    _dump_model("dns_records  (raw A/AAAA/MX/NS/CAA/TXT — now on the contract)", getattr(vm, "dns_records", None))

    # 4. CONTRACT HOLES — what the renderer needs with no contract field -
    print("\n── 4. CONTRACT HOLES (renderer falls back to `legacy` for these) ──")
    holes = {
        "cert_analysis (SMTP/HTTPS cert detail)": "legacy['cert_analysis']",
        "subdomains": "legacy['subdomains']",
        "txt_intelligence / threat_flags / narrative": "legacy[...]",
    }
    for k, v in holes.items():
        print(f"  · {k}\n        → {v}")

    if as_json:
        print("\n── full vm (json) ──")
        print(json.dumps(vm.model_dump(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--json", action="store_true", help="also dump the full view-model")
    a = ap.parse_args()
    sys.exit(asyncio.run(main(a.domain, a.json)))
