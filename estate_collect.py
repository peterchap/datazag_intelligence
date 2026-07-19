"""
estate_collect.py — build a real-domain estate manifest for the cross-estate reports
-------------------------------------------------------------------------------------
The estate runners (estate_run.py / estate_report_run.py) consume a manifest of
pre-built per-domain contract JSON — they never scan. This is the collector that
produces that input for a REAL domain list.

It builds each contract through `report_pipeline.build_view_model` — the SAME
assembly the single-domain report uses (live DNS scan -> medallion -> lake/RDAP
enrichment -> CT-log cert intel -> compose). That matters: a contract built from
the medallion alone leaves `annotation`/`registration`/`hygiene` empty, and the
cross-estate analytics group by exactly those fields. Verified on tiptoes.co.uk:
medallion-only grades A (composite 9); the full assembly grades B (composite 28),
because `spf_strict` defaults False when absent and reads as a passing control.
An absent field must never be scored as a finding.

Usage:
    # domains.csv:  domain,segment   (segment optional — crossestate infers gaps)
    python estate_collect.py --domains estates/x/domains.csv --out estates/x --local

    # skip CT-log cert intel (CertSpotter rate-limits hard without a paid key):
    python estate_collect.py --domains ... --out ... --local --no-certs

    # resume a part-collected estate:
    python estate_collect.py --domains ... --out ... --local --resume

Then:
    python estate_run.py        --manifest estates/x/manifest.json --cut all
    python estate_report_run.py --manifest estates/x/manifest.json

--local uses LocalIntelligenceClient (reads the reporting snapshot in-process, no
API key). Otherwise INTELLIGENCE_BASE_URL + INTELLIGENCE_API_KEY are required.

Live DNS comes from the collector at DNS_REALTIME_PATH, imported in-process via
canonical_collect — a direct DNSFetcher call, NOT a Celery task queue.

A per-domain failure is non-fatal: reported, omitted from the manifest, and
recorded in `collect_report.json` alongside the domains that scored.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()


def load_domain_list(path: str) -> list[tuple[str, str | None]]:
    """Parse `domain[,segment]` per line. A `domain` header makes it a CSV; a
    bare list is accepted too. Blank lines and `#` comments are skipped."""
    raw = Path(path).read_text(encoding="utf-8").splitlines()
    lines = [ln for ln in raw if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return []

    if "," in lines[0] and lines[0].split(",")[0].strip().lower() == "domain":
        out = []
        for row in csv.DictReader(lines):
            d = (row.get("domain") or "").strip()
            if d:
                out.append((d, (row.get("segment") or "").strip() or None))
        return out

    out = []
    for ln in lines:
        parts = [p.strip() for p in ln.split(",")]
        out.append((parts[0], parts[1] if len(parts) > 1 and parts[1] else None))
    return out


def disable_cert_intel() -> None:
    """Stub out the CT-log pull. CertSpotter's free tier rate-limits by SLEEPING
    (observed: 321s, 359s per domain), so it blocks rather than degrading — an
    estate-sized run would take hours. Cost of skipping: no `cert_analysis`, so
    the CA-issuer concentration dimension, certificate expiry in the calendar
    block, and cross-domain-SAN discovery all go quiet. They render as
    unavailable rather than as false negatives."""
    import report_pipeline

    async def _empty(domain):  # noqa: ARG001 - signature must match
        return {"subdomains": [], "cert_analysis": {}}

    report_pipeline._ensure_cert_intel = _empty


async def collect_one(client, domain: str, contracts_dir: Path, resume: bool,
                      live: bool) -> dict:
    """Fetch + assemble one domain → contract file. Returns a status dict
    (never raises — one bad domain must not sink the estate)."""
    path = contracts_dir / f"{domain}.json"
    if resume and path.exists():
        return {"domain": domain, "status": "skipped", "path": str(path)}

    from report_pipeline import build_view_model
    try:
        vm = await build_view_model(domain, client, live=live)
    except Exception as e:  # noqa: BLE001 - IntelligenceUnavailable, DNS, lake, ...
        return {"domain": domain, "status": "error", "error": f"{type(e).__name__}: {e}"}

    if not getattr(vm, "has_intelligence", False):
        return {"domain": domain, "status": "no_intelligence"}

    path.write_text(json.dumps(vm.model_dump(mode="json"), indent=2), encoding="utf-8")
    g = getattr(vm, "grade", None)
    return {"domain": domain, "status": "ok", "path": str(path),
            "grade": getattr(g, "letter", None),
            "score": getattr(vm, "composite_score", None)}


async def run(domains_path: str, group: str, out_dir: str, concurrency: int,
              resume: bool, local: bool, live: bool, certs: bool) -> dict:
    pairs = load_domain_list(domains_path)
    if not pairs:
        raise SystemExit(f"no domains found in {domains_path}")

    out = Path(out_dir)
    contracts = out / "contracts"
    contracts.mkdir(parents=True, exist_ok=True)

    if not certs:
        disable_cert_intel()

    if local:
        from local_intelligence import LocalIntelligenceClient
        client = LocalIntelligenceClient()
    else:
        from intelligence_client import IntelligenceClient
        client = IntelligenceClient()
        if not client.api_key or client.api_key.startswith("your_"):
            raise SystemExit(
                "INTELLIGENCE_API_KEY is unset or still the .env placeholder — "
                "set the real key, or use --local on the master host")

    print(f"  Collecting {len(pairs)} domains -> {contracts}")
    print(f"  live-dns={live} certs={certs} concurrency={concurrency} "
          f"client={'local' if local else 'http'}")
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def guarded(domain):
        nonlocal done
        async with sem:
            res = await collect_one(client, domain, contracts, resume, live)
            done += 1
            flag = {"ok": "+", "skipped": "=", "no_intelligence": "~"}.get(res["status"], "!")
            extra = ""
            if res["status"] == "ok":
                extra = f"  {res.get('grade')}/{res.get('score')}"
            elif flag == "!":
                extra = f"  {res.get('error', '')[:120]}"
            print(f"    [{done}/{len(pairs)}] {flag} {domain}{extra}", flush=True)
            return res

    results = await asyncio.gather(*(guarded(d) for d, _ in pairs))

    by_domain = {r["domain"]: r for r in results}
    entries = [
        {"domain": d, "segment": seg, "contract_path": f"contracts/{d}.json"}
        for d, seg in pairs
        if by_domain[d]["status"] in ("ok", "skipped")
    ]
    for e in entries:
        if e["segment"] is None:
            del e["segment"]        # let crossestate infer rather than tag it null

    manifest = out / "manifest.json"
    manifest.write_text(
        json.dumps({"group": group, "domains": entries}, indent=2), encoding="utf-8")
    (out / "collect_report.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f"  {counts} | manifest -> {manifest} ({len(entries)} domains)")
    return {"manifest": str(manifest), "counts": counts}


def main():
    ap = argparse.ArgumentParser(description="Collect real-domain contracts + estate manifest")
    ap.add_argument("--domains", required=True, help="CSV (domain,segment) or plain domain list")
    ap.add_argument("--group", help="Estate/group name (default: --out directory name)")
    ap.add_argument("--out", required=True, help="Output directory for manifest.json + contracts/")
    ap.add_argument("--concurrency", type=int, default=3,
                    help="Parallel domains (default 3 — each does a live DNS scan "
                         "plus lake queries; higher contends on the lake connection)")
    ap.add_argument("--resume", action="store_true", help="Skip domains already collected")
    ap.add_argument("--local", action="store_true",
                    help="Use LocalIntelligenceClient (master host, reads the snapshot directly)")
    ap.add_argument("--live", action=argparse.BooleanOptionalAction, default=True,
                    help="Live DNS scan (default on). Without it, hygiene and provider "
                         "labels are absent and grades read falsely well.")
    ap.add_argument("--certs", action=argparse.BooleanOptionalAction, default=True,
                    help="CT-log cert intel (default on). --no-certs to skip when "
                         "CertSpotter is rate-limiting.")
    args = ap.parse_args()

    group = args.group or Path(args.out).name
    asyncio.run(run(args.domains, group, args.out, args.concurrency,
                    args.resume, args.local, args.live, args.certs))


if __name__ == "__main__":
    main()
