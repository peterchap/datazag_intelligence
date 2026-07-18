"""
estate_collect.py — build a real-domain estate manifest from the riskscore service
----------------------------------------------------------------------------------
The estate runners (estate_run.py / estate_report_run.py) consume a manifest of
pre-built per-domain contract JSON — they never scan. This is the collector that
produces that input for a REAL domain list: fetch the medallion per domain, build
the `ReportViewModel`, write `contracts/<domain>.json`, emit `manifest.json`.

Usage:
    # domains.csv:  domain,segment   (segment optional — crossestate infers gaps)
    python estate_collect.py --domains domains.csv --group "Acme Group" --out estates/acme

    # plain list (one domain per line), all untagged:
    python estate_collect.py --domains domains.txt --group "Acme Group" --out estates/acme

    # resume a part-collected estate (skips domains whose contract already exists):
    python estate_collect.py --domains domains.csv --out estates/acme --resume

Then:
    python estate_run.py        --manifest estates/acme/manifest.json --cut all
    python estate_report_run.py --manifest estates/acme/manifest.json

Requires INTELLIGENCE_BASE_URL + INTELLIGENCE_API_KEY. On the master host, pass
--local to read the reporting snapshot in-process instead (no key needed).

A per-domain failure is non-fatal: it is reported, omitted from the manifest, and
listed in `collect_report.json` alongside the domains that scored.
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

from findings_rules import derive_findings
from intelligence_contract import build_view_models


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


async def collect_one(client, domain: str, contracts_dir: Path, resume: bool) -> dict:
    """Fetch one domain → contract file. Returns a status dict (never raises)."""
    path = contracts_dir / f"{domain}.json"
    if resume and path.exists():
        return {"domain": domain, "status": "skipped", "path": str(path)}

    try:
        di = await client.fetch(domain)
    except Exception as e:                      # IntelligenceUnavailable, network, ...
        return {"domain": domain, "status": "error", "error": f"{type(e).__name__}: {e}"}

    if di.is_error:
        return {"domain": domain, "status": "error", "error": di.error or "unknown"}
    if not di.has_intelligence:
        return {"domain": domain, "status": "no_intelligence"}

    # Same construction crossestate/manifest.contract_from_payload uses for the
    # medallion fallback — a view-model dump is the preferred contract shape.
    vm = build_view_models(di, findings=derive_findings(di, []))
    path.write_text(json.dumps(vm.model_dump(mode="json"), indent=2), encoding="utf-8")
    return {"domain": domain, "status": "ok", "path": str(path)}


async def run(domains_path: str, group: str, out_dir: str, concurrency: int,
              resume: bool, local: bool) -> dict:
    pairs = load_domain_list(domains_path)
    if not pairs:
        raise SystemExit(f"no domains found in {domains_path}")

    out = Path(out_dir)
    contracts = out / "contracts"
    contracts.mkdir(parents=True, exist_ok=True)

    if local:
        from local_intelligence import LocalIntelligenceClient
        client = LocalIntelligenceClient()
    else:
        from intelligence_client import IntelligenceClient
        client = IntelligenceClient()
        if not client.api_key or client.api_key.startswith("your_"):
            raise SystemExit(
                "INTELLIGENCE_API_KEY is unset or still the .env placeholder — "
                "set the real key, or run on the master host with --local")

    print(f"  Collecting {len(pairs)} domains -> {contracts}")
    sem = asyncio.Semaphore(concurrency)

    async def guarded(domain):
        async with sem:
            res = await collect_one(client, domain, contracts, resume)
            flag = {"ok": "+", "skipped": "=", "no_intelligence": "~"}.get(res["status"], "!")
            print(f"    {flag} {domain}" + (f"  {res.get('error','')}" if flag == "!" else ""))
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
    ap.add_argument("--concurrency", type=int, default=4,
                    help="Parallel lookups (default 4 — a cold medallion query is slow)")
    ap.add_argument("--resume", action="store_true", help="Skip domains already collected")
    ap.add_argument("--local", action="store_true",
                    help="Use LocalIntelligenceClient (master host, reads the snapshot directly)")
    args = ap.parse_args()

    group = args.group or Path(args.out).name
    asyncio.run(run(args.domains, group, args.out, args.concurrency, args.resume, args.local))


if __name__ == "__main__":
    main()
