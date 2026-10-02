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
    """Stub out the CT-log pull (--no-certs). Cost of skipping: no `cert_analysis`, so
    the CA-issuer concentration dimension, certificate expiry in the calendar
    block, and cross-domain-SAN discovery all go quiet. They render as
    unavailable rather than as false negatives."""
    import report_pipeline

    async def _empty(domain):  # noqa: ARG001 - signature must match
        return {"subdomains": [], "cert_analysis": {}}

    report_pipeline._ensure_cert_intel = _empty


async def collect_dns(domains: list[str], concurrency: int) -> dict[str, dict]:
    """Phase 1: the live DNS scan for every domain, batched.

    DNS is I/O-bound and fast, so it runs wide (DNS_CONCURRENCY, default 20) through
    the report resolver, the way the celery workers batch the corpus. The slower
    per-domain assembly (scoring, lake, RDAP, certificates) then starts from these
    records instead of scanning again, and a stall in one phase is visible as that
    phase (2026-10-02: estate stalls could not be told apart from the DNS scan).
    A scan that does not finish comes back flagged scan_incomplete, never raises."""
    import canonical_collect

    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(d: str) -> tuple[str, dict]:
        async with sem:
            try:
                return d, await canonical_collect.collect(d, strict=False)
            except Exception as e:  # noqa: BLE001 - one bad scan must not sink the batch
                return d, {"domain": d, "status": "error", "scan_incomplete": True,
                           "error": f"{type(e).__name__}: {e}"}

    pairs = await asyncio.gather(*(one(d) for d in domains))
    return dict(pairs)


async def collect_one(client, domain: str, contracts_dir: Path, resume: bool,
                      live: bool, live_output: dict | None = None) -> dict:
    """Fetch + assemble one domain → contract file. Returns a status dict
    (never raises — one bad domain must not sink the estate)."""
    path = contracts_dir / f"{domain}.json"
    if resume and path.exists():
        return {"domain": domain, "status": "skipped", "path": str(path)}

    from report_pipeline import build_view_model
    # One domain must not stall the estate. On 2026-10-02 a 14-domain run sat for
    # 17 minutes with three domains awaiting a socket that never answered, and
    # nothing timed them out. A domain that overruns is an error like any other:
    # reported, omitted from the manifest, recorded in collect_report.json.
    timeout_s = float(os.environ.get("ESTATE_DOMAIN_TIMEOUT", "300"))
    try:
        vm = await asyncio.wait_for(
            build_view_model(domain, client, live=live, live_output=live_output), timeout=timeout_s)
    except asyncio.TimeoutError:
        return {"domain": domain, "status": "error",
                "error": f"timed out after {timeout_s:.0f}s (ESTATE_DOMAIN_TIMEOUT)"}
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
    todo = [d for d, _ in pairs if not (resume and (contracts / f"{d}.json").exists())]
    # Phase 1a: every domain's certificates in one CT-archive query. Each per-domain
    # build then reads from memory. A failure here only costs the cert sections:
    # each domain retries its own lookup and degrades to empty.
    if certs and todo:
        try:
            import cert_stream
            await asyncio.to_thread(cert_stream.prefetch, todo)
        except Exception as e:  # noqa: BLE001
            print(f"  cert-intel: estate prefetch failed: {str(e).splitlines()[0] if str(e) else e!r}",
                  flush=True)

    # Phase 1b: one batched DNS pass over every domain still to collect.
    dns: dict[str, dict] = {}
    if live:
        if todo:
            dns_conc = int(os.environ.get("DNS_CONCURRENCY", "20"))
            print(f"  DNS: scanning {len(todo)} domains in one batch (concurrency {dns_conc})", flush=True)
            dns = await collect_dns(todo, dns_conc)
            bad = [d for d, r in dns.items() if r.get("scan_incomplete")]
            print(f"  DNS: {len(dns) - len(bad)} complete, {len(bad)} incomplete"
                  + (f" ({', '.join(bad)})" if bad else ""), flush=True)

    # Phase 2: per-domain assembly from those records.
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def guarded(domain):
        nonlocal done
        async with sem:
            res = await collect_one(client, domain, contracts, resume, live, live_output=dns.get(domain))
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
                    help="CT-log cert intel from the Datazag CT archive (default on). "
                         "--no-certs skips it.")
    args = ap.parse_args()

    group = args.group or Path(args.out).name
    asyncio.run(run(args.domains, group, args.out, args.concurrency,
                    args.resume, args.local, args.live, args.certs))


if __name__ == "__main__":
    main()
