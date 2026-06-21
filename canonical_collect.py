"""
canonical_collect.py
--------------------
Full DNS collection for the report pipeline, via celery_app_realtime (the SAME
collector that feeds the lake's gold.dns_wide), imported in-process — so the
report sees exactly what the corpus sees.

Replaces report_pipeline._live_scan (dnsproject compile_intelligence, a subset).

    rec   = await collect(domain)                # full DNSRecords-as-dict (+ enrichment)
    ldr   = build_live_dns_report(rec)           # the slim dict riskscore merges
    asn, ip = fallback_asn_ip(rec)               # for out-of-corpus scoring

Then feed into LocalIntelligenceClient.fetch(domain, fallback_asn=asn,
fallback_ip=ip, live_dns_report=ldr).

Env:
    CELERY_REALTIME_PATH   path to celery_app_realtime (default /root/celery_app_realtime)
    DNS_COLLECT_DUCKDB     optional DUCKDB_PATH for celery's LabelEnricher
    DNS_SCORE_CONFIG       optional score_config.yaml for celery's RiskScorer
"""
from __future__ import annotations

import dataclasses
import os
import sys
from typing import Any, Optional

_CELERY_PATH = os.environ.get("CELERY_REALTIME_PATH", "/root/celery_app_realtime")
if _CELERY_PATH not in sys.path:
    sys.path.insert(0, _CELERY_PATH)


async def collect(domain: str, *, timeout: float = 10.0, enrich: bool = True) -> dict:
    """Run celery_app_realtime's collector for one domain; return a flat dict.

    `enrich=True` adds celery's DuckDB label enrichment (mx/ns provider, ASN) when
    DNS_COLLECT_DUCKDB is configured. Risk scoring is intentionally NOT taken from
    celery here — the report's risk comes from riskscore (one source of truth)."""
    # Lowest-level path: raw DNS only (no Celery queue, no broker).
    from dns_module.dns_fetcher import DNSFetcher  # type: ignore

    fetcher = DNSFetcher(domain=domain, domain_timeout_s=timeout,
                         run_blocking_probes=True, fetch_mta_sts_policy=True)
    records = await fetcher.fetch_records()
    if records is None:
        return {"domain": domain, "status": "error"}
    rec = dataclasses.asdict(records) if dataclasses.is_dataclass(records) else dict(records)

    if enrich and os.environ.get("DNS_COLLECT_DUCKDB"):
        try:
            from annotations_module.label_enricher import LabelEnricher  # type: ignore
            enricher = LabelEnricher(db_path=os.environ["DNS_COLLECT_DUCKDB"])
            rec = enricher.enrich_one(rec) if hasattr(enricher, "enrich_one") else rec
        except Exception as e:
            print(f"[canonical_collect] label enrichment skipped: {e}")
    return rec


def _split(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [p.strip() for p in str(value).split(",") if p.strip()]


def build_live_dns_report(rec: dict) -> dict:
    """Map the celery collection → the slim `live_dns_report` the riskscore
    endpoint merges (matches report_pipeline.synth_live_dns_report's shape, but
    sourced from the richer celery record)."""
    spf = (rec.get("spf") or "").lower()
    dmarc = (rec.get("dmarc") or "").lower()
    dmarc_policy = ""
    for part in dmarc.split(";"):
        part = part.strip()
        if part.startswith("p="):
            dmarc_policy = part[2:].strip()
            break
    a_records = _split(rec.get("a"))
    lowest_ttl = rec.get("a_ttl") or rec.get("lowest_ttl") or 0

    return {
        "email_security": {
            "inferred_mbp": rec.get("mx_provider_name") or rec.get("mx_mbp_category") or "unknown",
            "dmarc_enforced": dmarc_policy in ("reject", "quarantine"),
            "spf_strict": "-all" in spf,
        },
        "dns_profile": {
            "records": {"A": {"raw": a_records}},
            "security_heuristics": {"lowest_ttl": int(lowest_ttl or 0)},
        },
    }


def fallback_asn_ip(rec: dict) -> tuple[Optional[int], Optional[str]]:
    """Best-effort ASN + primary IP for out-of-corpus scoring."""
    asn_raw = rec.get("asn")
    try:
        asn = int(asn_raw) if asn_raw not in (None, "", "—") else None
    except (TypeError, ValueError):
        asn = None
    a = _split(rec.get("a"))
    return asn, (a[0] if a else None)
