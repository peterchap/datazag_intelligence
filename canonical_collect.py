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

# Realtime report collection must be up-to-the-minute: disable the batch DNS
# cache (this codebase is branched from the batch processor, whose LMDB negative
# cache otherwise returns a stale empty MX even when the live record exists).
# Set before the dns_module import below; `setdefault` lets an operator force
# the cache back on (DNS_DISABLE_CACHE=0) for debugging.
os.environ.setdefault("DNS_DISABLE_CACHE", "1")

# The real-time DNS collector (source repo celery_app_realtime; deployed on the
# master as /root/dns_realtime). DNS_REALTIME_PATH preferred; CELERY_REALTIME_PATH
# kept for back-compat.
_CELERY_PATH = (os.environ.get("DNS_REALTIME_PATH")
                or os.environ.get("CELERY_REALTIME_PATH")
                or "/root/dns_realtime")


def _celery_dns_fetcher():
    """Import celery_app_realtime's DNSFetcher unambiguously.

    Both celery_app_realtime AND riskscore ship a top-level `dns_module` package;
    riskscore is on sys.path (via the medallion client) and its `dns_module` has a
    different/older API, so a plain `import dns_module` resolves to the WRONG one
    and crashes. Force celery's to win: require the path, put it first, and evict
    any `dns_module` already cached from another repo before importing."""
    if not os.path.isdir(_CELERY_PATH):
        raise RuntimeError(
            f"real-time DNS collector not found at {_CELERY_PATH!r}. Set DNS_REALTIME_PATH "
            f"to the deployed dns_realtime folder. (canonical_collect needs ITS dns_module — "
            f"riskscore ships a colliding, incompatible dns_module.)"
        )
    if _CELERY_PATH not in sys.path:
        sys.path.insert(0, _CELERY_PATH)
    else:
        sys.path.remove(_CELERY_PATH); sys.path.insert(0, _CELERY_PATH)
    for name in [k for k in list(sys.modules) if k == "dns_module" or k.startswith("dns_module.")]:
        f = getattr(sys.modules[name], "__file__", "") or ""
        if not os.path.abspath(f).startswith(os.path.abspath(_CELERY_PATH)):
            del sys.modules[name]
    from dns_module.dns_fetcher import DNSFetcher  # type: ignore  # noqa: E402
    return DNSFetcher


async def collect(domain: str, *, timeout: float = 10.0, enrich: bool = True) -> dict:
    """Run celery_app_realtime's collector for one domain; return a flat dict.

    `enrich=True` adds celery's DuckDB label enrichment (mx/ns provider, ASN) when
    DNS_COLLECT_DUCKDB is configured. Risk scoring is intentionally NOT taken from
    celery here — the report's risk comes from riskscore (one source of truth)."""
    DNSFetcher = _celery_dns_fetcher()

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
