"""
local_intelligence.py
---------------------
In-process drop-in for IntelligenceClient — same async interface, but instead of
HTTP it imports riskscore's DomainIntelligenceAPI directly (the SAME scoring the
rest of the system uses, reading the lake-materialized reporting_snapshot.duckdb).

Use it anywhere IntelligenceClient is used (report_pipeline.build_view_model takes
a `client`): pass LocalIntelligenceClient() and nothing else changes. This keeps
the "one source of truth" guarantee — the report's risk/infra/threat numbers come
from riskscore, not a re-implementation.

Env:
    RISKSCORE_PATH            path to the riskscore repo (default /root/riskscore)
    REPORTING_SNAPSHOT_DB     reporting_snapshot.duckdb (default
                              /root/asn_data_v3/reporting_snapshot.duckdb)
    PLATFORM_IMPERSONATION_*  see fetch_platform_impersonations (lake rollup)
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys

from intelligence_contract import (
    BrandExposure, DomainIntelligence, ExternalThreat, PlatformImpersonation,
)

# riskscore lives as a sibling repo on the master; import its pure scoring class.
_RISKSCORE_PATH = os.environ.get("RISKSCORE_PATH", "/root/riskscore")
if _RISKSCORE_PATH not in sys.path:
    sys.path.insert(0, _RISKSCORE_PATH)

# Windowed impersonation rollup (kind/name/count_7d/count_30d/sample_domains),
# written by riskscore's compute_platform_impersonation_rollup and mirrored to R2
# gold. Read over R2 via the shared lake connection.
_ROLLUP_PARQUET = os.environ.get(
    "PLATFORM_IMPERSONATION_ROLLUP",
    "r2://ducklake-silver/gold/platform_impersonation_rollup_latest.parquet")


# --- pure rollup matching (mirrors riskscore/intelligence_service.query_rollup) ---

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _brand_key(brand: str) -> str:
    label = (brand or "").strip().lower()
    if "." in label:
        label = label.split(".")[0]
    return _norm(label)


def _samples(raw) -> list:
    try:
        return list(json.loads(raw or "[]"))[:5]
    except (TypeError, ValueError):
        return []


def _match_platform(rows: list, requested: str) -> dict:
    rq = _norm(requested)
    best = None
    for name, c7, c30, samples in rows:
        rn = _norm(name)
        if rq and rn and (rn in rq or rq in rn):
            if best is None or c30 > best[2]:
                best = (name, c7, c30, samples)
    if best:
        return {"platform": requested, "category": "", "count_7d": int(best[1] or 0),
                "count_30d": int(best[2] or 0), "sample_domains": _samples(best[3])}
    return {"platform": requested, "category": "", "count_7d": 0, "count_30d": 0, "sample_domains": []}


def _match_brand(rows: list, brand_key: str) -> dict:
    for name, c7, c30, samples in rows:
        if _norm(name) == brand_key:
            return {"count_7d": int(c7 or 0), "count_30d": int(c30 or 0),
                    "sample_domains": _samples(samples)}
    return {"count_7d": 0, "count_30d": 0, "sample_domains": []}

try:
    from infrastructure.domain_intelligence_api import DomainIntelligenceAPI  # type: ignore
except Exception as e:  # pragma: no cover - surfaced at first use
    DomainIntelligenceAPI = None  # type: ignore
    _IMPORT_ERR = e
else:
    _IMPORT_ERR = None


class LocalIntelligenceClient:
    """Mirrors datazag_intelligence.IntelligenceClient, backed by an in-process
    riskscore DomainIntelligenceAPI instead of the HTTP endpoint."""

    def __init__(self, db_path: str | None = None):
        if DomainIntelligenceAPI is None:
            raise RuntimeError(
                f"riskscore not importable from {_RISKSCORE_PATH!r}: {_IMPORT_ERR}. "
                "Set RISKSCORE_PATH to the riskscore repo."
            )
        self.db_path = db_path or os.environ.get(
            "REPORTING_SNAPSHOT_DB", "/root/asn_data_v3/reporting_snapshot.duckdb"
        )
        # DomainIntelligenceAPI opens a read-only DuckDB connection per call, so a
        # single instance is cheap to keep around.
        self._api = DomainIntelligenceAPI(db_path=self.db_path)

    async def fetch(
        self,
        domain: str,
        *,
        fallback_asn: int | None = None,
        fallback_ip: str | None = None,
        profile: str | None = None,
        live_dns_report: dict | None = None,
    ) -> DomainIntelligence:
        """Return the canonical medallion for a domain. get_domain_intelligence is
        synchronous (DuckDB), so run it off the event loop."""
        payload = await asyncio.to_thread(
            self._api.get_domain_intelligence,
            domain,
            profile=profile,
            fallback_asn=fallback_asn,
            fallback_ip=fallback_ip,
            live_dns_report=live_dns_report,
        )
        # Validates the same dict the HTTP client would have received.
        return DomainIntelligence.model_validate(payload)

    async def fetch_platform_impersonations(self, platforms: list[str], brand: str | None = None) -> ExternalThreat:
        """Platform-impersonation activity from the WINDOWED rollup
        (platform_impersonation_rollup_latest.parquet, mirrored to R2 gold by
        riskscore's compute_platform_impersonation_rollup) — real 7/30-day distinct
        impersonating-domain counts per platform. EXACT matches drive
        `impersonations`; fuzzy typosquat candidates (FP-heavy, lower confidence) come
        back separately as `lookalike_candidates`. Mirrors intelligence_service.
        query_rollup so the local + HTTP clients agree. Degrades to an empty
        ExternalThreat (detected_platforms preserved) so the report still renders."""
        detected = list(platforms or [])
        if not detected and not brand:
            return ExternalThreat(detected_platforms=detected)
        try:
            return await asyncio.to_thread(self._query_impersonations, detected, brand)
        except Exception as e:  # impersonations are supplementary — never fatal
            print(f"[local_intelligence] impersonation lookup failed: {e}")
            return ExternalThreat(detected_platforms=detected)

    def _query_impersonations(self, platforms: list[str], brand: str | None = None) -> ExternalThreat:
        from lake_enrich import lake_connect  # shared DuckLake connector (carries R2 creds)

        con = lake_connect()
        try:
            rows = con.execute(
                f"SELECT kind, name, count_7d, count_30d, sample_domains "
                f"FROM read_parquet('{_ROLLUP_PARQUET}')"
            ).fetchall()
        finally:
            con.close()

        by_kind = {k: [(r[1], r[2], r[3], r[4]) for r in rows if r[0] == k]
                   for k in ("platform", "platform_typosquat", "brand", "brand_typosquat")}

        exact = [_match_platform(by_kind["platform"], p) for p in platforms]
        looks = [p for p in (_match_platform(by_kind["platform_typosquat"], p) for p in platforms)
                 if p["count_30d"] > 0]

        kw = {}
        if brand:
            bk = _brand_key(brand)
            kw["own_brand"] = BrandExposure.model_validate(
                {**_match_brand(by_kind["brand"], bk), "confidence": "exact"})
            kw["own_brand_lookalikes"] = BrandExposure.model_validate(
                {**_match_brand(by_kind["brand_typosquat"], bk), "confidence": "lookalike"})

        return ExternalThreat(
            detected_platforms=platforms,
            impersonations=[PlatformImpersonation.model_validate({**x, "confidence": "exact"}) for x in exact],
            lookalike_candidates=[PlatformImpersonation.model_validate({**x, "confidence": "lookalike"}) for x in looks],
            **kw,
        )
