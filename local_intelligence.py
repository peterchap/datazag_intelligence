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
import os
import sys

from intelligence_contract import DomainIntelligence, ExternalThreat, PlatformImpersonation

# riskscore lives as a sibling repo on the master; import its pure scoring class.
_RISKSCORE_PATH = os.environ.get("RISKSCORE_PATH", "/root/riskscore")
if _RISKSCORE_PATH not in sys.path:
    sys.path.insert(0, _RISKSCORE_PATH)

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
        """Platform-impersonation activity from the lake's `ref.platform_impersonation`
        rollup. That table is a CURRENT snapshot (platform, hits, impersonating_domains,
        loaded_at) — no 7/30-day split — so impersonating_domains maps to count_30d and
        count_7d stays 0 until a windowed source exists. Degrades to an empty
        ExternalThreat (detected_platforms preserved) so the report still renders."""
        detected = list(platforms or [])
        if not detected:
            return ExternalThreat(detected_platforms=detected)
        try:
            return await asyncio.to_thread(self._query_impersonations, detected)
        except Exception as e:  # impersonations are supplementary — never fatal
            print(f"[local_intelligence] impersonation lookup failed: {e}")
            return ExternalThreat(detected_platforms=detected)

    def _query_impersonations(self, platforms: list[str]) -> ExternalThreat:
        from lake_enrich import lake_connect  # shared self-contained DuckLake connector

        table = os.environ.get("PLATFORM_IMPERSONATION_TABLE", "ref.platform_impersonation")
        terms = sorted({p.strip().lower() for p in platforms if p and p.strip()})
        con = lake_connect()
        try:
            rows = con.execute(
                f"SELECT platform, hits, impersonating_domains FROM {table} WHERE lower(platform) = ANY(?)",
                [terms],
            ).fetchall()
        finally:
            con.close()
        imps = [
            PlatformImpersonation(platform=r[0], count_7d=0, count_30d=int(r[2] or r[1] or 0))
            for r in rows
        ]
        return ExternalThreat(detected_platforms=platforms, impersonations=imps)
