"""
intelligence_client.py
-----------------------
Async client for the riskscore intelligence service (see
riskscore/intelligence_service.py). Fetches the medallion payload and the
platform-impersonation rollup over HTTP and returns typed contract objects.

Config (env):
    INTELLIGENCE_BASE_URL   e.g. http://riskscore-host:8817
    INTELLIGENCE_API_KEY    shared secret sent as X-Datazag-Key
    INTELLIGENCE_TIMEOUT    seconds (default 15)
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional

import aiohttp

from intelligence_contract import (
    BrandExposure,
    BrandFunnel,
    DomainIntelligence,
    ExternalThreat,
    PlatformImpersonation,
)


class IntelligenceUnavailable(Exception):
    """Raised when the service cannot be reached (connect error / timeout / 5xx).

    Distinct from a 404, which is a valid 'no intelligence for this domain'
    answer and is returned as a defaulted DomainIntelligence(code=404).
    """


class IntelligenceClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.base_url = (base_url or os.environ.get("INTELLIGENCE_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("INTELLIGENCE_API_KEY", "")
        # The medallion lookup runs a per-domain query against the snapshot /
        # gold parquet on the riskscore host, so a cold lookup can take tens of
        # seconds — 15s was too tight. Default 60s; override via INTELLIGENCE_TIMEOUT.
        self.timeout = aiohttp.ClientTimeout(
            total=float(timeout or os.environ.get("INTELLIGENCE_TIMEOUT", 60))
        )
        if not self.base_url:
            raise ValueError("INTELLIGENCE_BASE_URL is not set")

    @property
    def _headers(self) -> dict:
        return {"X-Datazag-Key": self.api_key} if self.api_key else {}

    async def fetch(
        self,
        domain: str,
        fallback_asn: Optional[int] = None,
        fallback_ip: Optional[str] = None,
        profile: Optional[str] = None,
        live_dns_report: Optional[dict] = None,
    ) -> DomainIntelligence:
        """Fetch the medallion payload. POST when a live DNS scan is supplied
        (server-side merge), otherwise GET the snapshot fast-path."""
        url = f"{self.base_url}/intelligence/{domain}"
        params = {}
        if fallback_asn is not None:
            params["fallback_asn"] = fallback_asn
        if fallback_ip:
            params["fallback_ip"] = fallback_ip
        if profile:
            params["profile"] = profile

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                if live_dns_report is not None:
                    body = {
                        "fallback_asn": fallback_asn,
                        "fallback_ip": fallback_ip,
                        "profile": profile,
                        "live_dns_report": live_dns_report,
                    }
                    ctx = session.post(url, json=body, headers=self._headers)
                else:
                    ctx = session.get(url, params=params, headers=self._headers)
                async with ctx as resp:
                    if resp.status == 404:
                        return DomainIntelligence(domain=domain, error="not_found", code=404)
                    if resp.status >= 500:
                        raise IntelligenceUnavailable(
                            f"service returned {resp.status} for {domain}")
                    data = await resp.json()
        except asyncio.TimeoutError as e:
            raise IntelligenceUnavailable(
                f"intelligence lookup for {domain} exceeded {self.timeout.total:.0f}s "
                "— raise INTELLIGENCE_TIMEOUT or speed up the server-side query") from e
        except aiohttp.ClientError as e:
            raise IntelligenceUnavailable(str(e)) from e

        di = DomainIntelligence.model_validate(data)
        if not di.is_error and di.schema_version != "1.0":
            raise IntelligenceUnavailable(
                f"unexpected schema_version {di.schema_version!r}")
        # carry the queried domain if the payload omitted it
        if not di.domain:
            di.domain = domain
        return di

    async def fetch_platform_impersonations(
        self,
        platforms: list[str],
        windows: tuple[int, int] = (7, 30),
        brand: Optional[str] = None,
    ) -> ExternalThreat:
        """Fetch impersonation data for the detected platform stack: EXACT matches
        (`platforms` / `own_brand`) that drive the headline, plus lower-confidence
        typosquat candidates (`platform_lookalikes` / `own_brand_lookalikes`).
        Returns an empty ExternalThreat if the rollup is unavailable — impersonation
        data is supplementary, never fatal."""
        empty = ExternalThreat(detected_platforms=platforms)
        if not platforms and not brand:
            return empty

        url = f"{self.base_url}/platform-impersonations"
        params = {
            "platforms": ",".join(platforms),
            "windows": ",".join(str(w) for w in windows),
        }
        if brand:
            params["brand"] = brand

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, params=params, headers=self._headers) as resp:
                    if resp.status != 200:
                        return empty
                    data = await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return empty   # impersonation data is supplementary — never fatal

        def _imps(key: str, confidence: str) -> list[PlatformImpersonation]:
            return [PlatformImpersonation.model_validate({**x, "confidence": confidence})
                    for x in data.get(key, [])]

        def _brand(key: str, confidence: str) -> BrandExposure:
            return BrandExposure.model_validate({**data.get(key, {}), "confidence": confidence})

        return ExternalThreat(
            detected_platforms=platforms,
            impersonations=_imps("platforms", "exact"),
            own_brand=_brand("own_brand", "exact"),
            lookalike_candidates=_imps("platform_lookalikes", "lookalike"),
            own_brand_lookalikes=_brand("own_brand_lookalikes", "lookalike"),
        )

    async def fetch_brand_funnel(self, domain: str) -> BrandFunnel:
        """Fetch the FREE-report active-scan brand funnel for `domain` from the
        riskscore brand-funnel endpoint (pattern-gen + cheap corpus resolution +
        DGA cross-check). Brand-scoped by construction — the endpoint must never
        fill it from platform-global impersonation data. Returns an empty funnel
        (→ empty-state framing) if the endpoint is unavailable; never fatal."""
        empty = BrandFunnel()
        if not domain:
            return empty
        url = f"{self.base_url}/brand-funnel"
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, params={"domain": domain}, headers=self._headers) as resp:
                    if resp.status != 200:
                        return empty
                    data = await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return empty
        return BrandFunnel.model_validate(data or {})
