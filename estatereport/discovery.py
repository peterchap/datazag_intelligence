"""
estatereport/discovery.py
-------------------------
The v2.2 discovery ADAPTER. Discovery itself is the single shared engine in
`crossestate.discovery` (spec §2.7 — one pass feeds both §2.1 completeness and
these four tiers). This module only reshapes a `DiscoveryResult` into the
report's `EstateDiscovery` tiers:

    declared   — the customer's list
    strong     — owned, corroborated (shared cert SAN + apex/brand)  → graded
    possible   — low-confidence candidates (shared cert, no corroboration) → ungraded
    defensive  — owned but login/payroll/invoice-style names          → never graded

The default provider is the real `ConnectedDomainDiscoveryProvider`; pass
`NullDiscoveryProvider` to render the four-tier structure with declared-only data
and the honest "not enabled" note.
"""

from __future__ import annotations

from crossestate.discovery import (  # re-export the shared engine
    ConnectedDomainDiscoveryProvider,
    DiscoveryProvider,
    DiscoveryResult,
    NullDiscoveryProvider,
)
from estatereport.contract import DiscoveredDomain, EstateDiscovery, Evidence

__all__ = ["ConnectedDomainDiscoveryProvider", "DiscoveryProvider", "NullDiscoveryProvider",
           "to_estate_discovery"]


def _convert(dd) -> DiscoveredDomain:
    tier = dd.tier if dd.tier in ("strong", "possible", "defensive") else "possible"
    return DiscoveredDomain(
        domain=dd.domain, tier=tier,
        evidence=[Evidence(kind=e.get("kind", ""), detail=e.get("detail", "")) for e in dd.evidence],
    )


def to_estate_discovery(result: DiscoveryResult, declared_domains: list[str]) -> EstateDiscovery:
    tiers: dict[str, list[DiscoveredDomain]] = {"declared": [], "strong": [], "possible": [], "defensive": []}
    for d in declared_domains:
        tiers["declared"].append(DiscoveredDomain(
            domain=d, tier="declared",
            evidence=[Evidence(kind="declared", detail="On your declared list")]))
    for dd in result.discovered:                 # owned, corroborated
        bucket = "defensive" if dd.tier == "defensive" else "strong"
        tiers[bucket].append(_convert(dd))
    for dd in result.candidates:                 # low-confidence, held separate
        tiers["possible"].append(_convert(dd))

    total = sum(len(v) for v in tiers.values())
    note = result.note if result.available else NullDiscoveryProvider.NOTE
    return EstateDiscovery(enabled=result.available, declared_count=len(declared_domains),
                           total_found=total, tiers=tiers, note=note)
