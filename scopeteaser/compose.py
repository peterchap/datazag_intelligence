"""Compose the TeaserViewModel from a discovery result — guardrails live HERE.

The commercial rules (WU20 doc §Teaser artefact rules) are enforced at compose
time so no renderer or serializer downstream can leak them:

1. Tier COUNTS are public; possible/defensive NAMES never enter the ViewModel —
   that list is the paid deliverable, and naming defensive candidates in a free
   artefact is a gift to whoever registers them first.
2. At most 3 strongly-associated domains ship as proof, each with its one-line
   connection evidence.
3. The band is computed on declared + strongly associated (the graded estate).
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Iterable, Optional

from scopeteaser.bands import band_for
from scopeteaser.contract import MAX_PROOF_DOMAINS, TEASER_TTL_DAYS, ProofDomain, TeaserViewModel

TIERS = ("declared", "strong", "possible", "defensive")


def tiers_from_discovery_result(result: Any) -> dict[str, list[Any]]:
    """Adapt a crossestate DiscoveryResult into the four teaser tiers.

    Owned+corroborated domains keep their assigned tier; low-confidence
    candidates are possible; the hostile lane maps to defensive (same mapping
    as estatereport.discovery).
    """
    tiers: dict[str, list[Any]] = {t: [] for t in TIERS}
    tiers["declared"] = list(getattr(result, "declared", []) or [])
    for item in getattr(result, "discovered", []) or []:
        tier = getattr(item, "tier", "strong")
        tiers.setdefault(tier if tier in TIERS else "strong", []).append(item)
    for item in getattr(result, "candidates", []) or []:
        tiers["possible"].append(item)
    for item in getattr(result, "hostile", []) or []:
        tiers["defensive"].append(item)
    return tiers


def _evidence_line(item: Any) -> str:
    """One-line connection evidence from a DiscoveredDomain-like object."""
    line = getattr(item, "evidence_line", None)
    if line:
        return str(line)
    evidence = getattr(item, "evidence", None) or []
    parts = []
    for ev in evidence:
        detail = getattr(ev, "detail", None) or (ev.get("detail") if isinstance(ev, dict) else None) or str(ev)
        parts.append(str(detail))
    return " · ".join(parts[:3]) or "connection evidence in the full report"


def _domain(item: Any) -> str:
    return str(getattr(item, "domain", None) or (item.get("domain") if isinstance(item, dict) else item))


def build_teaser(
    tiers: dict[str, Iterable[Any]],
    declared_count: int,
    requested_by: str,
    src: Optional[str] = None,
    today: Optional[date] = None,
) -> TeaserViewModel:
    """`tiers` maps tier name -> DiscoveredDomain-like items (objects or dicts)."""
    tier_items = {t: list(tiers.get(t, [])) for t in TIERS}
    tier_counts = {t: len(items) for t, items in tier_items.items()}
    tier_counts["declared"] = max(tier_counts.get("declared", 0), declared_count)

    proof = [
        ProofDomain(domain=_domain(item), evidence_line=_evidence_line(item))
        for item in tier_items["strong"][:MAX_PROOF_DOMAINS]
    ]

    graded = tier_counts["declared"] + tier_counts["strong"]
    today = today or date.today()
    return TeaserViewModel(
        declared_count=declared_count,
        tier_counts=tier_counts,
        proof_domains=proof,
        band=band_for(graded),
        expires=today + timedelta(days=TEASER_TTL_DAYS),
        requested_by=requested_by,
        src=src,
    )
