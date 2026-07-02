"""
estatereport/discovery.py
-------------------------
Estate discovery (spec §2 page 2, §3.1) — the four confidence tiers.

Discovery LEADS the report and its structure never disappears: when the real
discovery pipeline (330M corpus + CRN + connected-domain inference) is not wired,
this NullDiscoveryProvider renders the four-tier model with declared-only data and
an explicit "discovery not enabled for this run" note. Grade scope is declared +
strongly-associated; possible is listed ungraded ("pending confirmation");
defensive is never graded.

The interface matches the spec's tiers so the corpus/CRN implementation drops in
without touching the renderer.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from estatereport.contract import DiscoveredDomain, EstateDiscovery, Evidence


@runtime_checkable
class DiscoveryProvider(Protocol):
    def discover(self, group: str, declared: list[str]) -> EstateDiscovery:
        ...


class NullDiscoveryProvider:
    """MVP default. Declared domains only; strong/possible/defensive empty;
    `enabled=False` so the renderer shows the honest placeholder panel."""

    NOTE = ("Undeclared-domain discovery is not enabled for this run. It requires the "
            "Datazag 340M-domain corpus, Companies House CRN links and connected-domain "
            "inference (shared certificate SANs, MX/SPF, registrar and nameserver "
            "patterns). The four-tier model below is shown with your declared estate only.")

    def discover(self, group: str, declared: list[str]) -> EstateDiscovery:
        declared_rows = [
            DiscoveredDomain(domain=d, tier="declared",
                             evidence=[Evidence(kind="declared", detail="On your declared list")])
            for d in declared
        ]
        return EstateDiscovery(
            enabled=False,
            declared_count=len(declared),
            total_found=len(declared),
            tiers={"declared": declared_rows, "strong": [], "possible": [], "defensive": []},
            note=self.NOTE,
        )
