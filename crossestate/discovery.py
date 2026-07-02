"""
crossestate/discovery.py
------------------------
The estate-completeness (§2.1) and discovery-triage (§2.7) interface.

The real implementation needs a 330M-corpus + Companies House CRN→domain +
connected-domain inference (shared NS / MX / registrant / cert-SAN / ASN) that
does NOT live in this repo, so the MVP ships a NULL provider. It reports an
honest "not available" status — never a false "estate complete" — and the
`DiscoveryProvider` protocol matches the spec's two-lane (owned / hostile /
ambiguous) triage so the corpus/CRN implementation drops in later without
touching the callers.

Billing note (spec §2.7): owned discoveries are a *suggestion* (confirm →
expand scope); impersonation discoveries are an *alert* (feed-delivered, SKU-2).
The completeness block here only ever surfaces the owned lane; the hostile lane
is the live feed's job, cross-referenced from the exposure section.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from crossestate.contract import CompletenessBlock


@runtime_checkable
class DiscoveryProvider(Protocol):
    def estate_completeness(self, group: str, declared: list[str]) -> CompletenessBlock:
        ...


class NullDiscoveryProvider:
    """MVP default. Reports declared_n only; discovered == declared; no delta,
    no candidates; `available=False` so the render shows an honest placeholder."""

    NOTE = ("Undeclared-domain discovery is not enabled in this edition. It "
            "requires the Datazag 330M-domain corpus + Companies House CRN + "
            "connected-domain inference. Declared estate shown as-is.")

    def estate_completeness(self, group: str, declared: list[str]) -> CompletenessBlock:
        n = len(declared)
        return CompletenessBlock(
            available=False, declared_n=n, discovered_n=n,
            delta=[], candidates=[], note=self.NOTE,
        )
