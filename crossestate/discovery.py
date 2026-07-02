"""
crossestate/discovery.py
------------------------
Estate discovery — the ONE pass that feeds both estate completeness (§2.1) and,
via the v2.2 adapter, the four confidence tiers (§2.7). Owned discoveries are a
*suggestion* (confirm → expand scope); the hostile/impersonation lane stays
feed-delivered (SKU-2) and is cross-referenced from the exposure section, not
asserted here.

What's real in-repo: **cross-domain certificate SANs**. A certificate whose SAN
list covers a declared domain AND an undeclared one is strong evidence the same
party controls both — it surfaces undeclared domains from data already on each
contract's `cert_analysis`. The corroboration stack then assigns the tier.

**The gate rule (the failure mode designed out):** a brand/lexical string-match
*qualifies* a candidate for scoring; it never *decides* the lane. A shared SAN
with no apex/brand corroboration (e.g. a shared CDN "universal" certificate that
lists unrelated co-tenants) is held as a low-confidence CANDIDATE, never folded
into the owned headline. Classify on the string match alone and the report would
eventually tell a customer they own their CDN's other customers.

The heavy signals not in this repo (330M-corpus brand sweep, Companies House CRN,
live active-check DNS→website→CV) plug in behind `active_check` / a corpus
provider without changing the callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, runtime_checkable

from crossestate.contract import CompletenessBlock
from crossestate.segments import registrable


@dataclass
class DiscoveredDomain:
    domain: str
    lane: str                              # owned | ambiguous  (hostile is feed-delivered, not asserted here)
    tier: str                              # strong | possible | defensive
    evidence: list[dict] = field(default_factory=list)   # {kind, detail}
    confidence: float = 0.0
    corroboration: list[str] = field(default_factory=list)


@dataclass
class DiscoveryResult:
    available: bool
    declared: list[str]
    discovered: list[DiscoveredDomain] = field(default_factory=list)   # owned, corroborated
    candidates: list[DiscoveredDomain] = field(default_factory=list)   # low-confidence, held separate
    hostile: list[DiscoveredDomain] = field(default_factory=list)      # lookalike/typosquat — alert, not headlined as owned
    note: str = ""


@runtime_checkable
class DiscoveryProvider(Protocol):
    def discover(self, group: str, refs) -> DiscoveryResult:
        ...


# ---------------------------------------------------------------------------
# Null provider — discovery genuinely not run (no cert data / disabled)
# ---------------------------------------------------------------------------

class NullDiscoveryProvider:
    NOTE = ("Undeclared-domain discovery is not enabled for this run. The declared "
            "estate is shown as-is.")

    def discover(self, group: str, refs) -> DiscoveryResult:
        return DiscoveryResult(available=False, declared=[r.domain for r in refs], note=self.NOTE)


# ---------------------------------------------------------------------------
# Real (passive) provider — connected-domain discovery via cross-domain cert SANs
# ---------------------------------------------------------------------------

_DEFENSIVE_HINTS = ("login", "payroll", "invoice", "portal", "secure", "account", "sso")
_MIN_STEM = 4


class ConnectedDomainDiscoveryProvider:
    """Passive discovery from signals already on the loaded contracts.

    `active_check` (optional) is the hook for the heavier corroboration the spec
    describes — resolve the candidate, fetch the page, CV brand-match — run only
    on candidates that pass the cheap gate. Absent, discovery is corpus-free and
    corroborates on apex/brand + SAN-link count only.
    """

    def __init__(self, active_check: Optional[Callable[[str], dict]] = None,
                 corpus=None, min_confidence: float = 0.5, dga_threshold: float = 0.6):
        self.active_check = active_check
        self.corpus = corpus                 # ParquetCorpusIndex | None — the corpus stem-sweep source
        self.min_confidence = min_confidence
        self.dga_threshold = dga_threshold

    def discover(self, group: str, refs) -> DiscoveryResult:
        declared = {r.domain.lower() for r in refs}
        estate_apex = {registrable(r.domain) for r in refs}
        estate_stems = {a.split(".")[0] for a in estate_apex if a.split(".")[0]}

        # candidate → {san_links: set(declared domains), }
        cand: dict[str, set] = {}
        for r in refs:
            for san in _cross_domain_sans(r.vm, declared):
                cand.setdefault(san, set()).add(r.domain)

        discovered: list[DiscoveredDomain] = []
        candidates: list[DiscoveredDomain] = []
        hostile: list[DiscoveredDomain] = []
        seen: set = set(declared)
        for dom, links in sorted(cand.items()):
            seen.add(dom)
            apex = registrable(dom)
            stem = apex.split(".")[0]
            apex_match = apex in estate_apex
            brand_match = (stem in estate_stems) or any(
                s in dom for s in estate_stems if len(s) >= _MIN_STEM)
            corr: list[str] = [f"{len(links)} shared-certificate link(s)"]
            if apex_match:
                corr.append("shared registrable apex")
            if brand_match:
                corr.append("brand/lexical match")

            ev = [{"kind": "san",
                   "detail": f"On a certificate with {', '.join(sorted(links)[:3])}"
                             + (" …" if len(links) > 3 else "")}]

            # Gate rule: SAN alone qualifies; corroboration decides the lane.
            corroborated = apex_match or brand_match
            defensive = any(h in dom for h in _DEFENSIVE_HINTS)
            if corroborated:
                conf = min(0.95, 0.7 + 0.1 * len(links) + (0.1 if apex_match else 0.0))
                tier = "defensive" if defensive else "strong"
                discovered.append(DiscoveredDomain(dom, "owned", tier, ev, round(conf, 2), corr))
            else:
                # shared cert but no ownership corroboration → likely a co-tenant.
                conf = 0.45 + 0.05 * (len(links) - 1)
                candidates.append(DiscoveredDomain(dom, "ambiguous", "possible", ev,
                                                   round(min(conf, 0.6), 2),
                                                   corr + ["no apex/brand corroboration — held for review"]))

        # ── Corpus stem-sweep source (the tailored index) ────────────────────
        corpus_n = 0
        if self.corpus is not None:
            self._corpus_pass(refs, declared, seen, discovered, candidates, hostile)
            corpus_n = len(discovered) + len(candidates) + len(hostile) - len(cand)

        src = "shared-certificate links" + (" + corpus stem-sweep" if self.corpus is not None else "")
        note = (f"Discovery ran over {src} across {len(refs)} declared domains. "
                f"{len(discovered)} undeclared owned domain(s) surfaced; {len(candidates)} low-confidence "
                f"candidate(s) held for review"
                + (f"; {len(hostile)} lookalike(s) flagged (feed-delivered, not claimed as owned)"
                   if hostile else "")
                + ". Companies House CRN (UK) and the live impersonation feed extend this.")
        return DiscoveryResult(available=True, declared=sorted(declared),
                               discovered=discovered, candidates=candidates,
                               hostile=hostile, note=note)

    def _corpus_pass(self, refs, declared, seen, discovered, candidates, hostile) -> None:
        """Sweep the tailored corpus index per estate stem; classify brand-family
        domains via infra corroboration + DGA/entropy. The corpus DNS columns give
        both the estate's own infra fingerprint (from the declared rows) and each
        candidate's — so ownership is corroborated straight from the file."""
        from crossestate.entropy import dga_score, is_typosquat

        by_stem: dict[str, list] = {}
        for r in refs:
            by_stem.setdefault(registrable(r.domain).split(".")[0], []).append(r)

        for stem, _group in by_stem.items():
            if not stem:
                continue
            rows = self.corpus.stem_matches(stem)          # declared + candidates, one partition read
            estate_ns = {r.ns_domain for r in rows if r.domain.lower() in declared and r.ns_domain}
            estate_mx = {r.mx_domain for r in rows if r.domain.lower() in declared and r.mx_domain}
            for c in rows:
                dom = c.domain.lower()
                if dom in seen:
                    continue
                seen.add(dom)
                dga = dga_score(c.stem)
                infra = bool((c.ns_domain and c.ns_domain in estate_ns)
                             or (c.mx_domain and c.mx_domain in estate_mx))
                exact = (c.stem == stem)
                typo = is_typosquat(c.stem, stem)
                ev = [{"kind": "corpus", "detail": f"Brand-family domain in the corpus (stem '{c.stem}')"}]
                corr: list[str] = []
                if infra:
                    corr.append(f"shares infrastructure with the estate ({c.ns_domain or c.mx_domain})")
                if exact:
                    corr.append("exact brand stem, different TLD")

                if infra:                                   # shared NS/MX = strong ownership
                    discovered.append(DiscoveredDomain(dom, "owned", "strong",
                                       ev + [{"kind": "ns", "detail": corr[0]}], 0.9, corr))
                elif exact and dga < 0.5 and not typo:      # clean brand extension you own
                    discovered.append(DiscoveredDomain(dom, "owned", "strong", ev, 0.8,
                                       corr or ["exact brand stem"]))
                elif typo or dga >= self.dga_threshold:     # lookalike/typosquat — hostile lane
                    hostile.append(DiscoveredDomain(dom, "hostile", "defensive",
                                    ev + [{"kind": "dga",
                                           "detail": f"lookalike signature (dga {dga}"
                                                     + (", typosquat" if typo else "") + ")"}],
                                    0.4, ["lookalike/DGA signature — alert, not owned"]))
                else:                                       # brand-family, no corroboration → review
                    candidates.append(DiscoveredDomain(dom, "ambiguous", "possible", ev, 0.5,
                                       ["brand-family match, no infra corroboration — held for review"]))


def default_discovery() -> DiscoveryProvider:
    """The provider the reports use unless one is injected. Wires the tailored
    corpus index when `CORPUS_INDEX_DIR` points at a built index; otherwise runs
    cert-SAN discovery only (no corpus needed locally / in tests)."""
    import os
    idx = os.environ.get("CORPUS_INDEX_DIR")
    if idx and os.path.isdir(idx):
        try:
            from crossestate.corpus_index import ParquetCorpusIndex
            return ConnectedDomainDiscoveryProvider(corpus=ParquetCorpusIndex(idx))
        except Exception as e:  # pragma: no cover - never let discovery config sink a report
            print(f"  discovery: corpus index at {idx} unavailable ({e}); cert-SAN only")
    return ConnectedDomainDiscoveryProvider()


def _cross_domain_sans(vm, declared: set) -> set:
    """Undeclared domains appearing on this domain's certificates. Tolerant of
    the two plausible `cross_domain_sans` shapes (list[str] | list[dict])."""
    ca = getattr(vm, "cert_analysis", None) or {}
    raw = ca.get("cross_domain_sans")
    out: set = set()
    if isinstance(raw, list):
        for it in raw:
            if isinstance(it, dict):
                d = it.get("domain") or it.get("dns_name") or it.get("name")
            else:
                d = it
            if not d:
                continue
            d = str(d).lstrip("*.").strip().lower().rstrip(".")
            # registrable form; skip declared and same-registrable-as-a-declared apexes? keep apex-siblings.
            if d and d not in declared:
                out.add(d)
    return out


# ---------------------------------------------------------------------------
# Adapter → the MVP completeness block (§2.1)
# ---------------------------------------------------------------------------

def to_completeness(result: DiscoveryResult) -> CompletenessBlock:
    owned = result.discovered
    return CompletenessBlock(
        available=result.available,
        declared_n=len(result.declared),
        discovered_n=len(result.declared) + len(owned),
        delta=[{"domain": d.domain, "tier": d.tier, "discovery_method": (d.evidence[0]["kind"] if d.evidence else ""),
                "confidence": d.confidence, "evidence": d.evidence} for d in owned],
        candidates=[{"domain": d.domain, "confidence": d.confidence, "evidence": d.evidence,
                     "corroboration": d.corroboration} for d in result.candidates],
        note=result.note or NullDiscoveryProvider.NOTE,
    )
