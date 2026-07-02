"""
estatereport/resilience.py
--------------------------
The §4a concentration severity model — resilience-weighted, not fixed-threshold.

Two facts a fixed threshold conflates: how MUCH of the estate is on one provider
(mechanical share — stays uncoloured and honest) and how BAD it is that it's this
provider (judgement — lives in provider resilience data). Share drives the bar
length; resilience drives the severity pill + recommendation.

`ref.provider_resilience` is authored here as a starter in-repo table (registrar /
CA / NS / ASN fully tiered; the head of the mailbox set tiered, tail defaulted).
Hard fallback rule: an unknown or unassessed provider is treated as `commodity`
and rendered "resilience: not assessed" — never implicitly safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

Tier = Literal["hyperscale", "enterprise", "commodity", "fragile"]
Exit = Literal["low", "medium", "high"]
Severity = Literal["high", "elevated", "watch"]

_SEV_RANK = {"watch": 0, "elevated": 1, "high": 2}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}


@dataclass(frozen=True)
class ProviderResilience:
    provider: str
    dimension: str
    tier: Tier
    exit_friction: Exit
    assessed: bool                    # False → commodity default + "not assessed" in evidence


# ref.provider_resilience — canonical substring → (tier, exit_friction). Matched
# case-insensitively against the provider label. Order-independent; the longest
# / first match wins in _match. Worked examples from the spec are encoded exactly
# (Let's Encrypt = hyperscale CA; GoDaddy = commodity registrar, high exit).
_REF: dict[str, dict[str, tuple[Tier, Exit]]] = {
    "registrar": {
        "markmonitor": ("enterprise", "low"), "csc": ("enterprise", "low"),
        "cloudflare": ("hyperscale", "low"), "amazon": ("hyperscale", "low"),
        "route 53": ("hyperscale", "low"), "google": ("hyperscale", "low"),
        "godaddy": ("commodity", "high"), "namecheap": ("commodity", "high"),
        "network solutions": ("commodity", "high"), "gandi": ("commodity", "medium"),
        "tucows": ("commodity", "medium"), "enom": ("commodity", "high"),
        "ionos": ("commodity", "medium"), "1&1": ("commodity", "medium"),
    },
    "mailbox": {
        "microsoft": ("hyperscale", "medium"), "office 365": ("hyperscale", "medium"),
        "google": ("hyperscale", "medium"), "proofpoint": ("enterprise", "medium"),
        "mimecast": ("enterprise", "medium"), "barracuda": ("enterprise", "medium"),
        "zoho": ("commodity", "medium"), "fastmail": ("commodity", "medium"),
        "self-hosted": ("fragile", "high"), "self hosted": ("fragile", "high"),
    },
    "ns": {
        "cloudflare": ("hyperscale", "low"), "route 53": ("hyperscale", "low"),
        "amazon": ("hyperscale", "low"), "aws": ("hyperscale", "low"),
        "google": ("hyperscale", "low"), "azure": ("hyperscale", "low"),
        "akamai": ("hyperscale", "low"), "ultradns": ("enterprise", "low"),
        "ns1": ("enterprise", "medium"), "dyn": ("enterprise", "medium"),
        "godaddy": ("commodity", "high"), "dnsmadeeasy": ("commodity", "medium"),
    },
    "asn": {
        "cloudflare": ("hyperscale", "low"), "amazon": ("hyperscale", "low"),
        "aws": ("hyperscale", "low"), "google": ("hyperscale", "low"),
        "microsoft": ("hyperscale", "low"), "azure": ("hyperscale", "low"),
        "akamai": ("hyperscale", "low"), "fastly": ("hyperscale", "low"),
        "digitalocean": ("commodity", "medium"), "ovh": ("commodity", "medium"),
        "godaddy": ("commodity", "high"), "hetzner": ("commodity", "medium"),
    },
    "hosting": {
        "cloudflare": ("hyperscale", "low"), "amazon": ("hyperscale", "low"),
        "aws": ("hyperscale", "low"), "akamai": ("hyperscale", "low"),
        "google": ("hyperscale", "low"), "azure": ("hyperscale", "low"),
        "fastly": ("hyperscale", "low"), "godaddy": ("commodity", "high"),
    },
    "ca_issuer": {
        "let's encrypt": ("hyperscale", "low"), "lets encrypt": ("hyperscale", "low"),
        "digicert": ("enterprise", "low"), "globalsign": ("enterprise", "low"),
        "entrust": ("enterprise", "low"), "google trust": ("hyperscale", "low"),
        "amazon": ("hyperscale", "low"), "sectigo": ("commodity", "low"),
        "comodo": ("commodity", "low"), "godaddy": ("commodity", "medium"),
    },
}

# Dimension aliases so callers can pass the MVP dimension keys.
_DIM_ALIAS = {"ca": "ca_issuer", "ca_issuer": "ca_issuer", "mailbox": "mailbox",
              "registrar": "registrar", "ns": "ns", "asn": "asn", "hosting": "hosting"}


def lookup(provider: Optional[str], dimension: str) -> ProviderResilience:
    dim = _DIM_ALIAS.get(dimension, dimension)
    table = _REF.get(dim, {})
    name = (provider or "").strip().lower()
    if name and table:
        for key, (tier, exit_f) in table.items():
            if key in name:
                return ProviderResilience(provider or "", dim, tier, exit_f, assessed=True)
    # Hard fallback: unknown/unassessed → commodity, never implicitly safe.
    return ProviderResilience(provider or "unknown", dim, "commodity", "medium", assessed=False)


# Severity matrix (spec §4a). Rows = share band, cols = resilience tier.
_MATRIX = {
    "hi": {"hyperscale": "watch", "enterprise": "elevated", "commodity": "high", "fragile": "high"},
    "mid": {"hyperscale": None, "enterprise": "watch", "commodity": "elevated", "fragile": "high"},
    "lo": {"hyperscale": None, "enterprise": None, "commodity": None, "fragile": "watch"},
}

# One-clause recommendation per (band, tier), from the §4a copy matrix.
_RECO = {
    ("hi", "hyperscale"): "verify account-level controls (MFA, admin recovery); concentration acceptable if deliberate",
    ("hi", "enterprise"): "lock down: registrar/account locks, CAA pinning, recovery paths",
    ("hi", "commodity"): "reduce: migrate the weakest segment to the group-standard provider",
    ("hi", "fragile"): "diversify now: failure modes are not survivable at this share",
    ("mid", "enterprise"): "monitor; keep account controls verified",
    ("mid", "commodity"): "plan to reduce before it grows",
    ("mid", "fragile"): "diversify: fragile provider at material share",
    ("lo", "fragile"): "watch: fragile provider, keep the share low",
}


def _band(share: float) -> str:
    if share >= 0.50:
        return "hi"
    if share >= 0.35:
        return "mid"
    return "lo"


def severity(share: float, res: ProviderResilience) -> tuple[Optional[Severity], str]:
    """Return (severity | None, recommendation) for a provider at `share` of the
    estate. Rules: share ≥ 50% ALWAYS yields a register-eligible finding (the tier
    only sets which severity); `exit_friction = high` bumps severity one level at
    ≥ 50% (leaving under duress is slow and transfer-abusable)."""
    band = _band(share)
    sev = _MATRIX[band].get(res.tier)
    if band == "hi" and sev is None:
        sev = "watch"                 # floor: ≥50% always registers
    if sev and band == "hi" and res.exit_friction == "high":
        sev = _RANK_SEV[min(2, _SEV_RANK[sev] + 1)]
    reco = _RECO.get((band, res.tier), "")
    if res.exit_friction == "high" and band == "hi" and reco:
        reco += " · high exit friction"
    return sev, reco
