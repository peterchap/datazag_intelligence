"""
crossestate/technographic.py
----------------------------
The SPF-observed technographic layer: what third-party vendors a domain's own DNS says
it depends on. Feeds §2.2 concentration (a `technographic` dimension), the exception
register, and — via `identity_critical()` — the platform-impersonation exposure join.

WHERE THE FINGERPRINTS COME FROM
--------------------------------
`crossestate/tech_fingerprints.json`, written by
`dnsproject/scripts/export_tech_fingerprints.py` from the ONE authored source
(`dnsproject/lookups/tech_fingerprints_seed.csv` + the two consolidated dictionaries).
It is generated data — do not hand-edit it, and do not add a second table here. Three
copies of the same vendor dictionary is this estate's most expensive recurring defect.

WHY THIS PARSES THE RAW SPF RECORD RATHER THAN READING THE LAKE
---------------------------------------------------------------
Two reasons, and the second one changes the answer:

1. The cross-estate analytics run over already-collected contracts, possibly with no lake
   credentials. `hygiene.spf_record` is on the contract; a lake round-trip is not available.

2. **The corpus cannot see the enterprise tier.** `gold.dns_wide.spf_includes` is built with
   an `[a-z0-9._-]+` character class, which silently drops every MACRO-BEARING term. That is
   the form large organisations publish: measured on a real 18-domain estate, five of them
   delegate SPF as `include:%{ir}.%{v}.%{d}.spf.has.pphosted.com` — Proofpoint, invisible to
   the corpus, plainly visible in the raw record. A technographic layer built on the corpus
   column would report "no email gateway observed" for the exact population the risk reports
   are sold into.

MATCHING RULES — identical to `dnsproject/scripts/annotation_views.technographic_sql`
------------------------------------------------------------------------------------
* Mechanisms considered: `include:`, `redirect=`, `exists:` — the three SPF terms that NAME
  a third-party referral. `a:` / `mx:` / `ip4:` are excluded: they are self-referential or
  bare addresses, not a vendor claim.
* `exact`  -> target == pattern
* `suffix` -> target == pattern OR target ends with "." + pattern  (label boundary; a bare
              `endswith` matched `notzoho.com` against `zoho.com`)
* `regex`  -> re.search(pattern, target)
* LONGEST matching pattern wins per target, so `qiye.aliyun.com` resolves to Alibaba Mail
  rather than to both it and a broader `aliyun.com` row.
* SELF-REFERENTIAL targets are dropped. `include:spf1.adidas.com` on adidas.com is not a
  technographic fact, and counting it would inflate every denominator with noise.

WHAT THIS LAYER DOES NOT COVER — state it in the report, not only here
---------------------------------------------------------------------
* **Subdomain-only sending.** The corpus and these contracts are keyed on the apex. Marketing
  and transactional ESPs commonly sit on a subdomain (`mail.example.com`) or a separate brand
  domain, and are invisible from the apex record.
* **Cousin domains.** `getdatazag.com` and `datazag.com` are separate apexes and nothing here
  links them. No entity resolution is attempted and none should be inferred.
* **Trajectory.** Snapshot only. An SPF include left behind after a vendor switch is a stale
  "uses" claim and this layer cannot tell the difference.
* **Anything not published in DNS.** Absence of a fingerprint means NOT OBSERVED.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

_FP_PATH = Path(__file__).with_name("tech_fingerprints.json")

# include: / redirect= / exists: targets. The character class admits `%{}` so macro-bearing
# terms survive — see the module docstring; this is the whole reason the enterprise tier is
# visible here and not in the corpus column.
_TERM_RE = re.compile(r"(?:include:|redirect=|exists:)([a-z0-9%{}._-]+)")


@dataclass(frozen=True)
class Fingerprint:
    signal_type: str
    match_type: str
    pattern: str
    provider: str
    category: str
    identity_risk: str


@dataclass(frozen=True)
class TechSignal:
    """One observed vendor dependency for one domain."""
    provider: str
    category: str
    identity_risk: str          # high | med | none
    evidence: str               # the SPF term that produced it
    signal_type: str = "SPF_INCLUDE"


@lru_cache(maxsize=1)
def load_fingerprints() -> tuple[Fingerprint, ...]:
    """Load the exported fingerprint set. FAILS LOUD if it is missing: a technographic
    dimension computed against zero fingerprints renders "no vendor observed" for every
    domain, which reads in an underwriting file as a finding rather than as a broken
    deployment. There is no empty-set fallback here on purpose."""
    if not _FP_PATH.exists():
        raise FileNotFoundError(
            f"{_FP_PATH} is missing. Regenerate it with "
            f"`python dnsproject/scripts/export_tech_fingerprints.py`."
        )
    payload = json.loads(_FP_PATH.read_text(encoding="utf-8"))
    rows = payload.get("fingerprints") or []
    if not rows:
        raise ValueError(f"{_FP_PATH} contains no fingerprints.")
    return tuple(
        Fingerprint(
            signal_type=r["signal_type"], match_type=r["match_type"], pattern=r["pattern"],
            provider=r["provider"], category=r.get("category") or "",
            identity_risk=r.get("identity_risk") or "none",
        )
        for r in rows
    )


@lru_cache(maxsize=1)
def _spf_fingerprints() -> tuple[Fingerprint, ...]:
    return tuple(f for f in load_fingerprints() if f.signal_type == "SPF_INCLUDE")


def fingerprint_provenance() -> dict:
    """The export's own metadata, for the report's methodology note."""
    payload = json.loads(_FP_PATH.read_text(encoding="utf-8"))
    return {k: payload[k] for k in ("source_rows", "seed_mtime_utc", "built_from") if k in payload}


def spf_terms(spf_record: Optional[str], domain: str) -> list[str]:
    """Third-party referral targets in an SPF record, self-references removed."""
    if not spf_record:
        return []
    rec = spf_record.strip().lower()
    if not rec.startswith("v=spf1"):
        return []
    d = (domain or "").strip().lower().rstrip(".")
    out: list[str] = []
    for t in _TERM_RE.findall(rec):
        t = t.rstrip(".")
        if not t:
            continue
        if d and (t == d or t.endswith("." + d)):
            continue                      # self-referential shard, not a vendor
        out.append(t)
    return out


def _match(target: str, f: Fingerprint) -> bool:
    if f.match_type == "exact":
        return target == f.pattern
    if f.match_type == "suffix":
        return target == f.pattern or target.endswith("." + f.pattern)
    if f.match_type == "regex":
        try:
            return re.search(f.pattern, target) is not None
        except re.error:
            return False
    return False


def match_target(target: str) -> Optional[Fingerprint]:
    """Longest matching pattern wins — the same rule `mx_platforms.py` uses."""
    best: Optional[Fingerprint] = None
    for f in _spf_fingerprints():
        if _match(target, f) and (best is None or len(f.pattern) > len(best.pattern)):
            best = f
    return best


def signals_for(domain: str, spf_record: Optional[str]) -> list[TechSignal]:
    """The vendor dependencies observable for one domain, deduplicated by provider.

    An empty list means one of three genuinely different things — no SPF record, an SPF
    record with no third-party referral (all `ip4:`), or referrals we could not attribute.
    Callers that need to tell them apart must use `observability()`; treating an empty list
    as "uses nothing" is the error this whole module is written to prevent.
    """
    seen: dict[str, TechSignal] = {}
    for t in spf_terms(spf_record, domain):
        f = match_target(t)
        if f is None:
            continue
        if f.provider not in seen:
            seen[f.provider] = TechSignal(
                provider=f.provider, category=f.category,
                identity_risk=f.identity_risk, evidence=t,
            )
    return list(seen.values())


def observability(domain: str, spf_record: Optional[str]) -> str:
    """Why a domain has (or has not) an observable vendor stack. The denominator rule:
    only `attributed` domains may enter a technographic denominator.

      no_spf        no SPF record published — nothing to observe
      no_referral   SPF present but purely `ip4:`/`a:`/`mx:` — no vendor is NAMED, so this
                    is unobservable, NOT "no vendors"
      unattributed  third-party referrals present, none of them in the fingerprint set —
                    a curation gap, and a known one
      attributed    at least one vendor identified
    """
    if not (spf_record or "").strip().lower().startswith("v=spf1"):
        return "no_spf"
    terms = spf_terms(spf_record, domain)
    if not terms:
        return "no_referral"
    return "attributed" if any(match_target(t) for t in terms) else "unattributed"


def identity_critical(signals: Iterable[TechSignal]) -> list[TechSignal]:
    """The `identity_risk = high` subset — IdP, secure email gateway, payment, e-sign and
    SPF/DMARC delegation. This is the population `ref.platform_impersonation` tracks, and
    it is what makes the exposure join sharp rather than broad.

    🚨 It RANKS exposure. It must never gate, suppress or downgrade an alert. A DocuSign
    phish lands on staff at companies that do not use DocuSign, and a non-match here would
    inherit every coverage gap in this module as a silent false negative — the same failure
    `cc-task-pi-platform-scoring.md` records at 2.5% precision.
    """
    return [s for s in signals if s.identity_risk == "high"]
