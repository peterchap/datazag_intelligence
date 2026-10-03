"""
estatereport/brand_lookalikes.py
--------------------------------
Same-name registrations of an entity's brand label on other TLDs, from the
tailored corpus index (crossestate/corpus_index.py).

For short or generic labels (ploy, refute, aisy) most exact-label matches are
unrelated businesses, not impersonation, so the report calls them "same-name
registrations" and lists only those with evidence of activity:

  * exact label only: `ploy.co.uk` matches `ploy`; `ploy-app.com` and typos do not
  * not the entity's own: excludes its declared and linked domains, and any match
    sharing its nameserver or MX domain (shared infrastructure suggests ownership,
    which is discovery's call, not this list's)
  * confidence = 0.4 for the exact label, +0.3 if it publishes MX (can send and
    receive mail as the brand), +0.2 if it resolves to an address
  * shown when confidence >= THRESHOLD, top TOP_N by confidence

The index carries no registration date or certificate history, so recency is not
scored. Without an index the result is None (not measured), never [].
"""

from __future__ import annotations

from typing import Iterable, Optional

THRESHOLD = 0.6
TOP_N = 5
RULE = (f"Exact brand label on another TLD, excluding the entity's own and linked "
        f"domains and any sharing its nameserver or MX domain. Confidence 0.4 base, "
        f"+0.3 with MX, +0.2 when it resolves; shown at >= {THRESHOLD}, top {TOP_N}. "
        f"Registration date and certificate history are not available in the index.")


def brand_label(domain: str) -> str:
    from crossestate.segments import registrable
    return registrable(domain).split(".")[0]


def _infra(rows, own: set[str]) -> tuple[set[str], set[str]]:
    ns = {r.ns_domain for r in rows if r.domain.lower() in own and r.ns_domain}
    mx = {r.mx_domain for r in rows if r.domain.lower() in own and r.mx_domain}
    return ns, mx


def find(primary_domain: str, own_domains: Iterable[str], corpus) -> Optional[dict]:
    """{label, rule, total_matches, shown: [{domain, confidence, signals}]} or None
    when there is no corpus index. `total_matches` counts every exact-label row
    that passed the ownership exclusions, before the threshold, so the report can
    say "N same-name registrations, M with activity"."""
    if corpus is None:
        return None
    label = brand_label(primary_domain)
    own = {d.lower() for d in own_domains} | {primary_domain.lower()}
    rows = corpus.stem_matches(label, include_hyphen=False)
    own_ns, own_mx = _infra(rows, own)
    scored = []
    total = 0
    for r in rows:
        dom = r.domain.lower()
        if dom in own or (r.stem or "").lower() != label:
            continue
        if (r.ns_domain and r.ns_domain in own_ns) or (r.mx_domain and r.mx_domain in own_mx):
            continue
        total += 1
        conf, signals = 0.4, ["exact brand label"]
        if r.mx_domain:
            conf += 0.3
            signals.append("publishes MX")
        if r.ip or r.asn:
            conf += 0.2
            signals.append("resolves")
        scored.append({"domain": dom, "confidence": round(min(conf, 1.0), 2), "signals": signals})
    shown = sorted((s for s in scored if s["confidence"] >= THRESHOLD),
                   key=lambda s: (-s["confidence"], s["domain"]))
    return {"label": label, "rule": RULE, "total_matches": total,
            "active_matches": len(shown), "shown": shown[:TOP_N]}
