"""
estatereport/entities.py
------------------------
Build `entities[]`: one record per company in the estate, plus the owner, from
the per-domain contracts already loaded by the crossestate engine.

Everything here is read from data on the contracts or from the estate's own
analytics. A field with no data source is left empty or None (not measured);
nothing is estimated.
"""

from __future__ import annotations

import re
from typing import Optional

from estatereport import brand_lookalikes as _bl
from estatereport.contract import (
    BrandLookalike,
    BrandLookalikes,
    CalItem,
    CertIssue,
    DomainRecord,
    EmailGateway,
    Entity,
    EstateDiscovery,
    LinkedDomain,
    SaasPlatform,
    SubdomainSummary,
)
from estatereport.controls import controls_for, gaps, top_issue

# A CT hostname is "notable" when any label left of the registrable domain is one
# of these (optionally followed by digits): login and admin surfaces, pre-production
# environments, remote access and APIs.
NOTABLE_LABELS = ("auth", "login", "signin", "sso", "idp", "admin", "staging", "stage", "stg",
                  "dev", "test", "qa", "uat", "demo", "sandbox", "vpn", "remote", "api")
_NOTABLE_RE = re.compile(r"^(?:" + "|".join(NOTABLE_LABELS) + r")\d*$")
NOTABLE_CAP = 25


def _notable(host: str, apex: str) -> bool:
    left = host[: -len(apex)].rstrip(".") if host.endswith(apex) else host
    return any(_NOTABLE_RE.match(lbl) for lbl in re.split(r"[.\-]", left) if lbl)


def subdomain_summary(vm, domain: str) -> SubdomainSummary:
    names = set()
    for s in (vm.subdomains or []):
        if not isinstance(s, dict):
            continue
        n = str(s.get("dns_name") or "").strip().lower().rstrip(".")
        if not n or n.startswith("*") or n == domain or not n.endswith("." + domain):
            continue
        names.add(n)
    notable = sorted(n for n in names if _notable(n, domain))
    return SubdomainSummary(count=len(names), notable=notable[:NOTABLE_CAP])


def saas_platforms(vm) -> list[SaasPlatform]:
    """Platforms evidenced by MX / SPF include / CNAME, via the free report's
    guarded reader (ownership-proof TXT tokens are never platform evidence). The
    mailbox provider is reported as the email gateway, not repeated here."""
    from freereport.compose import confirmed_platforms, mailbox_provider
    mbp, _ = mailbox_provider(vm)
    out = []
    for p in confirmed_platforms(vm):
        if mbp and p["name"].strip().lower() == mbp.strip().lower():
            continue
        out.append(SaasPlatform(provider=p["name"], category=p.get("category") or "",
                                evidence=p.get("evidence") or ""))
    return out


def email_gateway(vm) -> Optional[EmailGateway]:
    """The inbound mail path: a security gateway when an MX points at one,
    otherwise the mailbox provider. None when the domain publishes no MX."""
    from freereport.compose import mailbox_provider
    from mx_platforms import classify_mx
    hosts = [str(m).split()[-1].lower().rstrip(".") for m in (vm.dns_records.mx or []) if str(m).strip()]
    for h in hosts:
        provider, category = classify_mx(h)
        if provider and (category or "").lower() == "security gateway":
            return EmailGateway(provider=provider, kind="gateway", category=category)
    if not hosts:
        return None
    mbp, cat = mailbox_provider(vm)
    return EmailGateway(provider=mbp, kind="mailbox", category=cat or "") if mbp else None


def cert_issues(calendar: list[CalItem], domain: str) -> list[CertIssue]:
    return [CertIssue(host=c.host or c.domain, kind=c.item_kind, due=c.due,
                      days_left=c.days_left)
            for c in calendar if c.domain == domain and c.item_kind.startswith("cert")]


def domain_record(ref, calendar: list[CalItem]) -> DomainRecord:
    vm = ref.vm
    ctl = controls_for(vm, ref.load_error)
    # load_error also carries "live DNS scan did not finish" (crossestate.build).
    if not (getattr(vm, "has_intelligence", False) and not ref.load_error):
        return DomainRecord(domain=ref.domain, primary=ref.primary, assessed=False,
                            not_assessed_reason=ref.load_error or "no intelligence for this domain",
                            controls=ctl)
    return DomainRecord(
        domain=ref.domain, primary=ref.primary, assessed=True,
        grade=(vm.grade.letter if getattr(vm, "grade", None) else None),
        score=float(vm.composite_score or 0), controls=ctl,
        findings=[text for _, text in gaps(ctl)],
        subdomains=subdomain_summary(vm, ref.domain),
        saas=saas_platforms(vm), email_gateway=email_gateway(vm),
        cert_issues=cert_issues(calendar, ref.domain),
    )


def _union_subdomains(records: list[DomainRecord]) -> SubdomainSummary:
    return SubdomainSummary(count=sum(r.subdomains.count for r in records),
                            notable=sorted({n for r in records for n in r.subdomains.notable})[:NOTABLE_CAP])


def _union_saas(records: list[DomainRecord]) -> list[SaasPlatform]:
    seen, out = set(), []
    for r in records:
        for s in r.saas:
            if s.provider.lower() not in seen:
                seen.add(s.provider.lower())
                out.append(s)
    return out


def _linked(disc: Optional[EstateDiscovery], domains: set[str]) -> list[LinkedDomain]:
    if disc is None:
        return []
    return [LinkedDomain(domain=d.domain, tier=d.tier, evidence=d.evidence)
            for d in disc.tiers.get("strong", []) if set(d.linked_to) & domains]


def build_entity(name: str, role: str, refs: list, calendar: list[CalItem],
                 disc: Optional[EstateDiscovery], corpus=None) -> Entity:
    refs = sorted(refs, key=lambda r: (not r.primary, r.domain))
    records = [domain_record(r, calendar) for r in refs]
    primary = records[0]
    domains = [r.domain for r in records]
    linked = _linked(disc, set(domains))

    bl = None
    found = _bl.find(primary.domain, set(domains) | {l.domain for l in linked}, corpus)
    if found is not None:
        bl = BrandLookalikes(label=found["label"], total_matches=found["total_matches"],
                             active_matches=found["active_matches"],
                             shown=[BrandLookalike(**s) for s in found["shown"]])

    return Entity(
        name=name, primary_domain=primary.domain, role=role, domains=domains,
        assessed=primary.assessed, grade=primary.grade, score=primary.score,
        controls=primary.controls, top_issue=top_issue(primary.controls) if primary.assessed else None,
        records=records,
        subdomains=_union_subdomains(records), saas=_union_saas(records),
        email_gateway=primary.email_gateway,
        cert_issues=[c for r in records for c in r.cert_issues],
        brand_lookalikes=bl, linked_domains=linked,
    )


def build_entities(mvp, calendar: list[CalItem], disc: Optional[EstateDiscovery],
                   owner_disc: Optional[EstateDiscovery] = None, corpus=None,
                   now=None) -> list[Entity]:
    """Owner first, then the estate's entities sorted by name. Entity membership
    comes from the estate spec (`DomainRef.entity`); a plain manifest makes every
    domain its own entity."""
    groups: dict[tuple[str, str], list] = {}
    for seg in mvp.segments:
        for r in seg.domains:
            groups.setdefault((r.entity_name, r.role), []).append(r)
    out = []
    owner_refs = list(getattr(mvp, "owner_refs", []) or [])
    if owner_refs:
        name = (mvp.owner or {}).get("name") or owner_refs[0].entity_name
        out.append(build_entity(name, "owner", owner_refs,
                                calendar_for_owner(mvp, owner_refs, now), owner_disc, corpus))
    for (name, role), refs in sorted(groups.items(), key=lambda kv: kv[0][0].lower()):
        out.append(build_entity(name, role, refs, calendar, disc, corpus))
    return out


def calendar_for_owner(mvp, owner_refs, now=None) -> list[CalItem]:
    """The owner's own calendar rows. The estate calendar excludes the owner, so
    they are computed here, with the same rules, for the owner's page only."""
    from crossestate.analytics import compute_calendar
    from estatereport.transform import calendar as to_items

    class _M:
        pass
    m = _M()
    m.calendar = compute_calendar([r.model_copy(update={"role": "portfolio"}) for r in owner_refs],
                                  mvp.thresholds, now=now)
    return to_items(m)
