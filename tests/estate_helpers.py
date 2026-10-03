"""
tests/estate_helpers.py
-----------------------
Shared builders for the cross-estate tests: construct small ReportViewModel /
DomainRef instances without the live pipeline. Repo-root is put on sys.path so
these run under pytest or standalone.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from crossestate.contract import DomainRef  # noqa: E402
from healthreport.grade import score_to_grade  # noqa: E402
from intelligence_contract import (  # noqa: E402
    Annotation,
    DnsHygiene,
    ExternalThreat,
    PlatformImpersonation,
    Registration,
    ReportViewModel,
    ThreatSurface,
    TrustSurface,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ESTATE_MANIFEST = os.path.join(FIXTURES, "estate", "manifest.json")


def make_vm(domain, score=30, *, dmarc="reject", spf_strict=True, dnssec=True,
            caa=True, ns=None, registrar=None, asn=0, isp=None, mailbox=None,
            hosting=None, expires=None, status="clientTransferProhibited",
            imps=None, lookalikes=None, subs=None, cert=None, has_intel=True,
            lookup_ok=True) -> ReportViewModel:
    g = score_to_grade(score if has_intel else None)
    return ReportViewModel(
        domain=domain, has_intelligence=has_intel, composite_score=score, grade=g,
        trust=TrustSurface(score=score, grade=g,
                           dmarc_risk=(dmarc not in ("reject", "quarantine")),
                           spf_risk=(not spf_strict), mx_type=(mailbox or "unknown"),
                           asn=asn, isp=isp),
        threat=ThreatSurface(score=score, grade=g),
        hygiene=DnsHygiene(dmarc_policy=dmarc, spf_strict=spf_strict,
                           spf_record="v=spf1 -all" if spf_strict else "v=spf1 ~all",
                           dnssec=dnssec, caa_present=caa),
        registration=Registration(registrar=registrar, expires_date=expires,
                                   dnssec=dnssec, status=status),
        annotation=Annotation(domain=domain, ns_provider=ns, mailbox_provider=mailbox,
                              hosting_provider=hosting, asn=asn or None),
        external_threat=ExternalThreat(impersonations=imps or [],
                                       lookalike_candidates=lookalikes or [],
                                       lookup_ok=lookup_ok),
        subdomains=subs or [], cert_analysis=cert or {},
    )


def make_ref(domain, segment, **vm_kwargs) -> DomainRef:
    source = vm_kwargs.pop("segment_source", "supplied")
    disagree = vm_kwargs.pop("segment_disagreement", False)
    return DomainRef(domain=domain, segment=segment, segment_source=source,
                     segment_disagreement=disagree, vm=make_vm(domain, **vm_kwargs))


def imp(platform, c7=0, c30=0, samples=None, confidence="exact") -> PlatformImpersonation:
    return PlatformImpersonation(platform=platform, count_7d=c7, count_30d=c30,
                                 sample_domains=samples or [], confidence=confidence)


def fixture_observatory():
    """The committed 2026-09-08 Observatory snapshot (corpus_domains = 364,175,633).
    Estate tests inject this (or no_observatory()) so they never reach R2."""
    import observatory
    os.environ["OBSERVATORY_DATE"] = "20260908"
    try:
        return observatory.load(os.path.join(FIXTURES, "observatory") + "/")
    finally:
        os.environ.pop("OBSERVATORY_DATE", None)


def no_observatory():
    import observatory
    return observatory.Observatory.unavailable()


def report_from_refs(refs, now, observatory=None, tagged: bool = True):
    """Build a v2.2 EstateReport from in-memory refs via real contract files and the
    real build path. tagged=False drops the segments so they are INFERRED
    (ns:/reg:/asn: keys), as on a real estate with no customer tags."""
    import json
    import tempfile

    from crossestate.build import build_estate_view_model
    from crossestate.manifest import ManifestEntry
    from estatereport.build import build_estate_report

    with tempfile.TemporaryDirectory() as d:
        entries = []
        for r in refs:
            p = os.path.join(d, f"{r.domain}.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(r.vm.model_dump(mode="json"), fh)
            entries.append(ManifestEntry(domain=r.domain, segment=(r.segment if tagged else None),
                                         contract_path=p))
        mvp = build_estate_view_model("g", entries, now=now)
    return build_estate_report(mvp, now=now,
                               observatory=observatory if observatory is not None else no_observatory())


def visible_text(html: str) -> str:
    """What a reader sees: tags, <style> and <head> removed, entities decoded."""
    import html as _html
    import re
    body = re.sub(r"(?is)<head>.*?</head>|<style.*?</style>|<script.*?</script>", " ", html)
    return _html.unescape(re.sub(r"<[^>]+>", " ", body))
