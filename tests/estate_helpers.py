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
            imps=None, lookalikes=None, subs=None, cert=None, has_intel=True) -> ReportViewModel:
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
                                       lookalike_candidates=lookalikes or []),
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
