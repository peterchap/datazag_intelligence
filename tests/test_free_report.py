"""
Free Single-Domain report tests — exercises the spec's branch matrix + guards.
Standalone runner (no pytest locally); repo-root on sys.path via estate_helpers.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from freereport import compose, maturity  # noqa: E402
from freereport.renderer import FreeReportRenderer  # noqa: E402
from healthreport.grade import score_to_grade  # noqa: E402
from intelligence_contract import (  # noqa: E402
    Annotation, DnsHygiene, DnsRecordSet, ExternalThreat, PlatformImpersonation,
    PlatformSignal, Registration, ReportViewModel, ThreatSurface, TrustSurface,
)

NOW = datetime(2026, 6, 20, tzinfo=timezone.utc)


def _vm(domain="example.com", score=40, *, dmarc="reject", spf="v=spf1 -all",
        caa=True, dnssec=True, tls_issuer="DigiCert", mailbox=None, hosting=None,
        asn=0, isp_country=None, registrar="CSC", status="clientTransferProhibited clientDeleteProhibited",
        expires="2027-08-04", signals=None, imps=None, subs=None, mx=None, has_intel=True):
    g = score_to_grade(score if has_intel else None)
    return ReportViewModel(
        domain=domain, has_intelligence=has_intel, composite_score=score, grade=g,
        trust=TrustSurface(score=score, grade=g, asn=asn, isp_country=isp_country),
        threat=ThreatSurface(score=score, grade=g),
        hygiene=DnsHygiene(spf_record=spf, dmarc_policy=dmarc, caa_present=caa,
                           dnssec=dnssec, tls_issuer=tls_issuer),
        registration=Registration(registrar=registrar, expires_date=expires, status=status, dnssec=dnssec),
        annotation=Annotation(domain=domain, mailbox_provider=mailbox, hosting_provider=hosting,
                              asn=asn or None, isp_country=isp_country, platform_signals=signals or []),
        external_threat=ExternalThreat(impersonations=imps or []),
        dns_records=DnsRecordSet(mx=mx or []),
        subdomains=subs or [],
    )


def _render(vm):
    return FreeReportRenderer(vm, now=NOW).to_html()


# ---- structure ----

def test_five_pages_and_verbatim_tokens():
    html = _render(_vm())
    assert html.count('class="page') == 5
    assert "--cyan:#00C2FF" in html                     # design token verbatim
    assert "endpoint security, network segmentation" in html  # scope caveat verbatim


# ---- dashboard branches ----

def test_strong_email_branch():
    d = compose.dashboard(_vm(dmarc="reject", spf="v=spf1 -all"), NOW)
    email = next(c for c in d if c["key"] == "Email security")
    assert email["cls"] == "ok" and email["state"] == "Strong"


def test_weak_email_branch():
    vm = _vm(dmarc="none", spf="v=spf1 ~all")
    d = compose.dashboard(vm, NOW)
    email = next(c for c in d if c["key"] == "Email security")
    assert email["cls"] == "bad" and email["state"] == "Exposed"
    # synthesis reflects the weaker posture
    assert "needs attention" in compose.synthesis(vm, NOW)


def test_no_impersonation_branch_low_and_primer_present():
    vm = _vm(imps=[])
    ext = next(c for c in compose.dashboard(vm, NOW) if c["key"] == "External threat")
    assert ext["cls"] == "ok" and ext["state"] == "Low"
    html = _render(vm)
    assert "How the cyber attack economy works" in html   # primer still renders
    assert "no confirmed impersonation" in compose.observed_event_line(vm).lower()


# ---- classifier / guards ----

def test_google_workspace_mx_classifier_not_token_trap():
    vm = _vm(mailbox="Google Workspace", mx=["1 aspmx.l.google.com"],
             signals=[PlatformSignal(provider="Google Search Console", signal_type="TXT",
                                     match_type="txt", evidence="google-site-verification=abc")])
    plats = compose.confirmed_platforms(vm)
    names = [p["name"] for p in plats]
    assert "Google Workspace" in names                   # real MX classified
    assert "Google Search Console" not in names          # ownership token excluded
    assert "google-site-verification" not in _render(vm)


def test_lookalikes_excluded_from_headline():
    vm = _vm(imps=[PlatformImpersonation(platform="m365", count_30d=2, confidence="exact")])
    vm.external_threat.lookalike_candidates = [
        PlatformImpersonation(platform="g", count_30d=9, confidence="lookalike")]
    assert compose.exact_count_30d(vm) == 2              # only exact counted


def test_advanced_gold_never_red():
    # a domain missing every advanced/gold control must not colour them red
    vm = _vm(caa=False, dnssec=False)
    for c in maturity.absent_controls(vm):
        if c.tier in ("advanced", "gold"):
            assert c.colour != "bad"


# ---- empty states ----

def test_null_geo_renders_not_determined():
    vm = _vm(isp_country=None, hosting=None, asn=0)
    html = _render(vm)
    assert "not determined" in html


def test_clean_domain_positive_led_no_awkward_empty():
    vm = _vm(dmarc="reject", spf="v=spf1 -all", caa=True, dnssec=True, imps=[], subs=[],
             mailbox="Microsoft 365", hosting="Akamai", asn=202466, isp_country="GB")
    html = _render(vm)
    assert html.count('class="page') == 5
    # a clean domain has no Now/Soon exploitable fixes (only Maturity opportunities)
    fx = compose.fixes(vm, NOW)
    assert all(f["priority"] == "plan" for f in fx)
    # positive-led: no genuine weaknesses surfaced
    assert compose._weaknesses(vm) == []


# ---- fixes / right-sizing ----

def test_rfc1918_leak_is_top_now_fix():
    vm = _vm(subs=[{"dns_name": "api.example.com", "a_records": ["10.28.1.1"],
                    "risk_level": "review", "note": "private RFC1918"}])
    fx = compose.fixes(vm, NOW)
    assert fx[0]["priority"] == "now" and "internal endpoints" in fx[0]["title"].lower()


def test_caa_is_soon_not_leak_severity():
    vm = _vm(caa=False)
    fx = {f["title"]: f for f in compose.fixes(vm, NOW)}
    caa = next(f for t, f in fx.items() if "CAA" in t)
    assert caa["priority"] == "soon"


def test_no_absolute_risk_claims_in_generated_copy():
    # guard: generated compose strings avoid absolute claims (rhetorical primer
    # copy in the static template is out of scope for this check)
    vm = _vm()
    blob = " ".join([
        compose.synthesis(vm, NOW), compose.insurer_lens(vm, NOW),
        compose.observed_event_line(vm),
        *[f["why"] for f in compose.fixes(vm, NOW)],
    ])
    assert not re.search(r"\b(guaranteed|the only|any CA)\b", blob, re.I)


def _run_all():
    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
