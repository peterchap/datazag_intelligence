"""
report_pipeline.py
------------------
The post-split orchestration: turn a domain (+ optional live DNS scan) or a
medallion payload into rendered Trust + Threat Surface reports.

Data flow (see plan dynamic-watching-sparrow.md):

    dnsproject live scan (optional, ~1s on the dnsproject server)
        → `output` dict (email_auth, technographics, txt_intelligence,
          subdomains, rdap, cert_analysis, dns_records) — renderer enrichment
          + the detected platform stack
        → synthesize the small `live_dns_report` the riskscore endpoint merges
    riskscore HTTP endpoint
        POST /intelligence/{domain}  (live_dns_report)  → medallion DomainIntelligence
        GET  /platform-impersonations(platforms, brand) → ExternalThreat
        → derive_findings + build_view_models → ReportViewModel
        → HealthReportRenderer(vm, audience, tier, legacy=output) → html / md

The in-process medallion that dnsproject's compile_intelligence still computes
is IGNORED here — post-split it reads riskscore's local DB, which doesn't exist
on the dnsproject host. The medallion comes over HTTP instead.

The dnsproject import is lazy (only on --live) so this module unit-tests
without dnsproject present, against a mock client + fixtures.
"""

from __future__ import annotations

from typing import Any, Optional

from intelligence_client import IntelligenceClient, IntelligenceUnavailable
from intelligence_contract import (
    DomainIntelligence,
    ExternalThreat,
    ReportViewModel,
    build_view_models,
)
from findings_rules import derive_findings

# Audiences/tiers live with the engine so there is one source of truth.
from healthreport.audiences import AUDIENCES, TIERS
from healthreport.renderer import HealthReportRenderer


# ---------------------------------------------------------------------------
# Deriving the endpoint inputs from a dnsproject live-scan `output` dict
# ---------------------------------------------------------------------------

def synth_live_dns_report(output: dict) -> dict:
    """Build the minimal `live_dns_report` the riskscore merge reads
    (domain_intelligence_api.py:252-265) from dnsproject's `output` dict.

    The endpoint only consumes email_security.{inferred_mbp,dmarc_enforced,
    spf_strict} and dns_profile.records.A.raw + security_heuristics.lowest_ttl —
    so we synthesise exactly those from the live scan rather than reshaping the
    whole report.
    """
    ea = output.get("email_auth") or {}
    tech = output.get("technographics") or {}
    dns = output.get("dns_records") or {}
    labels = output.get("labels") or {}

    dmarc_policy = (ea.get("dmarc_policy") or "").lower()
    spf_raw = (ea.get("spf_raw") or "").lower()
    spf_strictness = (ea.get("spf_strictness") or ea.get("spf") or "").lower()
    spf_strict = ("-all" in spf_raw) or spf_strictness in ("strict", "-all", "hardfail")

    lowest_ttl = (labels.get("lowest_ttl") or output.get("lowest_ttl")
                  or (output.get("dns_profile", {}).get("security_heuristics", {}) or {}).get("lowest_ttl")
                  or 0)

    return {
        "email_security": {
            "inferred_mbp": tech.get("mx_provider_name") or tech.get("mx_mbp_category") or "unknown",
            # p=quarantine and p=reject both count as enforced; p=none is monitor-only.
            "dmarc_enforced": dmarc_policy in ("reject", "quarantine"),
            "spf_strict": bool(spf_strict),
        },
        "dns_profile": {
            "records": {"A": {"raw": list(dns.get("a") or [])}},
            "security_heuristics": {"lowest_ttl": int(lowest_ttl or 0)},
        },
    }


def detect_platforms(output: dict) -> list[str]:
    """The detected platform stack for the impersonation query, from the live
    scan's txt_intelligence + provider annotations. De-duplicated, order-stable."""
    ti = output.get("txt_intelligence") or {}
    tech = output.get("technographics") or {}

    names: list[str] = list(ti.get("all_identified") or [])
    if not names:
        for cat in ("identity_providers", "saas_platforms", "payment_processors",
                    "ai_infrastructure", "security_tooling", "email_marketing"):
            names.extend(ti.get(cat) or [])
    for key in ("mx_provider_name", "ns_provider_name"):
        v = tech.get(key)
        if v:
            names.append(v)

    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        k = (n or "").strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(n)
    return out


def fallback_asn_ip(output: dict) -> tuple[Optional[int], Optional[str]]:
    """Best-effort ASN + primary IP from the live scan, for the endpoint's
    fallback path when the domain isn't in the snapshot."""
    tech = output.get("technographics") or {}
    asn_raw = tech.get("asn")
    try:
        asn = int(asn_raw) if asn_raw not in (None, "", "—") else None
    except (TypeError, ValueError):
        asn = None
    a_records = (output.get("dns_records") or {}).get("a") or []
    ip = a_records[0] if a_records else None
    return asn, ip


# ---------------------------------------------------------------------------
# View-model assembly
# ---------------------------------------------------------------------------

async def build_view_model(
    domain: str,
    client: IntelligenceClient,
    *,
    live_output: Optional[dict] = None,
    profile: Optional[str] = None,
) -> ReportViewModel:
    """Fetch the medallion (POST with the live scan when present, else snapshot
    GET) + impersonations, then compose the view-model.

    Raises IntelligenceUnavailable if the medallion endpoint is unreachable —
    the caller decides whether to fall back to a cached payload or abort. A 404
    (domain not in corpus) is NOT an error: it yields a 'not yet assessed'
    view-model.
    """
    live_dns_report = synth_live_dns_report(live_output) if live_output else None
    fb_asn, fb_ip = fallback_asn_ip(live_output) if live_output else (None, None)

    di = await client.fetch(
        domain, fallback_asn=fb_asn, fallback_ip=fb_ip,
        profile=profile, live_dns_report=live_dns_report,
    )

    platforms = detect_platforms(live_output) if live_output else []
    # Impersonations are supplementary; the client already swallows transport
    # errors and returns an empty ExternalThreat.
    ext: ExternalThreat = await client.fetch_platform_impersonations(platforms, brand=domain)
    if not ext.detected_platforms:
        ext.detected_platforms = platforms

    findings = derive_findings(di, ext.impersonations)

    return build_view_models(
        di,
        detected_platforms=ext.detected_platforms,
        impersonations=ext.impersonations,
        own_brand=ext.own_brand,
        findings=findings,
        lookalike_candidates=ext.lookalike_candidates,
        own_brand_lookalikes=ext.own_brand_lookalikes,
    )


def view_model_from_medallion(payload: dict) -> ReportViewModel:
    """Build a view-model directly from a medallion JSON payload (the
    --input_json path) — no live scan, no impersonations."""
    di = DomainIntelligence.model_validate(payload)
    findings = derive_findings(di, [])
    return build_view_models(di, findings=findings)


def view_model_from_legacy_output(output: dict) -> ReportViewModel:
    """Build a view-model from a legacy compiled `output` dict — the medallion
    rides along under `infrastructure_intelligence` (compile_intelligence passes
    it through). When that's medallion-shaped, parse it; otherwise return a
    'not yet assessed' view-model (never a false all-clear)."""
    infra = output.get("infrastructure_intelligence") or {}
    if isinstance(infra, dict) and "risk_assessment" in infra:
        di = DomainIntelligence.model_validate(
            {**infra, "domain": infra.get("domain") or output.get("domain", "")})
        findings = derive_findings(di, [])
    else:
        di = DomainIntelligence(domain=output.get("domain", ""), error="no_medallion", code=404)
        findings = []
    return build_view_models(di, findings=findings)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_variants(
    vm: ReportViewModel,
    *,
    audiences: list[str],
    tier: str = "full",
    formats: tuple[str, ...] = ("html", "markdown"),
    legacy: Optional[dict] = None,
    brand: Any = None,
) -> dict[str, dict[str, str]]:
    """Render the requested audience variants × formats from one view-model.
    Returns {audience: {format: content}}. Pure (no I/O) — PDF is generated by
    the caller from the HTML."""
    if tier not in TIERS:
        raise ValueError(f"Unknown tier {tier!r}; expected one of {TIERS}")

    out: dict[str, dict[str, str]] = {}
    for aud in audiences:
        renderer = HealthReportRenderer(vm, audience=aud, tier=tier, legacy=legacy)
        formatted: dict[str, str] = {}
        for fmt in formats:
            if fmt == "html":
                formatted["html"] = renderer.to_html(brand=brand)
            elif fmt == "markdown":
                formatted["markdown"] = renderer.to_markdown(brand=brand)
            else:
                raise ValueError(f"Unsupported format {fmt!r} (html, markdown only; pdf is derived)")
        out[aud] = formatted
    return out


def is_medallion_payload(obj: dict) -> bool:
    """True when a loaded --input_json dict is a riskscore medallion payload
    (vs a legacy compiled `output` dict)."""
    return isinstance(obj, dict) and "risk_assessment" in obj and "schema_version" in obj


DEFAULT_AUDIENCES = ["flagship", "insurer", "advisory", "remediation", "external_threat"]
assert all(a in AUDIENCES for a in DEFAULT_AUDIENCES)
