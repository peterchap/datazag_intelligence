"""
healthreport/audiences.py
-------------------------
Per-variant configuration for the flagship report engine.

One engine renders every variant; an AudienceConfig selects which report
sections are included, what the product is called on the masthead, and which
LLM-narrative keys (from narrative.py) the variant favours.

Section keys map 1:1 to pages in HEALTH_REPORT_TEMPLATE, in canonical order:

    cover               Page 1  — dual-pillar cover + overall grade
    toc                 Page 2  — table of contents (filtered to enabled sections)
    glance              Page 3  — at a glance: grade band, scorecards, priorities
    external_summary    Page 4  — external threat: stack, impersonation, brand
    controls            Page 5  — defensive controls audit (trust surface detail)
    infra_routing       Page 6  — IP / prefix / ASN quality (routing + reputation)
    hidden_infra        Page 7  — registration + subdomain estate
    timeline            Page 8  — change signals
    roadmap             Page 9  — remediation roadmap (fortnight/quarter/year)
    remediation_plan    Page 10 — IT remediation tear-off (detailed per-fix steps)
    glossary            Page 11 — glossary

The external surface was four pages (why / vendor_footprint / platform_exposure /
brand_exposure). Three of them argued the general case for platform impersonation
and carried no domain-specific action, so they read near-identically across most
domains. They are now one page built from this domain's own observations.
"""

from __future__ import annotations

from dataclasses import dataclass


SECTION_ORDER: tuple[str, ...] = (
    "cover", "toc", "glance", "external_summary", "controls", "dns_records",
    "infra_routing", "hidden_infra", "timeline", "roadmap", "remediation_plan",
    "glossary",
)

# Sections outside the canonical flagship page order:
#   brand_funnel      — the FREE health report's active-scan brand page
#                       (brand_page_data_contract.md)
EXTRA_SECTIONS: tuple[str, ...] = ("brand_funnel",)

TIERS: tuple[str, ...] = ("teaser", "full")


@dataclass(frozen=True)
class AudienceConfig:
    key: str
    title: str                      # masthead product label, e.g. "Health Report"
    description: str                # what this variant is for (internal)
    sections: tuple[str, ...]       # enabled section keys, canonical order
    narrative_keys: tuple[str, ...] # narrative.py fields this variant favours


AUDIENCES: dict[str, AudienceConfig] = {
    # The flagship Trust + Threat Surface report — everything.
    "flagship": AudienceConfig(
        key="flagship",
        title="Health Report",
        description="Executive Trust + Threat Surface report; the full product.",
        sections=SECTION_ORDER,
        narrative_keys=("key_finding", "executive_summary", "threat_narrative",
                        "positive_signals", "remediation_priority"),
    ),
    # Underwriting / due-diligence framing. Skips the IT remediation detail.
    "insurer": AudienceConfig(
        key="insurer",
        title="Cyber Risk Report",
        description="Underwriting / premium-loading view for insurers and "
                    "due-diligence providers.",
        sections=("cover", "toc", "glance", "external_summary", "controls",
                  "dns_records", "infra_routing", "timeline", "glossary"),
        narrative_keys=("key_finding", "executive_summary", "insurer_signals",
                        "threat_narrative"),
    ),
    # Consultant + Sales merged: technical findings + commercial talking points.
    "advisory": AudienceConfig(
        key="advisory",
        title="Advisory Report",
        description="Merged consultant/sales view: technical findings plus "
                    "commercial talking points for prospect conversations.",
        sections=("cover", "toc", "glance", "external_summary", "controls",
                  "dns_records", "infra_routing", "hidden_infra", "roadmap",
                  "remediation_plan", "glossary"),
        narrative_keys=("key_finding", "executive_summary", "threat_narrative",
                        "saas_stack_analysis", "positive_signals"),
    ),
    # IT remediation queue + economic-buyer framing (less technical).
    "remediation": AudienceConfig(
        key="remediation",
        title="Remediation Plan",
        description="IT remediation queue plus an economic-buyer section in "
                    "cost / business-impact language.",
        sections=("cover", "glance", "controls", "dns_records", "infra_routing",
                  "hidden_infra", "timeline", "roadmap", "remediation_plan", "glossary"),
        narrative_keys=("key_finding", "remediation_priority",
                        "executive_summary"),
    ),
    # FREE Health Report — the lead-gen artefact (always rendered at --tier
    # teaser). Slim: headline grade + trust posture + the active-scan BRAND
    # funnel (generated + cheaply checked at report time) with the paid Brand
    # Impersonation Watch as the upsell. See brand_page_data_contract.md.
    "health": AudienceConfig(
        key="health",
        title="Health Report",
        description="Free lead-gen health report: headline grade + trust posture "
                    "+ the active-scan brand funnel and paid-Watch upsell.",
        # No external page here: this tier suppresses platform-global counts
        # (brand_page_data_contract.md), which the external page reports directly.
        # Its brand story is brand_funnel. The old "why" context page went with the
        # four-page external arc.
        sections=("cover", "glance", "brand_funnel", "controls", "glossary"),
        narrative_keys=("key_finding", "executive_summary", "threat_narrative"),
    ),
    # Standalone External Threat / platform-impersonation deep-dive — kept
    # short and factual (1–2 pages): one dense summary page, not the full deck.
    "external_threat": AudienceConfig(
        key="external_threat",
        title="External Threat Report",
        description="Standalone platform-impersonation report: detected stack "
                    "(strongest signal first) x 7/30-day impersonation activity "
                    "+ own-brand lookalikes, on a single factual page.",
        sections=("external_summary",),
        narrative_keys=("key_finding", "threat_narrative"),
    ),
}


def get_audience(key: str) -> AudienceConfig:
    try:
        return AUDIENCES[key]
    except KeyError:
        raise ValueError(
            f"Unknown audience {key!r}; expected one of {sorted(AUDIENCES)}"
        ) from None
