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
    why                 Page 4  — why platform impersonation matters (context)
    vendor_footprint    Page 5  — detected platform stack by attacker desirability
    platform_exposure   Page 6  — active impersonation campaigns (7/30-day counts)
    brand_exposure      Page 7  — own-brand lookalike exposure
    controls            Page 8  — defensive controls audit (trust surface detail)
    hidden_infra        Page 9  — registration + subdomain estate
    timeline            Page 10 — change signals
    roadmap             Page 11 — remediation roadmap (fortnight/quarter/year)
    glossary            Page 12 — glossary
"""

from __future__ import annotations

from dataclasses import dataclass


SECTION_ORDER: tuple[str, ...] = (
    "cover", "toc", "glance", "why", "vendor_footprint", "platform_exposure",
    "brand_exposure", "controls", "hidden_infra", "timeline", "roadmap",
    "glossary",
)

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
        sections=("cover", "toc", "glance", "why", "vendor_footprint",
                  "platform_exposure", "brand_exposure", "controls",
                  "timeline", "glossary"),
        narrative_keys=("key_finding", "executive_summary", "insurer_signals",
                        "threat_narrative"),
    ),
    # Consultant + Sales merged: technical findings + commercial talking points.
    "advisory": AudienceConfig(
        key="advisory",
        title="Advisory Report",
        description="Merged consultant/sales view: technical findings plus "
                    "commercial talking points for prospect conversations.",
        sections=("cover", "toc", "glance", "why", "vendor_footprint",
                  "platform_exposure", "brand_exposure", "controls",
                  "hidden_infra", "roadmap", "glossary"),
        narrative_keys=("key_finding", "executive_summary", "threat_narrative",
                        "saas_stack_analysis", "positive_signals"),
    ),
    # IT remediation queue + economic-buyer framing (less technical).
    "remediation": AudienceConfig(
        key="remediation",
        title="Remediation Plan",
        description="IT remediation queue plus an economic-buyer section in "
                    "cost / business-impact language.",
        sections=("cover", "glance", "controls", "hidden_infra", "timeline",
                  "roadmap", "glossary"),
        narrative_keys=("key_finding", "remediation_priority",
                        "executive_summary"),
    ),
    # Standalone External Threat / platform-impersonation deep-dive.
    "external_threat": AudienceConfig(
        key="external_threat",
        title="External Threat Report",
        description="Standalone platform-impersonation deep-dive: detected "
                    "stack x 7/30-day impersonation activity + own-brand "
                    "lookalikes.",
        sections=("cover", "glance", "why", "vendor_footprint",
                  "platform_exposure", "brand_exposure"),
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
