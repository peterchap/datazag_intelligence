"""
crossestate/cuts.py
-------------------
The audience "cut" for the HUMAN render — the analogue of
`healthreport/audiences.py:AudienceConfig`. One engine, one data model; the cut
only parameterises the human document. JSON is ALWAYS the complete
`EstateViewModel` regardless of cut.

The real variable is who holds the document and what they can do with it:

  * operator  — the team that OPERATES the estate (enterprise security team,
    MSSP remediating on a client's behalf). Leads with the triaged exception
    register; shows per-domain fixes as drill-down.
  * oversight — insurer / MGA / PE-VC / board. Leads with concentration ·
    variance · exposure. SUPPRESSES per-domain fix instructions (a per-domain
    remediation list in an underwriting file is a liability artefact) and shows
    remediation only as a fixable-weakness ROLLUP ("62% of the estate shares
    this fixable weakness" — a portfolio finding, not an instruction).

`show_per_domain_fixes` is the single switch the renderer reads; everything else
is section ordering. Redistribution (an MSSP holding oversight for itself and
exporting operator for its client) is just two render calls over one estate.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Canonical section order (spec §3). The cut selects/orders a subset.
SECTION_ORDER: tuple[str, ...] = (
    "cover",           # executive aggregate: size, grade distribution, RED domains, top risks, exposure
    "completeness",    # §2.1 discovery delta (stubbed)
    "concentration",   # §2.2
    "correlated",      # §2.3
    "variance",        # §2.4
    "exposure",        # §2.5
    "calendar",        # §2.6
    "exceptions",      # the prioritised "do this" register
    "appendix",        # per-domain drill-down (operator) / fixable-weakness rollup (oversight)
)


@dataclass(frozen=True)
class CutConfig:
    key: str
    title: str                        # masthead label
    description: str
    sections: tuple[str, ...]         # enabled sections, in render order
    show_per_domain_fixes: bool       # per-domain remediation in the human render


CUTS: dict[str, CutConfig] = {
    "operator": CutConfig(
        key="operator",
        title="Cross-Estate Report — Operator Edition",
        description="For the team that operates the estate. Leads with the "
                    "triaged exception register; per-domain fixes as drill-down.",
        sections=("cover", "exceptions", "calendar", "concentration", "correlated",
                  "variance", "exposure", "completeness", "appendix"),
        show_per_domain_fixes=True,
    ),
    "oversight": CutConfig(
        key="oversight",
        title="Cross-Estate Report — Oversight Edition",
        description="For insurer / MGA / PE-VC / board. Leads with concentration, "
                    "variance and accumulation; per-domain fix instructions suppressed.",
        sections=("cover", "concentration", "variance", "exposure", "correlated",
                  "calendar", "completeness", "exceptions", "appendix"),
        show_per_domain_fixes=False,
    ),
}

CUT_KEYS: tuple[str, ...] = tuple(CUTS.keys())


def get_cut(key: str) -> CutConfig:
    try:
        return CUTS[key]
    except KeyError:
        raise ValueError(f"Unknown cut {key!r}; expected one of {sorted(CUTS)}") from None
