"""
estatereport — the Cross-Estate Domain Risk Report (v2.2, paid tier).

A design-continuous 6-page (+ Appendix A) renderer that fulfils the free
report's page-5 seam: estate discovery (four confidence tiers) and systemic risk.
It is a TRANSFORMATION over the committed `crossestate` analytics MVP — it reuses
that engine's manifest loader, segment resolver and deterministic analytics
unchanged, and adds the v2.2 layers: the §4a resilience-weighted concentration
severity model, discovery tiers, exception collapse, and the remediation
worksheet. The design system (tokens, .page/.runner/.foot, tiers, seam, CTA) is
shared verbatim with `freereport`.

Nothing in `crossestate/` or `freereport/` is mutated.
"""

from __future__ import annotations

__all__ = ["build_estate_report", "EstateReport"]


def __getattr__(name):
    if name == "build_estate_report":
        from estatereport.build import build_estate_report
        return build_estate_report
    if name == "EstateReport":
        from estatereport.contract import EstateReport
        return EstateReport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
