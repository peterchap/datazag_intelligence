"""
crossestate — the Datazag cross-estate / portfolio report.

An *aggregation layer* over the per-domain `ReportViewModel`
(intelligence_contract.py). It consumes N per-domain contracts and computes the
findings that only exist at N>1 — concentration, correlated weakness, posture
variance, active-exposure rollup, and the operational calendar — then renders an
exception-first "summary-of-summaries" document.

Governing principle: aggregation, not concatenation. Lead with the aggregate and
the exceptions; demote per-domain detail to a drill-down appendix. Findings are
rule-based, never LLM-invented (same discipline as the single report).

The per-domain layer is unchanged; this package only reads `ReportViewModel`.
"""

from __future__ import annotations

__all__ = ["build_estate_view_model", "EstateViewModel"]


def __getattr__(name):  # lazy re-export so importing the package is cheap
    if name == "build_estate_view_model":
        from crossestate.build import build_estate_view_model
        return build_estate_view_model
    if name == "EstateViewModel":
        from crossestate.contract import EstateViewModel
        return EstateViewModel
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
