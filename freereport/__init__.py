"""
freereport — the Free Single-Domain Cyber Exposure Report.

A 5-page lead-magnet renderer that reads the per-domain `ReportViewModel`
(intelligence_contract.py) and reproduces the approved prototype
`free_report_v1_3.html` in the shared Datazag design system.

Golden rule (from the flagship handover): render from the CONTRACT (`vm.*`),
never a legacy dict. House style: describe the mechanism, hedge the universal;
empty/unknown data renders as an explicit honest state, never a blank; only
BASELINE email-control gaps are negatives — advanced/gold render as
opportunities, never red.

Standalone by design (fresh build alongside the healthreport engine and the
crossestate MVP); it only reads `ReportViewModel`.
"""

from __future__ import annotations

__all__ = ["FreeReportRenderer", "compose_context"]


def __getattr__(name):
    if name == "FreeReportRenderer":
        from freereport.renderer import FreeReportRenderer
        return FreeReportRenderer
    if name == "compose_context":
        from freereport.compose import compose_context
        return compose_context
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
