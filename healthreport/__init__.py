"""
Datazag Health Report (v8)
==========================
Flagship Trust + Threat Surface report engine. One engine renders every
audience variant (flagship / insurer / advisory / remediation / external_threat)
at either tier (teaser / full).

`HealthReportRenderer` is imported lazily (PEP 562): `intelligence_contract`
imports `healthreport.grade`, and the renderer imports `intelligence_contract`,
so an eager renderer import here would create a cycle — and would also drag
jinja2 into every consumer that only wants the grade model.
"""

from .grade import score_to_grade, TrustGrade  # noqa: F401


def __getattr__(name):
    if name == "HealthReportRenderer":
        from .renderer import HealthReportRenderer
        return HealthReportRenderer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
