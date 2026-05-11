"""
Datazag Health Report (v8)
==========================
Master Trusted-Platform-Impersonation report.
Runs alongside the existing four-audience pipeline; same data, new design.
"""

from .renderer import HealthReportRenderer  # noqa: F401
from .grade import score_to_grade           # noqa: F401
