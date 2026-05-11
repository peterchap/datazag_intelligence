"""
healthreport/grade.py
---------------------
Numeric composite score → letter Trust Grade for the v8 Health Report.

The composite_score produced by `scorer.DatazagCompositeScorer` is 0-100 where
HIGHER = MORE EXPOSURE. We map that into a six-band A–F grade.

Calibration notes
-----------------
- The thresholds below are the v1 calibration. Adjust based on real distribution
  once we have more reports generated.
- A grade of A is intentionally rare — we want it to mean 'genuinely well-defended',
  not 'defaults to good'.
- C is the modal grade for the SMB target market; most first-assessment customers
  should land here.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class TrustGrade:
    letter: str           # 'A' through 'F'
    headline: str         # short interpretation, e.g. 'Strong posture'
    description: str      # one-sentence sub-line
    scale_position: float # 0.0–1.0 for the horizontal A→F scale on page 3
    arc_fill: float       # 0.0–1.0 for the dial ring on the cover


# Lower = better posture. Bands chosen so:
#  - A  is exceptional; uncommon
#  - B  is well-defended
#  - C  is acceptable / addressable in 90 days  ← v8 mockup default
#  - D  is meaningfully exposed
#  - E  is high exposure
#  - F  is critical
_BANDS = [
    (15, TrustGrade("A", "Strong posture",
                    "Exposure addressable through ongoing maintenance.",
                    0.08, 0.92)),
    (30, TrustGrade("B", "Solid posture",
                    "Addressable in a quarter through routine improvements.",
                    0.25, 0.75)),
    (50, TrustGrade("C", "Moderate exposure",
                    "Addressable in 90 days.",
                    0.42, 0.60)),
    (70, TrustGrade("D", "Meaningful exposure",
                    "Several material gaps; quarter of focused work needed.",
                    0.58, 0.40)),
    (85, TrustGrade("E", "High exposure",
                    "Multiple material risks; immediate prioritisation needed.",
                    0.75, 0.22)),
    (101, TrustGrade("F", "Critical exposure",
                     "Immediate action required across multiple surfaces.",
                     0.92, 0.10)),
]


def score_to_grade(score: int | float | None) -> TrustGrade:
    """Map a 0–100 composite score (higher = worse) to a TrustGrade."""
    if score is None:
        return TrustGrade("?", "Not yet assessed",
                          "First assessment in progress.",
                          0.50, 0.50)
    s = max(0, min(100, int(score)))
    for cutoff, grade in _BANDS:
        if s < cutoff:
            return grade
    return _BANDS[-1][1]  # safety; shouldn't reach
