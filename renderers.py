"""
renderers.py
------------
Four audience renderers that operate on the output dict
produced by run.py — no SubdomainReport dependency.
Works directly from CanonicalDNSRecord + findings + composite score.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

RISK_COLOURS = {
    "critical": {"bg": "#FCEBEB", "text": "#791F1F", "border": "#A32D2D"},
    "high":     {"bg": "#FAEEDA", "text": "#633806", "border": "#854F0B"},
    "medium":   {"bg": "#E6F1FB", "text": "#0C447C", "border": "#185FA5"},
    "info":     {"bg": "#EAF3DE", "text": "#27500A", "border": "#3B6D11"},
}

RISK_BAND_COLOUR = {
    "critical": "#A32D2D",
    "high":     "#854F0B",
    "medium":   "#185FA5",
    "low":      "#3B6D11",
}


def _badge(severity: str) -> str:
    c = RISK_COLOURS.get(severity, RISK_COLOURS["info"])
    return (
        f'<span style="background:{c["bg"]};color:{c["text"]};'
        f'padding:2px 8px;border-radius:4px;font-size:11px;'
        f'font-weight:600;text-transform:uppercase">{severity}</span>'
    )


def _score_bar(score: int, invert: bool = True) -> str:
    """Visual 0–100 bar. invert=True means higher = more red."""
    if invert:
        colour = "#A32D2D" if score >= 75 else "#854F0B" if score >= 40 else "#3B6D11"
    else:
        colour = "#3B6D11" if score >= 75 else "#854F0B" if score >= 40 else "#A32D2D"
    return (
        f'<div style="background:#eee;border-radius:3px;'
        f'height:6px;width:100%;margin:4px 0">'
        f'<div style="background:{colour};width:{score}%;'
        f'height:100%;border-radius:3px"></div></div>'
    )


def _findings_table(
    findings: list[dict],
    columns: list[tuple],
    max_rows: int = 50,
) -> str:
    th = ('style="text-align:left;padding:8px 12px;font-size:11px;'
          'font-weight:600;border-bottom:1px solid #e0e0e0;'
          'color:#666;text-transform:uppercase;letter-spacing:.04em;'
          'white-space:nowrap"')
    td = ('style="padding:7px 12px;font-size:12px;'
          'border-bottom:1px solid #f5f5f5;vertical-align:top"')

    headers = "".join(f"<th {th}>{label}</th>" for label, _ in columns)
    rows = ""
    for i, f in enumerate(findings[:max_rows]):