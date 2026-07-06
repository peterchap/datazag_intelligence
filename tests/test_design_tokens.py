"""WU21 design-token guards.

- Drift guard: generated files must match a fresh run of the generator.
- Token parity: the report templates must expose exactly the same custom
  properties (name -> value) as before the :root extraction, so renders stay
  pixel-identical.
"""
from __future__ import annotations

import re

from design import generate_tokens
from design.generated.tokens import COLORS, CSS_ROOT, GRADE, SEVERITY, TIER

_VAR_RE = re.compile(r"--([\w-]+)\s*:\s*([^;}]+)[;}]")


def _css_vars(css: str) -> dict[str, str]:
    return {name: value.strip() for name, value in _VAR_RE.findall(css)}


# The exact custom-property map both report templates carried before the WU21
# extraction (freereport/renderer.py and estatereport/renderer.py at 30d224a).
GOLDEN_REPORT_VARS = {
    "navy": "#0F1923", "navy-2": "#16263A", "navy-deep": "#0A121C",
    "ink": "#0F172A", "ink-2": "#33415A", "ink-3": "#64748B", "ink-4": "#94A3B8",
    "paper": "#FFFFFF", "tint": "#F6F8FB", "tint-2": "#EEF3F8",
    "rule": "#E2E8F0", "rule-2": "#F0F4F8",
    "cyan": "#00C2FF", "cyan-deep": "#0091C7", "cyan-wash": "#E8F8FF",
    "good": "#0E9F6E", "good-wash": "#E7F7F0", "good-line": "#A8E6CC",
    "warn": "#D97706", "warn-wash": "#FEF4E6", "warn-line": "#F6D9A8",
    "bad": "#E02424", "bad-wash": "#FDECEC", "bad-line": "#F5C6C6",
    "w": "#FFFFFF", "w2": "rgba(255,255,255,.82)", "w3": "rgba(255,255,255,.58)",
    "w4": "rgba(255,255,255,.34)", "rd": "rgba(255,255,255,.12)",
}


def test_generated_files_are_current():
    outputs = generate_tokens.build()
    for name, content in outputs.items():
        on_disk = (generate_tokens.GENERATED_DIR / name).read_text(encoding="utf-8")
        assert on_disk == content, (
            f"{name} is stale or was hand-edited; run python design/generate_tokens.py"
        )


def test_css_root_matches_tokens_json():
    assert _css_vars(CSS_ROOT) == COLORS


def test_free_report_template_token_parity():
    from freereport.renderer import FREE_REPORT_TEMPLATE

    head = FREE_REPORT_TEMPLATE.split("*{margin:0", 1)[0]
    assert _css_vars(head) == GOLDEN_REPORT_VARS


def test_estate_template_token_parity():
    from estatereport.renderer import ESTATE_TEMPLATE

    head = ESTATE_TEMPLATE.split("*{margin:0", 1)[0]
    assert _css_vars(head) == GOLDEN_REPORT_VARS


def test_semantic_maps_resolve_to_palette():
    assert SEVERITY == {"high": COLORS["bad"], "elevated": COLORS["warn"], "watch": COLORS["cyan-deep"]}
    assert TIER == {
        "declared": COLORS["ink-3"], "strong": COLORS["good"],
        "possible": COLORS["warn"], "defensive": COLORS["cyan-deep"],
    }
    # Literal (non-reference) grade stops pass through untouched.
    assert GRADE["A"] == COLORS["good"] and GRADE["B"] == "#5BBF8F" and GRADE["F"] == "#8B1414"
