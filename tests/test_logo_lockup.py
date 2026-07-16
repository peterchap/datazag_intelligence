"""WU21 logo amendment guards (two-tone wordmark, option 2a)."""
from __future__ import annotations

import re

from estatereport.renderer import ESTATE_TEMPLATE
from freereport.renderer import FREE_REPORT_TEMPLATE
from scopeteaser.renderer import _CSS as TEASER_CSS, render_teaser_html
from scopeteaser.compose import build_teaser

LOCKUP = '<span class="dz-logo"><span class="dz-logo-data">Data</span><span class="dz-logo-zag">zag</span></span>'

# Reference-mock colours rejected by the reconciliations — must never ship.
BANNED_HEXES = ("#0B1120", "#14273F", "#4AA0FF", "#2563EB", "#2F9DFF")


def _teaser_html():
    vm = build_teaser({"strong": []}, declared_count=1, requested_by="x@y.com")
    return render_teaser_html(vm, "https://x")


def test_lockup_markup_in_all_surfaces():
    assert LOCKUP in FREE_REPORT_TEMPLATE
    assert LOCKUP in ESTATE_TEMPLATE
    assert LOCKUP in _teaser_html()
    # The old flat-cyan back half is gone.
    for t in (FREE_REPORT_TEMPLATE, ESTATE_TEMPLATE):
        assert "DATA<span>ZAG</span>" not in t


def test_dark_and_light_variants_in_report_templates():
    for t in (FREE_REPORT_TEMPLATE, ESTATE_TEMPLATE):
        assert ".dz-logo-data{color:var(--logo-data-on-light)}" in t
        assert ".cover .dz-logo-data{color:var(--logo-data-on-dark)}" in t
        assert "var(--logo-zag-light-from)" in t and "var(--logo-zag-from)" in t
    # Teaser is a light surface: light variant only.
    assert "var(--logo-zag-light-from)" in TEASER_CSS


def test_manrope_contained_to_logo_lockup():
    """Manrope is the logotype face ONLY — the literal appears in the webfont
    link and the --logo-font token; every CSS use goes through var(--logo-font)
    inside .dz-logo."""
    for t in (FREE_REPORT_TEMPLATE, ESTATE_TEMPLATE, _teaser_html()):
        for occurrence in re.finditer(r"[^\n]*Manrope[^\n]*", t):
            line = occurrence.group(0)
            assert "fonts.googleapis.com" in line or "--logo-font" in line, line
        assert ".dz-logo{font-family:var(--logo-font)" in t


def test_no_reference_mock_colours():
    for t in (FREE_REPORT_TEMPLATE, ESTATE_TEMPLATE, TEASER_CSS):
        for hexcode in BANNED_HEXES:
            assert hexcode.lower() not in t.lower()
