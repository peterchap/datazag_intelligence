"""
Cross-Estate v2.2 report tests — the §4a resilience model, exception collapse,
remediation worksheet, discovery structure, and render. Standalone runner.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from estatereport import resilience  # noqa: E402
from estatereport.build import build_estate_report_from_manifest  # noqa: E402
from estatereport.renderer import EstateReportRenderer  # noqa: E402

MANIFEST = os.path.join(_ROOT, "tests", "fixtures", "estate", "manifest.json")
NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)


def _report():
    return build_estate_report_from_manifest(MANIFEST, now=NOW)


# ── §4a resilience severity matrix ──────────────────────────────────────────

def test_worked_contrast_biggest_bar_is_not_biggest_finding():
    # The spec's headline example: 75% Let's Encrypt (hyperscale CA) < 62% GoDaddy
    # (commodity registrar, high exit) in severity.
    le = resilience.lookup("Let's Encrypt", "ca_issuer")
    gd = resilience.lookup("GoDaddy", "registrar")
    le_sev, _ = resilience.severity(0.75, le)
    gd_sev, _ = resilience.severity(0.62, gd)
    assert le_sev == "watch"
    assert gd_sev == "high"
    assert resilience._SEV_RANK[gd_sev] > resilience._SEV_RANK[le_sev]


def test_share_ge_50_always_produces_a_finding():
    # even a hyperscale provider at >=50% registers (as WATCH) — auditability.
    hs = resilience.lookup("Cloudflare", "ns")
    sev, _ = resilience.severity(0.55, hs)
    assert sev == "watch"


def test_exit_friction_high_bumps_severity_at_50():
    gd = resilience.lookup("GoDaddy", "registrar")     # commodity, high exit → high (bumped from elevated)
    assert gd.exit_friction == "high"
    sev, _ = resilience.severity(0.50, gd)
    assert sev == "high"


def test_below_35_no_finding_except_fragile():
    hs = resilience.lookup("Cloudflare", "ns")
    assert resilience.severity(0.30, hs)[0] is None


def test_unknown_provider_is_commodity_not_assessed():
    r = resilience.lookup("SomeUnknownRegistrarLtd", "registrar")
    assert r.tier == "commodity" and r.assessed is False


# ── exception collapse (§3.3) ───────────────────────────────────────────────

def test_exceptions_collapsed_5_to_7_and_ranked():
    ex = _report().exceptions
    assert 3 <= len(ex) <= 7
    ranks = [e.rank for e in ex]
    assert ranks == sorted(ranks) and ranks[0] == 1
    order = {"high": 0, "elevated": 1, "watch": 2}
    sevs = [order[e.severity] for e in ex]
    assert sevs == sorted(sevs)


def test_correlated_and_concentration_collapse_into_single_entries():
    ex = _report().exceptions
    corr = [e for e in ex if e.collapsed_from and e.collapsed_from.startswith("correlated_weakness")]
    conc = [e for e in ex if e.collapsed_from and e.collapsed_from.startswith("concentration")]
    assert len(corr) == 1                     # six weaknesses -> ONE entry
    assert len(conc) <= 1


def test_recovery_leads_when_overdue_present():
    ex = _report().exceptions
    assert ex[0].severity == "high"
    assert "recover" in ex[0].title.lower()   # takeover windows precede hygiene


# ── remediation worksheet (§2b) ─────────────────────────────────────────────

def test_recovery_is_first_pattern_and_dedup_on_pattern_id():
    r = _report()
    assert r.remediation[0].pattern_id == "recovery"
    ids = [p.pattern_id for p in r.remediation]
    assert len(ids) == len(set(ids))          # dedup on pattern_id


def test_priorities_follow_maturity_tiers_not_v8_ranking():
    pats = {p.pattern_id: p for p in _report().remediation}
    assert pats["dmarc"].priority == "now"    # baseline
    assert pats["caa"].priority == "soon"     # advanced
    assert pats["dnssec"].priority == "plan"  # gold (Maturity) — NOT "now"


def test_worksheet_rows_ordered_by_admin_point():
    for p in _report().remediation:
        keys = [(e.admin_point, e.domain) for e in p.entries]
        assert keys == sorted(keys)


def test_now_strings_are_formatted_not_raw_field_names():
    for p in _report().remediation:
        for e in p.entries:
            assert "_" not in e.now or e.now in ("p=none (monitor only)",)  # no raw field tokens
            assert "certstream_hits" not in e.now


# ── discovery structure (§3.1) ──────────────────────────────────────────────

def test_four_tier_structure_renders_even_when_disabled():
    d = _report().discovery
    assert d.enabled is False
    for t in ("declared", "strong", "possible", "defensive"):
        assert t in d.tiers
    assert d.declared_count == 9 and d.tier_count("declared") == 9
    assert "not enabled" in d.note.lower()


# ── render ──────────────────────────────────────────────────────────────────

def test_render_six_core_plus_appendix_pages_and_verbatim_tokens():
    r = _report()
    html = EstateReportRenderer(r).to_html()
    assert html.count('class="page') == 6 + r.appendix_pages
    assert "--cyan:#00C2FF" in html                        # shared design token verbatim
    assert "CROSS-ESTATE DOMAIN RISK REPORT" in html        # cover runner id
    assert "340M-domain corpus" in html                     # single sourced corpus constant
    assert "resolved through vanity MX" in html             # vanity-MX methodology sentence


def test_severity_pill_carries_colour_not_the_bar():
    # concentration bars stay neutral (no hot/warm class); the severity pill colours.
    html = EstateReportRenderer(_report()).to_html()
    assert 'class="cfill"' in html                          # neutral bar
    assert 'class="ex-sev high"' in html                    # severity pill present


def _run_all():
    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
