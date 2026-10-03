"""
tests/test_estate_data_fixes.py
-------------------------------
Regression tests for the Phase 1 data-correctness fixes (docs/report-editions/PLAN.md
§3). Each test pins one defect seen in the cyber-startups baseline
(fixtures/cyber-startups/estate_report.json) so it cannot come back.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from crossestate.discovery import (  # noqa: E402
    ConnectedDomainDiscoveryProvider,
    is_shared_platform_host,
)
from estatereport.discovery import to_estate_discovery  # noqa: E402
from tests.estate_helpers import make_ref  # noqa: E402


# ── #2 discovery: shared-CDN hosts never become candidates ──────────────────

def _sans(*names):
    return {"cross_domain_sans": [{"dns_name": n} for n in names]}


def test_shared_cdn_sni_hosts_are_not_discovery_candidates():
    refs = [
        make_ref("ossprey.com", "core", cert=_sans("1fd3f647.sni.cloudflaressl.com",
                                                   "ossprey.io")),
        make_ref("mindgard.ai", "core", cert=_sans("34b5f1fb.sni.cloudflaressl.com",
                                                   "d1234.cloudfront.net")),
    ]
    res = ConnectedDomainDiscoveryProvider().discover("g", refs)
    found = {d.domain for d in res.discovered + res.candidates + res.hostile}
    assert found == {"ossprey.io"}
    assert not any("cloudflaressl" in d or "cloudfront" in d for d in found)


def test_shared_platform_match_is_suffix_not_substring():
    assert is_shared_platform_host("abc.sni.cloudflaressl.com")
    assert is_shared_platform_host("cloudflaressl.com")
    assert not is_shared_platform_host("notcloudflaressl.com")
    assert not is_shared_platform_host("ploy.io")


def test_estate_headline_counts_declared_plus_strong_only():
    refs = [make_ref("acme.com", "core", cert=_sans("acme.co.uk", "unrelated-tenant.com"))]
    res = ConnectedDomainDiscoveryProvider().discover("g", refs)
    disc = to_estate_discovery(res, ["acme.com"])
    assert disc.tier_count("strong") == 1          # acme.co.uk: brand corroborated
    assert disc.tier_count("possible") == 1        # co-tenant: held, not counted
    assert disc.estate_count == 2                  # declared + strong
    assert disc.total_found == 3                   # every row, never a headline


# ── #3 DNS snippets carry the real domain ───────────────────────────────────

import re  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

from tests.estate_helpers import ESTATE_MANIFEST, fixture_observatory, no_observatory  # noqa: E402

_NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)

# Shapes the baseline produced once HTML ate the <domain> placeholder.
EMPTY_PLACEHOLDER = re.compile(
    r'_dmarc\.\.|@(?:"|&#34;|&quot;)|^\.\s+IN\s+CAA|(^|\s)\.\s+TXT|\{domain\}', re.M)


def _rendered():
    from estatereport.build import build_estate_report_from_manifest
    from estatereport.renderer import EstateReportRenderer
    rep = build_estate_report_from_manifest(ESTATE_MANIFEST, now=_NOW,
                                            observatory=fixture_observatory())
    r = EstateReportRenderer(rep)
    return rep, r.to_html(), r.to_markdown()


def test_record_lines_substitute_every_entry_domain():
    rep, _, _ = _rendered()
    patterns = [p for p in rep.remediation if p.record_lines]
    assert patterns
    for p in patterns:
        for e in p.entries:
            text = "\n".join(ln.text for ln in p.records_for(e.domain))
            assert "{domain}" not in text
            if any("{domain}" in ln.text for ln in p.record_lines):
                assert e.domain in text, (p.pattern_id, e.domain)


def test_no_empty_placeholders_in_html_or_markdown():
    rep, html, md = _rendered()
    for name, out in (("html", html), ("md", md)):
        hit = EMPTY_PLACEHOLDER.search(out)
        assert not hit, f"{name}: empty placeholder near {out[max(0, hit.start()-40):hit.end()+40]!r}"
    # placeholders that are meant for the reader survive, escaped, in HTML
    caa = next((p for p in rep.remediation if p.pattern_id == "caa"), None)
    if caa:
        assert "&lt;your-ca&gt;" in html
        assert f'{caa.example_domain}.  IN  CAA  0 issue' in html.replace("&#34;", '"')
    # each record sits on its own line (trim_blocks once swallowed the separator)
    assert re.search(r'p=none; rua=mailto:dmarc@[^\n<]+\n<span class="cm">', html)


def test_record_data_carries_no_markup():
    rep, _, _ = _rendered()
    for p in rep.remediation:
        for ln in p.record_lines:
            assert "<span" not in ln.text and "&lt;" not in ln.text


# ── #5 / #6 calendar: one row per host, due populated, lapses = distinct hosts ─

from crossestate.analytics import compute_calendar  # noqa: E402
from crossestate.contract import EstateThresholds  # noqa: E402

TH = EstateThresholds()


def _cert(name, not_after, issuer="digicert"):
    days = (datetime.fromisoformat(not_after).replace(tzinfo=timezone.utc) - _NOW).days
    row = {"dns_name": name, "not_after": not_after, "days_remaining": days,
           "issuer_category": issuer}
    return row


def _ca(*rows, expired=()):
    """Reproduce CertAnalysis: every expiring cert also lands in missed_renewals."""
    return {"expiring_soon": list(rows), "missed_renewals": [dict(r) for r in rows],
            "expired": list(expired)}


def test_expiring_cert_and_its_missed_renewal_twin_are_one_row_with_a_due_date():
    ref = make_ref("mindgard.ai", "s", cert=_ca(_cert("auth.mindgard.ai", "2026-07-20")))
    cal = compute_calendar([ref], TH, now=_NOW)
    rows = [it for it in cal.items if it.kind.startswith("cert")]
    assert len(rows) == 1
    assert rows[0].host == "auth.mindgard.ai"
    assert rows[0].date == "2026-07-20" and rows[0].days_left == 18
    assert rows[0].renewal_window_passed is True


def test_no_host_appears_twice():
    ref = make_ref("sitehop.com", "s", status="ok", expires="2026-07-10",
                   cert=_ca(_cert("sitea.sitehop.com", "2026-07-20"),
                            _cert("siteb.sitehop.com", "2026-07-25")))
    hosts = [(it.kind.startswith("cert"), it.host)
             for it in compute_calendar([ref], TH, now=_NOW).items]
    cert_hosts = [h for is_cert, h in hosts if is_cert]
    assert len(cert_hosts) == len(set(cert_hosts)) == 2
    assert all(it.date for it in compute_calendar([ref], TH, now=_NOW).items
               if it.kind != "unlocked")


def test_auto_renewing_certs_only_flag_close_to_expiry():
    ref = make_ref("ploy.io", "s", cert=_ca(
        _cert("le-20d.ploy.io", "2026-07-22", issuer="letsencrypt"),   # normal ACME renewal window
        _cert("le-5d.ploy.io", "2026-07-07", issuer="letsencrypt"),    # genuinely close
        _cert("dc-20d.ploy.io", "2026-07-22", issuer="digicert"),      # manual issuer
    ))
    hosts = {it.host for it in compute_calendar([ref], TH, now=_NOW).items}
    assert hosts == {"le-5d.ploy.io", "dc-20d.ploy.io"}


def test_live_tls_drops_a_cert_already_renewed_and_keeps_unconfirmed_rows():
    ref = make_ref("huntbase.io", "s", cert=_ca(_cert("a.huntbase.io", "2026-07-20"),
                                                _cert("b.huntbase.io", "2026-07-20")))
    renewed = datetime(2026, 10, 1, tzinfo=timezone.utc)
    probe = lambda hosts: {"a.huntbase.io": renewed, "b.huntbase.io": None}  # noqa: E731
    hosts = {it.host for it in compute_calendar([ref], TH, now=_NOW, tls_probe=probe).items}
    assert hosts == {"b.huntbase.io"}


def test_a_failing_probe_never_sinks_the_calendar():
    def boom(hosts):
        raise OSError("network down")
    ref = make_ref("x.com", "s", cert=_ca(_cert("a.x.com", "2026-07-20")))
    assert len(compute_calendar([ref], TH, now=_NOW, tls_probe=boom).items) == 1


def test_window_counts_are_distinct_hosts():
    # registration AND a cert on the same apex host, plus a second cert host
    ref = make_ref("aisy.ai", "s", expires="2026-07-20",
                   cert=_ca(_cert("aisy.ai", "2026-07-15"), _cert("app.aisy.ai", "2026-07-16")))
    cal = compute_calendar([ref], TH, now=_NOW)
    assert len(cal.items) == 3
    assert cal.next_30d == 2                       # aisy.ai, app.aisy.ai


def test_cover_lapses_kpi_equals_distinct_hosts():
    from crossestate.build import build_estate_view_model
    from crossestate.manifest import ManifestEntry
    from estatereport.build import build_estate_report
    import json
    import tempfile
    refs = [make_ref("aisy.ai", "s", expires="2026-07-20",
                     cert=_ca(_cert("aisy.ai", "2026-07-15"), _cert("app.aisy.ai", "2026-07-16")))]
    with tempfile.TemporaryDirectory() as d:
        entries = []
        for r in refs:
            p = os.path.join(d, f"{r.domain}.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(r.vm.model_dump(mode="json"), fh)
            entries.append(ManifestEntry(domain=r.domain, segment="s", contract_path=p))
        mvp = build_estate_view_model("g", entries, now=_NOW)
    rep = build_estate_report(mvp, now=_NOW, observatory=no_observatory())
    lapses = next(c for c in rep.dash if c["key"] == "Live lapses")
    hosts = {c.host for c in rep.calendar if c.due_class in ("overdue", "soon")}
    assert lapses["state"] == str(len(hosts)) == "2"


# ── #7 every share shows its denominator ────────────────────────────────────

def test_concentration_rows_carry_n_and_N_matching_the_share():
    rep, _, _ = _rendered()
    assert rep.concentration
    for c in rep.concentration:
        assert c.N > 0 and 0 < c.n <= c.N
        assert abs(c.n / c.N - c.share_post_discovery) < 1e-9


def test_every_rendered_share_shows_n_of_N():
    rep, html, md = _rendered()
    blocks = re.findall(r'<div class="(?:cpct|cw-pct)">(.*?)</div>', html, re.S)
    assert len(blocks) == len(rep.concentration) + len(rep.correlated)
    for b in blocks:
        assert re.search(r"\d+%", b) and re.search(r"\b\d+ of \d+\b", b), b
    share_lines = [ln for ln in md.splitlines() if ln.startswith("- ") and "%" in ln]
    assert share_lines
    for ln in share_lines:
        assert re.search(r"\d+% \(\d+ of \d+\)", ln), ln


# ── #8 variance is signed ───────────────────────────────────────────────────

def test_variance_is_signed_and_above_baseline_renders_plus():
    from crossestate.analytics import compute_variance
    from estatereport.contract import SegmentVariance
    from estatereport.transform import variance

    refs = ([make_ref(f"cf{i}.com", "ns:Cloudflare", score=5) for i in range(3)]      # A
            + [make_ref(f"aws{i}.com", "ns:AWS", score=45) for i in range(3)])        # worse
    vb = compute_variance(refs, TH)

    class _M:
        variance = vb
    rows, baseline = variance(_M)
    by = {r.segment: r for r in rows}
    assert by["ns:Cloudflare"].bands_vs_baseline > 0
    assert by["ns:Cloudflare"].vs_baseline_label.startswith("+")
    assert by["ns:AWS"].bands_vs_baseline < 0
    assert by["ns:AWS"].vs_baseline_label.startswith("−")
    assert SegmentVariance(segment="s", domain_count=1, median_grade="B").vs_baseline_label == "baseline"


# ── #9 corpus size is read live, never hard-coded ───────────────────────────

def test_corpus_size_comes_from_the_observatory():
    rep, html, _ = _rendered()
    assert rep.corpus is not None and rep.corpus.domains == 364_175_633
    assert "364M-domain corpus" in html and "340M" not in html


def test_corpus_sentences_are_omitted_when_the_observatory_is_unreachable():
    from estatereport.build import build_estate_report_from_manifest
    from estatereport.renderer import EstateReportRenderer
    rep = build_estate_report_from_manifest(ESTATE_MANIFEST, now=_NOW, observatory=no_observatory())
    html = EstateReportRenderer(rep).to_html()
    assert rep.corpus is None
    assert "-domain corpus" not in html and "340M" not in html and "None" not in html


def test_free_report_reads_the_corpus_size_live_too():
    import json as _json
    from freereport.renderer import FreeReportRenderer
    from intelligence_contract import ReportViewModel
    path = os.path.join(_ROOT, "tests", "fixtures", "free_qbeeurope.json")
    with open(path, encoding="utf-8") as fh:
        vm = ReportViewModel.model_validate(_json.load(fh))
    live = FreeReportRenderer(vm, now=_NOW, observatory=fixture_observatory()).to_html()
    off = FreeReportRenderer(vm, now=_NOW, observatory=no_observatory()).to_html()
    assert "364M-domain corpus" in live
    assert "340M" not in live + off and "Datazag's domain corpus" in off


# ── internal field names never reach a reader ──────────────────────────────

INTERNAL_TOKENS = re.compile(
    r"\b(?:ns|reg|asn):\S|confidence\s*=|external_threat|calendar\.overdue|correlated_weakness"
    r"|registrar_lock|surface_diversity_masking|\b(?:cert_expiring|cert_expired|domain_expiry"
    r"|missed_renewal|item_kind|known_count|bands_below_baseline)\b|×\s*\d")


def _inferred_estate_report():
    from tests.estate_helpers import report_from_refs
    refs = [
        make_ref("a.com", "x", ns="AWS", registrar="GoDaddy", dmarc="none", caa=False,
                 status="ok", expires="2026-07-10",
                 cert=_ca(_cert("auth.a.com", "2026-07-20"))),
        make_ref("b.com", "x", ns="AWS", registrar="GoDaddy", dmarc="none", caa=False),
        make_ref("c.com", "x", ns="Cloudflare", registrar="Namecheap", score=5),
        make_ref("d.com", "x", ns="Cloudflare", registrar="Namecheap", score=5),
    ]
    return report_from_refs(refs, _NOW, tagged=False)


def test_no_internal_field_names_in_html_or_markdown():
    from estatereport.renderer import EstateReportRenderer
    from tests.estate_helpers import visible_text
    rep = _inferred_estate_report()
    assert any(v.segment.startswith("ns:") for v in rep.variance)    # keys really are inferred
    r = EstateReportRenderer(rep)
    for name, text in (("html", visible_text(r.to_html())), ("md", r.to_markdown())):
        hit = INTERNAL_TOKENS.search(text)
        assert not hit, f"{name}: {text[max(0, hit.start()-50):hit.end()+50]!r}"
    assert "DNS hosted by AWS" in visible_text(r.to_html())


def test_json_keeps_keys_and_provenance_for_analysts():
    import json as _json
    from estatereport.renderer import EstateReportRenderer
    data = _json.loads(EstateReportRenderer(_inferred_estate_report()).to_json())
    assert any(v["segment"].startswith("ns:") for v in data["variance"])
    assert all("provenance" in e and "evidence_line" not in e for e in data["exceptions"])


# Modules whose strings reach a reader (templates and composed copy).
_COPY_MODULES = ("estatereport/renderer.py", "estatereport/build.py", "estatereport/exceptions2.py",
                 "crossestate/renderer.py", "crossestate/exceptions.py",
                 "freereport/renderer.py", "freereport/compose.py")


def test_no_hard_coded_corpus_figure_in_report_copy():
    pat = re.compile(r"\b\d{3}M\b|\b\d{3} ?million\b", re.I)
    for rel in _COPY_MODULES:
        with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                code = line.split("  #")[0]
                if code.lstrip().startswith("#"):
                    continue
                assert not pat.search(code), f"{rel}:{i}: {line.strip()[:80]}"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
