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

from tests.estate_helpers import ESTATE_MANIFEST  # noqa: E402

_NOW = datetime(2026, 7, 2, tzinfo=timezone.utc)

# Shapes the baseline produced once HTML ate the <domain> placeholder.
EMPTY_PLACEHOLDER = re.compile(
    r'_dmarc\.\.|@(?:"|&#34;|&quot;)|^\.\s+IN\s+CAA|(^|\s)\.\s+TXT|\{domain\}', re.M)


def _rendered():
    from estatereport.build import build_estate_report_from_manifest
    from estatereport.renderer import EstateReportRenderer
    rep = build_estate_report_from_manifest(ESTATE_MANIFEST, now=_NOW)
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


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
