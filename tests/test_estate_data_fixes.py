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


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
