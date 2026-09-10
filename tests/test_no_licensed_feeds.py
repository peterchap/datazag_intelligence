"""
test_no_licensed_feeds.py
-------------------------
Datazag does not license Feodo, URLhaus, SSLBL, ThreatFox or Spamhaus. They must
not appear in capture, in risk scoring, or in a report — a licence we do not hold
cannot be the basis of a finding we sell.

They used to be all three: a `threat_feeds` block on the contract, a 0.85 floor on
the threat score, a critical finding per listing, named pills in the estate report,
a line in the LLM prompt, and — most visibly — the cover headline, which led with
"Immediate investigation: listed on Feodo C2 tracker".

This file is the standing guard. It fails if any of those names reappears in a
rendered report, in the contract, or in the scoring path.

Runs under pytest or standalone (`python tests/test_no_licensed_feeds.py`).
"""

from __future__ import annotations

import json
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from intelligence_contract import (  # noqa: E402
    BrandExposure,
    DomainIntelligence,
    PlatformImpersonation,
    build_view_models,
)
from findings_rules import derive_findings  # noqa: E402
from healthreport.renderer import HealthReportRenderer  # noqa: E402

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# Every feed Datazag does not license, in the spellings a report might use.
LICENSED_FEEDS = ("feodo", "urlhaus", "sslbl", "threatfox", "spamhaus", "abuse.ch",
                  "firehol", "spamhaus drop")


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _sample_vm():
    """The sample medallion still carries a threat_feeds block — deliberately, so
    this test proves the payload is ignored rather than merely absent."""
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    d = _load("platform_impersonation_sample.json")
    imps = [PlatformImpersonation.model_validate(p) for p in d["platforms"]]
    return build_view_models(di, detected_platforms=["microsoft365", "okta"],
                             impersonations=imps,
                             own_brand=BrandExposure.model_validate(d["own_brand"]),
                             findings=derive_findings(di, imps))


def _assert_clean(text: str, where: str) -> None:
    low = text.lower()
    for feed in LICENSED_FEEDS:
        assert feed not in low, f"{where} names a feed Datazag does not license: {feed!r}"


def test_the_fixture_still_carries_the_payload():
    """Otherwise this whole file passes for the wrong reason."""
    raw = _load("medallion_sample.json")
    assert raw.get("threat_feeds"), "fixture no longer exercises the ignored payload"
    assert raw["threat_feeds"].get("feodo", {}).get("listed") is True


def test_contract_ignores_the_payload():
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    assert not hasattr(di, "threat_feeds")
    assert not hasattr(build_view_models(di).threat, "listed_feeds")


def test_no_finding_comes_from_a_licensed_feed():
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    for f in derive_findings(di, []):
        _assert_clean(json.dumps(f), "a finding")
        assert not f["finding"].startswith("threat_feed_")


def test_scoring_does_not_move_on_a_listing():
    """The listing used to floor the threat score at 0.85. Two payloads identical
    but for the feed block must now score the same."""
    base = _load("medallion_sample.json")
    listed = {**base, "threat_feeds": {"feodo": {"listed": True}, "spamhaus": {"listed": True}}}
    clean = {**base, "threat_feeds": {}}
    a = build_view_models(DomainIntelligence.model_validate(listed))
    b = build_view_models(DomainIntelligence.model_validate(clean))
    assert a.threat.score == b.threat.score
    assert a.composite_score == b.composite_score


def test_rendered_report_never_names_a_feed():
    vm = _sample_vm()
    r = HealthReportRenderer(vm)
    _assert_clean(r.to_html(), "the rendered HTML report")
    _assert_clean(r.to_markdown(), "the markdown edition")


def test_cover_headline_never_leads_with_a_feed():
    """The most-read line in the report, and where the listing used to surface."""
    hook = HealthReportRenderer(_sample_vm())._cover_hook()
    _assert_clean(hook["title"] + " " + hook["deck"], "the cover headline")


def test_the_source_tree_keeps_no_feed_lookups():
    """Belt and braces: a reader of the code should not find a live lookup either."""
    offenders = []
    for root, dirs, files in os.walk(_ROOT):
        dirs[:] = [d for d in dirs if d not in
                   {".git", "node_modules", "__pycache__", "tests", "dzintelligence_env"}]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8", errors="ignore") as fh:
                in_denylist = False
                for i, line in enumerate(fh, 1):
                    # The deny-list names the codes in order to suppress them; that is
                    # the opposite of a lookup, so it is allowed to mention them.
                    if "_UNLICENSED_REASON_CODES" in line and "{" in line:
                        in_denylist = True
                        continue
                    if in_denylist:
                        if "}" in line:
                            in_denylist = False
                        continue
                    if line.lstrip().startswith("#"):
                        continue          # comments explaining the removal are fine
                    if re.search(r"feodo|urlhaus|sslbl|threatfox|spamhaus", line, re.I):
                        offenders.append(f"{os.path.relpath(path, _ROOT)}:{i}: {line.strip()[:70]}")
    assert not offenders, "live licensed-feed references remain:\n  " + "\n  ".join(offenders)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
