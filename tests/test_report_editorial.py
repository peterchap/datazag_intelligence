"""
test_report_editorial.py
------------------------
Editorial and data-consistency guards on the rendered report.

These exist because a reader who spots one inconsistency starts doubting every
number in the document — and the report's whole proposition is data quality. Each
test here corresponds to a defect found by reading the rendered PDF, not the code:

  * the contents claimed "ten sections" and listed eleven;
  * "Infrastructure &amp;amp; routing intelligence" — an entity encoded twice;
  * "Some New Unmapped Code" — a raw corpus token rendered as a finding title;
  * "MX configuration — Healthy" on a domain whose DNS page reports no MX records.

The last one was not a copy slip: the change-signal cards read a missing key as
their "stable" label, so absent data asserted a healthy state. That is the same
failure as a NULL score rendering 0.00, and this file is where it gets caught.

Runs under pytest or standalone (`python tests/test_report_editorial.py`).
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


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _render(**kw) -> str:
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    d = _load("platform_impersonation_sample.json")
    imps = [PlatformImpersonation.model_validate(p) for p in d["platforms"]]
    vm = build_view_models(di, detected_platforms=["microsoft365", "okta", "mailchimp"],
                           impersonations=imps, own_brand=BrandExposure.model_validate(d["own_brand"]),
                           findings=derive_findings(di, imps), **kw)
    return HealthReportRenderer(vm).to_html()


def _visible(html: str) -> str:
    """Reader-visible text: no CSS, no tags, entities resolved."""
    body = re.sub(r"<style.*?</style>", " ", html, flags=re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    for ent, ch in (("&mdash;", "—"), ("&ndash;", "–"), ("&amp;", "&"),
                    ("&rsquo;", "'"), ("&ldquo;", '"'), ("&rdquo;", '"'), ("&nbsp;", " ")):
        body = body.replace(ent, ch)
    return body


# ---------------------------------------------------------------------------

def test_stated_section_count_matches_the_contents_list():
    """"Mapping your attack surface, in ten sections." — above eleven of them."""
    html = _render()
    stated = re.search(r"in (\w+) sections", _visible(html))
    assert stated, "the contents page no longer states a section count"
    listed = len(re.findall(r'class="toc-row', html)) or len(re.findall(r'class="toc-item', html))
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
             "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13}
    claimed = words.get(stated.group(1).lower()) or int(stated.group(1))
    assert claimed == listed, f"contents claims {claimed} sections, lists {listed}"


def test_no_double_encoded_entities():
    """&amp;amp; reaches the reader as a literal "&amp;"."""
    html = _render()
    for bad in ("&amp;amp;", "&amp;mdash;", "&amp;nbsp;", "&amp;lt;", "&amp;#"):
        assert bad not in html, f"double-encoded entity in the rendered report: {bad}"


def test_no_raw_internal_tokens_as_copy():
    """A corpus reason code with no mapping used to become a finding TITLE, so the
    report showed things like "Some New Unmapped Code" — indistinguishable from
    placeholder text left in by mistake."""
    di = DomainIntelligence.model_validate({
        "schema_version": "1.0", "domain": "riskyexample.com",
        "risk_assessment": {"reason_codes": ["some_new_unmapped_code", "another_未mapped"]},
    })
    titles = [f["title"] for f in derive_findings(di, [])]
    assert "Some New Unmapped Code" not in titles
    for t in titles:
        assert "_" not in t, f"raw token in a finding title: {t!r}"
    # the signal is not thrown away — the code is still in the evidence
    evidence = " ".join(f["evidence"] for f in derive_findings(di, []))
    assert "some_new_unmapped_code" in evidence


def test_no_empty_template_variables_reach_the_reader():
    """Jinja renders an undefined name as an empty string, so a typo ships as a
    hole rather than an error: "Risk score /100" was live until this test existed."""
    text = _visible(_render())
    text = re.sub(r"\s+", " ", text)
    holes = []
    for pattern, what in ((r"\bscore\s*/\s*100", "a score with no number"),
                          (r"\b\w+\s*:\s*(?:·|\||$)", "a label with no value"),
                          (r"\(\s*\)", "an empty parenthetical"),
                          (r"\bof\s+/", "a fraction with no numerator")):
        for m in re.finditer(pattern, text):
            holes.append(f"{what}: ...{text[max(0, m.start()-45):m.end()+25].strip()}...")
    assert not holes, "empty template variables in the rendered report:\n  " + "\n  ".join(holes[:6])


def test_timeline_does_not_assert_health_it_never_measured():
    """The contradiction a reader spotted: the DNS page reported no MX records while
    the timeline reported "MX configuration — Healthy". `changes` is empty on the
    live path, so every card was rendering its stable label from absent data."""
    html = _render()
    text = _visible(html)
    if "No MX records" in text:
        assert "MX configuration" not in text or "Healthy" not in text.split("MX configuration")[1][:40], \
            "timeline calls MX healthy on a domain the DNS page says has no MX records"
    r = HealthReportRenderer(build_view_models(
        DomainIntelligence.model_validate(_load("medallion_sample.json"))))
    for card in r._build_change_signal_list():
        assert card["assessed"] is False
        assert card["state"] == "Not assessed", \
            f"{card['label']} claims {card['state']!r} with no change baseline"


def test_zero_detected_platforms_is_not_an_impersonation_all_clear():
    """Found on the first real-domain run: cybercube.com resolved with zero SaaS
    platforms detected, and the report answered "No active impersonation of your
    platforms in the last 30 days \u2014 but every platform here is a lure", pointing
    at an empty list. The impersonation count is zero because there was nothing to
    look up, which is not evidence of safety \u2014 the same absence-as-all-clear the
    unreachable-rollup branch already guards against.

    Covers all four sites that rendered the claim: the platform card, the scorecard
    pill, the external-surface table, and the markdown edition.
    """
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = build_view_models(di, detected_platforms=[], impersonations=[],
                           own_brand=None, findings=derive_findings(di, []))
    r = HealthReportRenderer(vm)
    text = re.sub(r"\s+", " ", _visible(r.to_html()))

    assert "No active impersonation" not in text, \
        "report claims no impersonation on a domain with no platforms to impersonate"
    assert "every platform here is a lure" not in text, \
        "report calls an empty platform list a set of lures"
    assert "trusted platforms in your stack" not in text, \
        "report describes a stack it did not detect"
    assert "nothing was checked" in text or "nothing to check" in text, \
        "report does not say that the impersonation check had no input"

    md = r.to_markdown() if hasattr(r, "to_markdown") else ""
    if md:
        assert "No active impersonation of your platforms" not in md, \
            "markdown edition still renders the all-clear"


def _cybcube_like():
    """A stack of three platforms where the rollup covers two — the shape the first
    real multi-platform run produced (cybcube.com: Google Workspace, HubSpot,
    Mandrill; no rollup entry for Mandrill; 6,167 / 15,306 totals)."""
    imps = [PlatformImpersonation(platform="Google Workspace", count_7d=5100, count_30d=12800),
            PlatformImpersonation(platform="HubSpot", count_7d=1067, count_30d=2506),
            PlatformImpersonation(platform="Mandrill", count_7d=0, count_30d=0, measured=False)]
    # The run also returned two fuzzy typosquat candidates (exact=3 lookalike=2).
    # These are platform-scoped too — rollup kind `platform_typosquat`.
    looks = [PlatformImpersonation(platform="Google Workspace", count_30d=4210,
                                   confidence="lookalike"),
             PlatformImpersonation(platform="HubSpot", count_30d=1380,
                                   confidence="lookalike")]
    di = DomainIntelligence.model_validate(_load("medallion_sample.json"))
    vm = build_view_models(di, detected_platforms=["Google Workspace", "HubSpot", "Mandrill"],
                           impersonations=imps, lookalike_candidates=looks,
                           own_brand=None, findings=[])
    return HealthReportRenderer(vm)


def test_platform_global_counts_are_never_bound_to_this_domain():
    """The impersonation rollup is keyed by platform name alone — there is no domain
    in that join. 15,306 means "15,306 lookalikes of Google Workspace exist", which
    is the same number for every Google Workspace customer. The cover led with it as
    "15306 lookalike domains are imitating the platforms your staff log into… this
    report shows who is imitating you", which reads as 15,306 domains aimed at the
    reader. Same conflation brand_page_data_contract.md forbids on the free tier,
    leading the paid report."""
    r = _cybcube_like()
    text = re.sub(r"\s+", " ", _visible(r.to_html()))

    for claim in ("imitating you", "of your platforms impersonated",
                  "actively impersonated"):
        assert claim not in text, \
            f"copy binds a platform-global count to this domain: {claim!r}"

    # The number must still appear — with its scope attached, not suppressed.
    assert "15,306" in text, "the platform-global total vanished entirely"
    assert "internet" in text, "the total is shown without saying what it is a total of"

    cover = r._cover_hook()
    assert "15,306" not in cover["title"], \
        "cover headline leads with a count that is identical for every customer of that platform"


def test_a_platform_the_rollup_never_held_is_named_not_dropped():
    """Mandrill was in the stack and absent from the rollup, so it scored 0 and
    _active_impersonations filtered it out — leaving it visible in "Detected platform
    stack" and absent from the impersonation table, which reads as cleared."""
    r = _cybcube_like()
    assert r.vm.external_threat.unmeasured_platforms == ["Mandrill"]
    # Not counted as a measured zero in the totals.
    assert r.vm.external_threat.total_30d == 15306

    text = re.sub(r"\s+", " ", _visible(r.to_html()))
    assert "Not checked:" in text and "Mandrill" in text, \
        "a platform the rollup never held is dropped from the report without a word"

    md = r.to_markdown() if hasattr(r, "to_markdown") else ""
    if md:
        assert "Not checked:" in md, "markdown edition drops the unchecked platform"


def test_large_counts_carry_thousands_separators():
    """"15306" on a cover reads as a typo, and the report's proposition is that its
    numbers can be trusted."""
    text = _visible(_cybcube_like().to_html())
    for formatted, raw in (("15,306", "15306"), ("12,800", "12800"),
                           ("4,210", "4210"), ("1,380", "1380")):
        assert formatted in text, f"{formatted} missing — is the count rendered at all?"
        assert raw not in text, f"{raw} rendered without a thousands separator"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
