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


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
