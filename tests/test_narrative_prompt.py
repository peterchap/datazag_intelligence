"""
test_narrative_prompt.py
------------------------
Verifies the narrative prompt is built from the medallion contract — the dead
`domain_risk_score` / `domain_risk_context` reads (which silently rendered
"NO_DATA/100" on every report) are gone, and platform-impersonation data is
woven in. No API call is made; only the prompt builder is exercised.

Runs under pytest or standalone (`python tests/test_narrative_prompt.py`).
"""

from __future__ import annotations

import json
import os
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
from narrative import build_narrative_prompt, _vm_from_output  # noqa: E402

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _medallion() -> dict:
    return _load("medallion_sample.json")


def _prompt(output=None, vm=None, audience="insurer", findings=None):
    return build_narrative_prompt(
        domain="riskyexample.com",
        score=85,
        risk_band="high",
        findings=findings or [],
        output=output or {},
        audience=audience,
        vm=vm,
    )


# ---------------------------------------------------------------------------
# Medallion block from the legacy output dict (current pipeline shape)
# ---------------------------------------------------------------------------

def test_prompt_reads_medallion_from_output_dict():
    output = {"domain": "riskyexample.com",
              "infrastructure_intelligence": _medallion()}
    p = _prompt(output=output)
    # dead-key regression guard: never the old silent failure
    assert "NO_DATA" not in p
    # 0-1 scaled medallion values present
    assert "Fast-flux risk: 0.70" in p
    assert "DGA risk: 0.65" in p
    assert "Dangling-CNAME risk: 0.80" in p
    assert "gone.cloudapp.net" in p          # cname target
    # reason codes bulleted, nothing dropped
    assert "HIGH_BGP_CHURN" in p
    assert "SOME_NEW_UNMAPPED_CODE" in p
    # threat feeds / routing / email / velocity
    assert "feodo" in p
    assert "RPKI invalid" in p
    assert "MOAS DETECTED" in p
    assert "18 IP changes" in p
    assert "30 malicious domains share this asn (64500)" in p


def test_vm_from_output_none_when_not_medallion():
    assert _vm_from_output({}) is None
    assert _vm_from_output({"infrastructure_intelligence": {"domain_risk_score": 42}}) is None


# ---------------------------------------------------------------------------
# Explicit no-intelligence state (never silent)
# ---------------------------------------------------------------------------

def test_prompt_explicit_when_no_intelligence():
    p = _prompt(output={"domain": "riskyexample.com"})
    assert "No Datazag corpus intelligence is available" in p
    assert "Do not fabricate" in p
    assert "NO_DATA" not in p


# ---------------------------------------------------------------------------
# Typed view-model path (post-cutover shape) + impersonation block
# ---------------------------------------------------------------------------

def test_prompt_from_vm_with_impersonations():
    di = DomainIntelligence.model_validate(_medallion())
    data = _load("platform_impersonation_sample.json")
    imps = [PlatformImpersonation.model_validate(x) for x in data["platforms"]]
    own = BrandExposure.model_validate(data["own_brand"])
    vm = build_view_models(di, ["microsoft365", "okta"], imps, own,
                           derive_findings(di, imps))
    p = _prompt(vm=vm)
    assert "PLATFORM IMPERSONATION" in p
    assert "microsoft365: 14 in 7d / 41 in 30d (up)" in p
    assert "micros0ft-365-login.com" in p
    assert "Own-brand lookalikes: 1 in 7d / 3 in 30d" in p
    assert "Detected platform stack: microsoft365, okta" in p


def test_prompt_no_impersonation_block_when_empty():
    di = DomainIntelligence.model_validate(_medallion())
    vm = build_view_models(di)
    p = _prompt(vm=vm)
    assert "PLATFORM IMPERSONATION" not in p
    # medallion block still present
    assert "Fast-flux risk: 0.70" in p


# ---------------------------------------------------------------------------
# Audience handling + output contract preserved
# ---------------------------------------------------------------------------

def test_new_audiences_do_not_keyerror():
    for aud in ("advisory", "remediation", "flagship", "external_threat",
                "insurer", "consultant", "it", "sales", "unknown_thing"):
        p = _prompt(output={"domain": "x.test"}, audience=aud)
        assert "You are producing a detailed DNS intelligence report" in p


def test_output_contract_keys_unchanged():
    p = _prompt(output={"domain": "x.test"})
    for key in ("key_finding", "executive_summary", "threat_narrative",
                "positive_signals", "remediation_priority", "insurer_signals",
                "saas_stack_analysis"):
        assert f'"{key}"' in p


def _main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
            import traceback
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    _main()
