"""
estatereport/controls.py
------------------------
The seven per-domain controls on every entity record, each with ONE fixed
vocabulary (documented in docs/report-editions/controls.md; a test keeps the two
in step). `unknown` on every control means the domain was not assessed (its live
scan did not finish, or its contract failed to load). It is never used for a
measured absence: a domain we scanned that publishes no DMARC is `missing`.
"""

from __future__ import annotations

import re

UNKNOWN = "unknown"

VOCAB: dict[str, tuple[str, ...]] = {
    "dmarc": ("reject", "quarantine", "monitor", "missing", "invalid", UNKNOWN),
    "spf": ("hardfail", "softfail", "neutral", "permissive", "delegated", "missing", UNKNOWN),
    "caa": ("present", "missing", UNKNOWN),
    "dnssec": ("signed", "unsigned", UNKNOWN),
    "mta_sts": ("enforce", "testing", "none", "invalid", "missing", UNKNOWN),
    "bimi": ("present", "missing", UNKNOWN),
    "registrar_lock": ("locked", "unlocked", UNKNOWN),
}
CONTROL_ORDER = tuple(VOCAB)

# The values that count as a gap, per control, and how each gap reads as a finding.
# Order of FIX_ORDER is the remediation urgency (brief §8): recovery/locks, DMARC,
# SPF, CAA, DNSSEC, then the maturity controls.
GAPS: dict[str, dict[str, str]] = {
    "registrar_lock": {"unlocked": "No registrar lock"},
    "dmarc": {"missing": "No DMARC record", "monitor": "DMARC at p=none (monitor only)",
              "invalid": "DMARC record is malformed"},
    "spf": {"missing": "No SPF record", "softfail": "SPF ends in soft-fail (~all)",
            "neutral": "SPF does not fail unlisted senders", "permissive": "SPF allows any sender (+all)"},
    "caa": {"missing": "No CAA record"},
    "dnssec": {"unsigned": "Zone not signed with DNSSEC"},
    "mta_sts": {"missing": "No MTA-STS policy", "none": "MTA-STS policy set to none",
                "testing": "MTA-STS in testing mode", "invalid": "MTA-STS policy unreadable"},
    "bimi": {"missing": "No BIMI record"},
}
FIX_ORDER = ("registrar_lock", "dmarc", "spf", "caa", "dnssec", "mta_sts", "bimi")
BASELINE = frozenset({"registrar_lock", "dmarc", "spf"})        # an actionable finding on its own
MATURITY = frozenset({"mta_sts", "bimi"})                        # never a headline gap

_LOCK_TOKENS = ("transferprohibited", "deleteprohibited", "updateprohibited",
                "clienthold", "serverhold")


def _assessed(vm, load_error) -> bool:
    return bool(getattr(vm, "has_intelligence", False)) and not load_error \
        and not getattr(vm, "scan_incomplete", False)


def dmarc_state(vm) -> str:
    rec = (vm.hygiene.dmarc_record or "").strip()
    pol = (vm.hygiene.dmarc_policy or "").strip().lower()
    if pol in ("reject", "quarantine"):
        return pol
    if pol == "none":
        return "monitor"
    if pol:
        return "invalid"
    return "invalid" if rec else "missing"


def spf_state(vm) -> str:
    spf = re.sub(r"\s+", " ", (vm.hygiene.spf_record or "").strip().lower())
    if not spf:
        return "missing"
    if re.search(r"(^| )-all\b", spf):
        return "hardfail"
    if re.search(r"(^| )~all\b", spf):
        return "softfail"
    if re.search(r"(^| )\+?all\b", spf) and not re.search(r"[-~?]all\b", spf):
        return "permissive"
    if re.search(r"(^| )\?all\b", spf):
        return "neutral"
    if "redirect=" in spf:
        return "delegated"
    return "neutral"                 # no all mechanism: unlisted senders are not failed


def mta_sts_state(vm) -> str:
    mode = (vm.hygiene.mta_sts_mode or "").strip().lower()
    if mode in ("enforce", "testing", "none"):
        return mode
    if mode or vm.hygiene.mta_sts_txt_present:
        return "invalid"             # published, but no readable policy mode
    return "missing"


def lock_state(vm) -> str:
    status = re.sub(r"[\s_-]", "", (vm.registration.status or "").lower())
    if not status:
        return UNKNOWN               # RDAP gave us no status: not measured
    return "locked" if any(t in status for t in _LOCK_TOKENS) else "unlocked"


def controls_for(vm, load_error=None) -> dict[str, str]:
    """The seven controls for one domain, each a value from VOCAB."""
    if not _assessed(vm, load_error):
        return {c: UNKNOWN for c in CONTROL_ORDER}
    return {
        "dmarc": dmarc_state(vm),
        "spf": spf_state(vm),
        "caa": "present" if (vm.hygiene.caa_present or vm.dns_records.caa) else "missing",
        "dnssec": "signed" if (vm.registration.dnssec or vm.hygiene.dnssec) else "unsigned",
        "mta_sts": mta_sts_state(vm),
        "bimi": "present" if vm.hygiene.bimi_present else "missing",
        "registrar_lock": lock_state(vm),
    }


def gaps(controls: dict[str, str], include_maturity: bool = True) -> list[tuple[str, str]]:
    """[(control, finding text)] in fix-urgency order."""
    out = []
    for c in FIX_ORDER:
        if not include_maturity and c in MATURITY:
            continue
        text = GAPS.get(c, {}).get(controls.get(c, UNKNOWN))
        if text:
            out.append((c, text))
    return out


def top_issue(controls: dict[str, str]) -> str | None:
    g = gaps(controls)
    return g[0][1] if g else None
