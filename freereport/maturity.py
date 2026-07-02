"""
freereport/maturity.py
----------------------
The email-control maturity reference — the proposed `ref.email_control_maturity`
table expressed as DATA, joined at render time (per the free-report build spec).

Two jobs:
  1. Classify each email/DNS control into a tier (baseline / advanced / gold) so
     the renderer can obey the house rule: **only baseline gaps are negatives.**
     Advanced/gold gaps render as opportunities (cyan/amber), never red.
  2. Drive the page-4 fix priority (Now / Soon / Maturity) with the free report's
     right-sizing (CAA = Soon; MTA-STS/TLS-RPT/DNSSEC/DANE = Maturity).

Severity → colour: critical/high → red (bad) · low → amber (warn) · info → cyan ·
not_assessed → grey (na). Colour tokens map to the prototype's dot classes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Tier = Literal["baseline", "advanced", "gold"]
Severity = Literal["critical", "high", "low", "info", "not_assessed"]
Priority = Literal["now", "soon", "plan"]          # 'plan' == the "Maturity" pill
Colour = Literal["bad", "warn", "cyan", "na", "ok"]

# severity → the prototype dot/colour class
_SEV_COLOUR: dict[str, Colour] = {
    "critical": "bad", "high": "bad", "low": "warn", "info": "cyan", "not_assessed": "na",
}


@dataclass(frozen=True)
class Control:
    key: str
    label: str
    tier: Tier
    absent_severity: Severity      # severity WHEN the control is absent
    priority: Priority             # page-4 fix pill when absent
    note: str                      # short "what it does" blurb (house-style, hedged)

    @property
    def colour(self) -> Colour:
        return _SEV_COLOUR[self.absent_severity]

    @property
    def is_baseline(self) -> bool:
        return self.tier == "baseline"


# The reference table (spec §"Maturity-tier reference"). Order is render order.
CONTROLS: dict[str, Control] = {
    "dmarc": Control("dmarc", "DMARC", "baseline", "high", "now",
                     "email authentication that lets you reject mail spoofed as your domain"),
    "spf": Control("spf", "SPF", "baseline", "high", "now",
                   "declares which servers may send as your domain"),
    "dkim": Control("dkim", "DKIM", "baseline", "not_assessed", "now",
                    "signs outbound mail; the selector is not always discoverable from outside"),
    "mta_sts": Control("mta_sts", "MTA-STS", "advanced", "info", "plan",
                       "enforces TLS on inbound mail"),
    "tls_rpt": Control("tls_rpt", "TLS-RPT", "advanced", "info", "plan",
                       "reports TLS delivery failures on inbound mail"),
    "caa": Control("caa", "CAA", "advanced", "low", "soon",
                   "reduces the set of certificate authorities that may issue for your domain"),
    "security_txt": Control("security_txt", "security.txt", "advanced", "low", "soon",
                            "publishes a security contact for vulnerability reports"),
    "dnssec": Control("dnssec", "DNSSEC", "gold", "info", "plan",
                      "cryptographically signs your DNS records"),
    "dane": Control("dane", "DANE", "gold", "info", "plan",
                    "pins mail-server certificates via DNSSEC"),
    "bimi": Control("bimi", "BIMI", "gold", "info", "plan",
                    "displays your verified logo in supporting mail clients"),
}


def control(key: str) -> Control:
    return CONTROLS[key]


def present_map(vm) -> dict[str, bool]:
    """Which controls are present on the view-model. Defensive: absent contract
    fields read as False (rendered as an honest gap), never as an error.
    DKIM is a special case — `p=reject` implies working alignment even when the
    selector isn't discoverable, so a reject policy counts DKIM as present."""
    h = vm.hygiene
    reg = vm.registration
    dmarc_reject = (h.dmarc_policy or "").lower() == "reject"
    return {
        "dmarc": bool(h.dmarc_policy) and (h.dmarc_policy or "").lower() in ("reject", "quarantine"),
        "spf": bool(h.spf_record),
        "dkim": bool(getattr(h, "dkim_present", False)) or dmarc_reject,
        "mta_sts": bool(h.mta_sts_mode),
        "tls_rpt": bool(getattr(h, "tlsrpt_present", False)),
        "caa": bool(h.caa_present),
        "security_txt": bool(getattr(h, "has_security_txt", False)),
        "dnssec": bool(h.dnssec or reg.dnssec),
        "dane": False,          # not observable from the contract today
        "bimi": bool(getattr(h, "bimi_present", False)),
    }


def absent_controls(vm, tier: Tier | None = None) -> list[Control]:
    """Controls that are absent (optionally filtered to a tier), in table order.
    DKIM 'not_assessed' is never treated as an absent negative."""
    pres = present_map(vm)
    out: list[Control] = []
    for key, c in CONTROLS.items():
        if pres.get(key):
            continue
        if c.absent_severity == "not_assessed":
            continue
        if tier and c.tier != tier:
            continue
        out.append(c)
    return out
