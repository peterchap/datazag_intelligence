"""
estatereport/labels.py
----------------------
Human labels for internal keys. Customer-facing output (HTML, Markdown, PDF)
never shows a field name or an inferred segment key such as `ns:AWS`; the JSON
export keeps the keys so consumers stay stable.
"""

from __future__ import annotations

_SEGMENT_PREFIX = {
    "ns": "DNS hosted by {}",
    "reg": "Registered with {}",
    "asn": "Hosted on network AS{}",
}

_CAL_KIND = {
    "domain_expiry": "Registration expiry",
    "unlocked": "Registrar lock missing",
    "cert_expiring": "Certificate expiring",
    "cert_expired": "Certificate expired",
}


def segment_label(key: str) -> str:
    """`ns:AWS` -> "DNS hosted by AWS". A customer-supplied segment name (no
    inferred prefix) is already a human label and passes through unchanged."""
    k = (key or "").strip()
    prefix, sep, rest = k.partition(":")
    if sep and prefix in _SEGMENT_PREFIX and rest:
        return _SEGMENT_PREFIX[prefix].format(rest.strip())
    return k


def calendar_kind_label(kind: str) -> str:
    return _CAL_KIND.get(kind, (kind or "").replace("_", " ").capitalize())
