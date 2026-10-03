"""
crossestate/tls_probe.py
------------------------
Confirm a certificate-expiry calendar row against the certificate a host is
actually serving. Certificate transparency only shows what was logged in our
archive window, which has gaps (2026-08-07..15 and some stalled logs), so a cert
renewed during a gap looks like one about to lapse. A live handshake settles it.

Standard library only. A probe that fails (no listener, timeout, a cert that does
not verify) returns None, meaning "not confirmed either way": the calendar row is
kept, never dropped on a failed probe.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

TlsProbe = Callable[[Iterable[str]], dict[str, Optional[datetime]]]


def served_not_after(host: str, timeout: float = 3.0) -> Optional[datetime]:
    """notAfter of the certificate `host` serves on 443, or None if it cannot be
    read with a verified handshake."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except (OSError, ssl.SSLError, ValueError):
        return None
    raw = cert.get("notAfter")
    if not raw:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), tz=timezone.utc)
    except (ValueError, OverflowError):
        return None


def probe_hosts(hosts: Iterable[str], timeout: float = 3.0,
                workers: int = 16) -> dict[str, Optional[datetime]]:
    """Probe many hosts concurrently. {host: served notAfter | None}."""
    uniq = sorted({h.strip().lower() for h in hosts if h and h.strip() and "*" not in h})
    if not uniq:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(uniq)))) as pool:
        results = pool.map(lambda h: served_not_after(h, timeout), uniq)
        return dict(zip(uniq, results))
