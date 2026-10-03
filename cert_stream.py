"""
cert_stream.py — certificate intel from Datazag's own CT-log archive.

Replaces the per-domain CertSpotter pull (2026-10-02). CertSpotter's free tier
rate-limits by SLEEPING (Retry-After 148–358s, observed), so one domain could
stall a report for minutes and an estate for hours. The archive holds every
certificate our CertStream tailer has logged since 2026-07-23:

    r2://cert-observations/bronze/cert_observations/dt=YYYY-MM-DD/*.parquet

One query serves any number of domains, so an estate prefetches all of its
domains at once (`prefetch`) and each per-domain build reads from memory.

The rows match dnsproject's cert_pipeline.normalise() exactly, so CertAnalysis
and everything downstream are unchanged. Differences from CertSpotter:
  - cert_id is the serial (the archive has no CertSpotter id).
  - common_name is "" (the archive stores SANs, not the subject CN).
  - Coverage starts 2026-07-23 and has gaps (2026-08-07..15, some stalled logs),
    so a certificate issued before the window is not seen. `coverage` says so.

Env:
  CERT_ARCHIVE_R2_BUCKET   bucket/prefix (default cert-observations/bronze/cert_observations)
  CERT_LOOKBACK_DAYS       days of partitions to read (default 100)
  R2_ACCESS_KEY_ID|R2_ACCESS_KEY, R2_SECRET_ACCESS_KEY|R2_SECRET_KEY, R2_ACCOUNT_ID
"""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import date, datetime, timedelta, timezone
from typing import Iterable, Optional

ARCHIVE_START = date(2026, 7, 23)

# Prefetched rows per apex domain. An empty list means "looked up, no
# certificates"; a domain missing from the dict was never looked up.
_ROWS: dict[str, list[dict]] = {}


def _classify_issuer(org: str, cn: str) -> str:
    """Same buckets as dnsproject cert_pipeline._classify_issuer."""
    combined = (org + " " + cn).lower()
    if "amazon" in combined:
        return "amazon_acm"
    if "let's encrypt" in combined or "letsencrypt" in combined:
        return "letsencrypt"
    if "google trust" in combined:
        return "google_ts"
    if "cloudflare" in combined:
        return "cloudflare"
    if "starfield" in combined or "godaddy" in combined:
        return "starfield"
    if "digicert" in combined:
        return "digicert"
    if "sectigo" in combined or "comodo" in combined:
        return "sectigo"
    return "other"


def _as_date(v) -> Optional[date]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc).date()
    if isinstance(v, datetime):
        return (v.astimezone(timezone.utc) if v.tzinfo else v).date()
    if isinstance(v, date):
        return v
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _fmt(d: Optional[date]) -> Optional[str]:
    return d.isoformat() if d else None


def rows_from_certs(certs: Iterable[dict], today: Optional[date] = None) -> list[dict]:
    """One normalise()-shaped row per (certificate, SAN). `certs` are the deduped
    certificates: issuer_o, issuer_cn, cert_serial, not_before, not_after,
    logged_at, san_entries."""
    today = today or date.today()
    rows: list[dict] = []
    for c in certs:
        org = c.get("issuer_o") or ""
        cn = c.get("issuer_cn") or ""
        nb = _as_date(c.get("not_before"))
        na = _as_date(c.get("not_after"))
        logged = _as_date(c.get("logged_at"))
        validity = (na - nb).days if nb and na else None
        remaining = (na - today).days if na else None
        sans = [s for s in (c.get("san_entries") or []) if s]
        for name in sans:
            name = str(name).lower().rstrip(".")
            rows.append({
                "cert_id":         str(c.get("cert_serial") or ""),
                "logged_at":       _fmt(logged),
                "not_before":      _fmt(nb),
                "not_after":       _fmt(na),
                "common_name":     "",
                "dns_name":        name,
                "is_wildcard":     name.startswith("*."),
                "issuer_org":      org,
                "issuer_cn":       cn,
                "issuer_category": _classify_issuer(org, cn),
                "validity_days":   validity,
                "days_remaining":  remaining,
                "is_expired":      remaining < 0 if remaining is not None else False,
                "san_count":       len(sans),
            })
    return rows


def _connect():
    import duckdb
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"), override=False)
    except Exception:
        pass
    con = duckdb.connect(":memory:")
    if not os.environ.get("HOME"):
        home = os.path.expanduser("~")
        if home and home != "~":
            con.execute(f"SET home_directory='{home}';")
    con.execute("INSTALL httpfs; LOAD httpfs;")
    key = os.environ.get("R2_ACCESS_KEY_ID") or os.environ.get("R2_ACCESS_KEY")
    secret = os.environ.get("R2_SECRET_ACCESS_KEY") or os.environ.get("R2_SECRET_KEY")
    account = os.environ.get("R2_ACCOUNT_ID")
    if not (key and secret and account):
        raise RuntimeError("R2 credentials not set")
    con.execute("CREATE OR REPLACE SECRET cert_r2 (TYPE R2, KEY_ID ?, SECRET ?, ACCOUNT_ID ?);",
                [key, secret, account])
    return con


def _archive_glob() -> str:
    bucket = os.environ.get("CERT_ARCHIVE_R2_BUCKET", "cert-observations/bronze/cert_observations")
    return f"r2://{bucket.strip('/')}/*/*.parquet"


_DOMAIN_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

# Precert and final cert share a serial; the archive also repeats a cert across
# partitions (each log it reaches). Dedup across both at read time.
_SQL = """
SELECT apex_domain, issuer_o, issuer_cn, cert_serial,
       -- epoch seconds: time-zone independent, and fetching TIMESTAMPTZ needs pytz
       epoch(min(not_before)) AS not_before, epoch(max(not_after)) AS not_after,
       epoch(min(seen_at))    AS logged_at,  any_value(san_entries) AS san_entries
FROM read_parquet(?, hive_partitioning = true)
WHERE dt >= ? AND apex_domain IN ({names})
GROUP BY ALL
"""


def query_certs(con, domains: list[str], since: date) -> dict[str, list[dict]]:
    # A literal IN list (not a bound array) so DuckDB can skip row groups by their
    # apex_domain min/max: the daily rewrite sorts each partition by apex_domain.
    safe = [d for d in domains if _DOMAIN_RE.match(d)]
    if not safe:
        return {d: [] for d in domains}
    names = ", ".join(f"'{d}'" for d in safe)
    cur = con.execute(_SQL.format(names=names), [_archive_glob(), since])
    cols = [d[0] for d in cur.description]
    out: dict[str, list[dict]] = {d: [] for d in domains}
    for r in cur.fetchall():
        rec = dict(zip(cols, r))
        out.setdefault(rec["apex_domain"], []).append(rec)
    return out


def prefetch(domains: Iterable[str], con=None) -> dict[str, int]:
    """Load every domain's certificates in ONE archive query and keep the rows in
    memory for `cert_intel`. Returns {domain: certificate count}. Raises on a
    connection/query error so the caller can log it; nothing is cached then."""
    wanted = sorted({d.strip().lower() for d in domains if d and d.strip()} - set(_ROWS))
    if not wanted:
        return {}
    lookback = int(os.environ.get("CERT_LOOKBACK_DAYS", "100"))
    since = max(ARCHIVE_START, date.today() - timedelta(days=lookback))
    t = time.time()
    con = con or _connect()
    certs = query_certs(con, wanted, since)
    counts = {}
    for d in wanted:
        _ROWS[d] = rows_from_certs(certs.get(d, []))
        counts[d] = len(certs.get(d, []))
    print(f"  cert-intel: archive query for {len(wanted)} domain(s) in {time.time() - t:.1f}s "
          f"({sum(counts.values())} certificates)")
    return counts


def coverage(since: Optional[date] = None) -> dict:
    return {
        "source": "datazag_ct_archive",
        "window_start": (since or ARCHIVE_START).isoformat(),
        "note": "Certificates logged since the window start. Older certificates are not seen.",
    }


def _cert_analysis_cls():
    """dnsproject's CertAnalysis — the same analysis the CertSpotter path used."""
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent not in sys.path:
        sys.path.append(parent)
    from dnsproject.intelligence.cert_pipeline import CertAnalysis  # type: ignore
    return CertAnalysis


def analyse(rows: list[dict], domain: str, CertAnalysis=None) -> dict:
    """{"subdomains": [...], "cert_analysis": {...}} — the CertPipeline.run() shape."""
    CertAnalysis = CertAnalysis or _cert_analysis_cls()
    a = CertAnalysis(rows, domain)
    subdomains = [
        {
            "dns_name":        s["dns_name"],
            "a_records":       [],
            "source":          "ct_archive",
            "is_expired":      s["is_expired"],
            "days_remaining":  s["days_remaining"],
            "issuer_category": s["issuer_category"],
        }
        for s in a.subdomain_corpus()
    ]
    return {
        "subdomains": subdomains,
        "cert_analysis": {
            "summary":           a.summary(),
            "wildcard_zones":    a.wildcard_zones(),
            "issuer_breakdown":  a.issuer_distribution(),
            "expiring_soon":     a.expiring_soon(60),
            "expired":           a.expired(),
            "missed_renewals":   a.missed_renewals(),
            "cert_churn":        a.cert_churn(),
            "cross_domain_sans": a.cross_domain_sans(),
            "cn_anomalies":      a.cn_anomalies(),
            "coverage":          coverage(),
        },
    }


def cert_intel(domain: str) -> dict:
    """Subdomains + cert_analysis for one domain, from the prefetch cache or a
    single-domain query. Raises on archive errors (the caller degrades to empty)."""
    d = domain.strip().lower()
    if d not in _ROWS:
        prefetch([d])
    return analyse(_ROWS.get(d, []), d)
