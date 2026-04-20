"""
cert_pipeline.py — Certspotter certificate intelligence pipeline

Fully async using httpx. Returns plain dicts throughout — no Polars DataFrames,
no serialisation issues, no thread boundary problems.

Integrates with compile_pure_dns_report() via:
    cert_task = asyncio.create_task(fetch_certspotter_subdomains(domain))
"""

import asyncio
import httpx
import os
import json
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
load_dotenv()

def _classify_issuer(org: str, cn: str) -> str:
    combined = (org + " " + cn).lower()
    if "amazon" in combined:                        return "amazon_acm"
    if "let's encrypt" in combined \
    or "letsencrypt" in combined:                   return "letsencrypt"
    if "google trust" in combined:                  return "google_ts"
    if "cloudflare" in combined:                    return "cloudflare"
    if "starfield" in combined \
    or "godaddy" in combined:                       return "starfield"
    if "digicert" in combined:                      return "digicert"
    if "sectigo" in combined \
    or "comodo" in combined:                        return "sectigo"
    return "other"


def _parse_date(value) -> Optional[date]:
    if not value:
        return None
    if isinstance(value, date):
        return value
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).date()
    except Exception:
        return None


def _fmt(d: Optional[date]) -> Optional[str]:
    return d.isoformat() if d else None


# ── Async fetcher ──────────────────────────────────────────────────────────

class CertspotterFetcher:

    BASE_URL = "https://api.certspotter.com/v1/issuances"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def fetch(
        self,
        domain: str,
        include_subdomains: bool = True,
        max_pages: int = 20,
    ) -> list[dict]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent":    "datazag-cert-pipeline/1.0",
        }
        params = {
            "domain":             domain,
            "include_subdomains": "true" if include_subdomains else "false",
            "expand":             ["dns_names", "issuer", "cert"],
            "limit":              1000,
        }

        records  = []
        after_id = None
        page     = 0

        async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
            while page < max_pages:
                if after_id:
                    params["after"] = after_id

                resp = await client.get(self.BASE_URL, params=params)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    print(f"  Certspotter rate limited — waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    continue

                resp.raise_for_status()
                batch = resp.json()

                if not batch:
                    break

                records.extend(batch)
                after_id = batch[-1]["id"]
                page    += 1
                print(f"  Certspotter page {page}: "
                      f"{len(batch)} records (total: {len(records)})")

        return records


# ── Normalise to list of dicts ─────────────────────────────────────────────

def normalise(records: list[dict], root_domain: str) -> list[dict]:
    """
    Flatten raw Certspotter records into a list of dicts.
    One dict per (cert_id, dns_name) — SANs exploded.
    All dates are ISO strings — no date objects, fully JSON-safe.
    """
    today = date.today()
    rows  = []

    for rec in records:
        issuer_dn       = rec.get("issuer", {})
        issuer_org      = issuer_dn.get("organization", "") or ""
        issuer_cn       = issuer_dn.get("common_name", "")  or ""
        issuer_category = _classify_issuer(issuer_org, issuer_cn)

        not_before = _parse_date(rec.get("not_before"))
        not_after  = _parse_date(rec.get("not_after"))
        logged_at  = _parse_date(rec.get("logged_at"))

        validity_days  = (not_after - not_before).days if not_before and not_after else None
        days_remaining = (not_after - today).days      if not_after else None
        is_expired     = (days_remaining < 0)          if days_remaining is not None else False

        dns_names   = rec.get("dns_names", []) or []
        san_count   = len(dns_names)
        cert_id     = str(rec.get("id", ""))

        tbs         = rec.get("tbs_summary", {}) or {}
        cns         = tbs.get("common_names", [])
        common_name = cns[0] if isinstance(cns, list) and cns else ""

        for dns_name in dns_names:
            rows.append({
                "cert_id":          cert_id,
                "logged_at":        _fmt(logged_at),
                "not_before":       _fmt(not_before),
                "not_after":        _fmt(not_after),
                "common_name":      common_name,
                "dns_name":         dns_name.lower(),
                "is_wildcard":      dns_name.startswith("*."),
                "issuer_org":       issuer_org,
                "issuer_cn":        issuer_cn,
                "issuer_category":  issuer_category,
                "validity_days":    validity_days,
                "days_remaining":   days_remaining,
                "is_expired":       is_expired,
                "san_count":        san_count,
            })

    return rows


# ── Analysis ───────────────────────────────────────────────────────────────

class CertAnalysis:
    """
    All methods return lists of dicts — directly JSON-serialisable.
    """

    def __init__(self, rows: list[dict], root_domain: str):
        self.rows  = rows
        self.root  = root_domain.lower()
        self.today = date.today()

        # Deduplicate on (cert_id, dns_name)
        seen = set()
        self._deduped = []
        for r in rows:
            key = (r["cert_id"], r["dns_name"])
            if key not in seen:
                seen.add(key)
                self._deduped.append(r)

        # Latest cert per subdomain (highest not_after, excluding wildcards)
        latest_map: dict[str, dict] = {}
        for r in self._deduped:
            if r["is_wildcard"]:
                continue
            name = r["dns_name"]
            if name not in latest_map or (
                r["not_after"] and (
                    not latest_map[name]["not_after"] or
                    r["not_after"] > latest_map[name]["not_after"]
                )
            ):
                latest_map[name] = r

        self._latest = list(latest_map.values())

    def subdomain_corpus(self) -> list[dict]:
        results = [
            {
                "dns_name":        r["dns_name"],
                "not_before":      r["not_before"],
                "not_after":       r["not_after"],
                "days_remaining":  r["days_remaining"],
                "is_expired":      r["is_expired"],
                "issuer_category": r["issuer_category"],
                "issuer_cn":       r["issuer_cn"],
                "san_count":       r["san_count"],
                "logged_at":       r["logged_at"],
            }
            for r in self._latest
            if r["dns_name"] != self.root
        ]
        return sorted(
            results,
            key=lambda x: (x["days_remaining"] is None, x["days_remaining"] or 0)
        )

    def wildcard_zones(self) -> list[dict]:
        seen = set()
        results = []
        for r in sorted(self._deduped, key=lambda x: x["not_after"] or "", reverse=True):
            if not r["is_wildcard"] or r["dns_name"] in seen:
                continue
            seen.add(r["dns_name"])
            results.append({
                "dns_name":        r["dns_name"],
                "not_before":      r["not_before"],
                "not_after":       r["not_after"],
                "days_remaining":  r["days_remaining"],
                "issuer_category": r["issuer_category"],
                "san_count":       r["san_count"],
            })
        return results

    def issuer_distribution(self) -> list[dict]:
        counts: dict[str, int] = defaultdict(int)
        for r in self._latest:
            counts[r["issuer_category"]] += 1
        total = sum(counts.values()) or 1
        return sorted(
            [
                {
                    "issuer_category": cat,
                    "subdomain_count": cnt,
                    "pct":             round(cnt / total * 100, 1),
                }
                for cat, cnt in counts.items()
            ],
            key=lambda x: x["subdomain_count"],
            reverse=True,
        )

    def expiring_soon(self, days: int = 60) -> list[dict]:
        results = [
            {
                "dns_name":        r["dns_name"],
                "not_after":       r["not_after"],
                "days_remaining":  r["days_remaining"],
                "issuer_category": r["issuer_category"],
                "issuer_cn":       r["issuer_cn"],
            }
            for r in self._latest
            if not r["is_wildcard"]
            and r["days_remaining"] is not None
            and 0 <= r["days_remaining"] <= days
        ]
        return sorted(results, key=lambda x: x["days_remaining"])

    def expired(self) -> list[dict]:
        results = [
            {
                "dns_name":        r["dns_name"],
                "not_after":       r["not_after"],
                "days_remaining":  r["days_remaining"],
                "issuer_category": r["issuer_category"],
            }
            for r in self._latest
            if r["is_expired"]
        ]
        return sorted(results, key=lambda x: x["days_remaining"] or 0)

    def missed_renewals(self) -> list[dict]:
        today_str = self.today.isoformat()
        results = []
        for r in self._latest:
            if not r["not_after"] or r["is_expired"]:
                continue
            try:
                expiry           = date.fromisoformat(r["not_after"])
                expected_renewal = (expiry - timedelta(days=60)).isoformat()
                if expected_renewal < today_str:
                    results.append({
                        "dns_name":         r["dns_name"],
                        "not_after":        r["not_after"],
                        "expected_renewal": expected_renewal,
                        "days_remaining":   r["days_remaining"],
                        "issuer_category":  r["issuer_category"],
                    })
            except Exception:
                continue
        return sorted(results, key=lambda x: x["days_remaining"] or 0)

    def cert_churn(self, lookback_days: int = 120, threshold: int = 8) -> list[dict]:
        cutoff = (self.today - timedelta(days=lookback_days)).isoformat()
        counts: dict[str, int] = defaultdict(int)
        for r in self._deduped:
            if r["logged_at"] and r["logged_at"] >= cutoff:
                counts[r["dns_name"]] += 1
        return sorted(
            [
                {"dns_name": name, "cert_count": count}
                for name, count in counts.items()
                if count >= threshold
            ],
            key=lambda x: x["cert_count"],
            reverse=True,
        )

    def cross_domain_sans(self) -> list[dict]:
        seen = set()
        results = []
        for r in sorted(self._deduped, key=lambda x: x["not_after"] or "", reverse=True):
            name = r["dns_name"]
            if (
                self.root not in name
                and self.root not in r.get("common_name", "")
                and name not in seen
            ):
                seen.add(name)
                results.append({
                    "dns_name":        name,
                    "common_name":     r["common_name"],
                    "not_before":      r["not_before"],
                    "not_after":       r["not_after"],
                    "issuer_category": r["issuer_category"],
                    "cert_id":         r["cert_id"],
                })
        return results

    def cn_anomalies(self) -> list[dict]:
        seen = set()
        results = []
        for r in sorted(self._deduped, key=lambda x: x["not_after"] or "", reverse=True):
            cn   = r.get("common_name", "")
            name = r["dns_name"]
            if cn and self.root not in cn and name not in seen:
                seen.add(name)
                results.append({
                    "dns_name":    name,
                    "common_name": cn,
                    "issuer_cn":   r["issuer_cn"],
                    "not_before":  r["not_before"],
                    "not_after":   r["not_after"],
                })
        return results

    def summary(self) -> dict:
        return {
            "total_unique_subdomains": len(self.subdomain_corpus()),
            "wildcard_zones":          len(self.wildcard_zones()),
            "expiring_within_30d":     len(self.expiring_soon(30)),
            "expiring_within_60d":     len(self.expiring_soon(60)),
            "expired":                 len(self.expired()),
            "missed_renewals":         len(self.missed_renewals()),
            "cross_domain_sans":       len(self.cross_domain_sans()),
            "cn_anomalies":            len(self.cn_anomalies()),
            "high_churn_subdomains":   len(self.cert_churn()),
            "issuer_breakdown":        self.issuer_distribution(),
        }


# ── Cache helpers ──────────────────────────────────────────────────────────

def _cache_path(domain: str, cache_dir: str) -> Path:
    return Path(cache_dir) / f"{domain.replace('.', '_')}_certs.json"


def _load_cache(path: Path, max_age_days: int = 7) -> Optional[list[dict]]:
    if not path.exists():
        return None
    age_days = (datetime.now().timestamp() - path.stat().st_mtime) / 86400
    if age_days > max_age_days:
        path.unlink()
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _save_cache(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(rows, f)


# ── Top-level pipeline ─────────────────────────────────────────────────────

class CertPipeline:

    def __init__(self, api_key: str):
        self.fetcher = CertspotterFetcher(api_key)

    async def run(
        self,
        domain: str,
        cache_dir: str = "./cert_cache",
        max_cache_age_days: int = 7,
    ) -> dict:
        cache = _cache_path(domain, cache_dir)
        rows  = _load_cache(cache, max_cache_age_days)

        if rows is not None:
            print(f"  Certspotter — loaded from cache ({len(rows)} rows)")
        else:
            records = await self.fetcher.fetch(domain)
            rows    = normalise(records, domain)
            _save_cache(cache, rows)
            print(f"  Certspotter — {len(records)} certs, "
                  f"{len(rows)} rows after SAN explosion")

        analysis = CertAnalysis(rows, domain)

        subdomains = [
            {
                "dns_name":        s["dns_name"],
                "a_records":       [],
                "source":          "certspotter",
                "is_expired":      s["is_expired"],
                "days_remaining":  s["days_remaining"],
                "issuer_category": s["issuer_category"],
            }
            for s in analysis.subdomain_corpus()
        ]

        return {
            "subdomains": subdomains,
            "cert_analysis": {
                "summary":           analysis.summary(),
                "wildcard_zones":    analysis.wildcard_zones(),
                "issuer_breakdown":  analysis.issuer_distribution(),
                "expiring_soon":     analysis.expiring_soon(60),
                "expired":           analysis.expired(),
                "missed_renewals":   analysis.missed_renewals(),
                "cert_churn":        analysis.cert_churn(),
                "cross_domain_sans": analysis.cross_domain_sans(),
                "cn_anomalies":      analysis.cn_anomalies(),
            },
        }


# ── Integration helper ─────────────────────────────────────────────────────

async def fetch_certspotter_subdomains(
    domain: str,
    api_key: Optional[str] = None,
    cache_dir: Optional[str] = None,
) -> dict:
    """
    Drop-in for asyncio.create_task() in compile_pure_dns_report.
    Returns {"subdomains": [...], "cert_analysis": {...}}.
    """
    key      = api_key or os.environ.get("CERTSPOTTER_API_KEY", "")
    cache    = cache_dir or os.environ.get("CERT_CACHE_DIR", "./cert_cache")
    pipeline = CertPipeline(api_key=key)
    return await pipeline.run(domain, cache_dir=cache)


# ── Demo ───────────────────────────────────────────────────────────────────

async def get_subdomains():
    result  = await fetch_certspotter_subdomains("example.com")
    summary = result["cert_analysis"]["summary"]
    print(f"\n── Summary ──")
    for k, v in summary.items():
        if k != "issuer_breakdown":
            print(f"  {k:30} {v}")
    print(f"\n── First 5 subdomains ──")
    for sub in result["subdomains"][:5]:
        print(f"  {sub['dns_name']}")


if __name__ == "__main__":
    asyncio.run(get_subdomains())
