"""
Shodan enrichment for infrastructure health reports.

Three distinct use cases:

1. IP enrichment — for each resolved subdomain IP, fetch open ports,
   services, banners, and CVEs. Adds the service exposure findings
   that HTTP headers alone can't provide.

2. Favicon hash pivot — given a brand's MMH3 favicon hash, find every
   other host Shodan has seen serving the same favicon. Primary signal
   for phishing kit reuse and brand impersonation infrastructure.

3. Domain DNS — Shodan's passive DNS for subdomains and historical
   resolution data. Complements Certspotter with resolution history.

API credit cost guidance:
  - Host lookup (/shodan/host/{ip}): 1 query credit each
  - Search query (favicon hash, port scan): 1 query credit per call
  - DNS domain (/dns/domain/{domain}): free, no credits
  - Batch host lookup: 1 credit per IP still, but fewer HTTP calls

Cache resolved IPs aggressively — Shodan data for a given IP changes
slowly. A 7-day TTL is reasonable for port/service data.
"""

import asyncio
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Optional

import httpx
import polars as pl


# ── High-risk port / service definitions ──────────────────────────────────

HIGH_RISK_PORTS = {
    # Port: (service_name, severity, plain_english_risk)
    21:    ("FTP",              "elevated", "Unencrypted file transfer — credentials transmitted in plaintext"),
    22:    ("SSH",              "info",     "Remote shell access exposed — verify key-only auth, no password login"),
    23:    ("Telnet",           "critical", "Unencrypted remote shell — retire immediately"),
    25:    ("SMTP",             "elevated", "Mail server exposed — verify not an open relay"),
    80:    ("HTTP",             "info",     "Unencrypted web traffic — verify HTTPS redirect in place"),
    110:   ("POP3",             "elevated", "Unencrypted mail retrieval"),
    143:   ("IMAP",             "elevated", "Unencrypted mail access"),
    389:   ("LDAP",             "critical", "Directory service exposed — authentication infrastructure accessible"),
    445:   ("SMB",              "critical", "Windows file sharing exposed — common ransomware vector"),
    1433:  ("MSSQL",            "critical", "Database port exposed — should not be internet-facing"),
    1521:  ("Oracle DB",        "critical", "Database port exposed — should not be internet-facing"),
    2375:  ("Docker API",       "critical", "Docker daemon exposed without TLS — full container takeover possible"),
    2376:  ("Docker TLS",       "elevated", "Docker daemon exposed — verify certificate pinning"),
    3306:  ("MySQL",            "critical", "Database port exposed — should not be internet-facing"),
    3389:  ("RDP",              "critical", "Remote desktop exposed — primary ransomware entry point"),
    4369:  ("Erlang Port",      "critical", "Erlang port mapper exposed — RabbitMQ/CouchDB attack surface"),
    5432:  ("PostgreSQL",       "critical", "Database port exposed — should not be internet-facing"),
    5900:  ("VNC",              "critical", "Remote desktop exposed — often unauthenticated"),
    5984:  ("CouchDB",          "critical", "Database admin interface exposed"),
    6379:  ("Redis",            "critical", "Redis exposed — commonly unauthenticated, full data access"),
    6443:  ("Kubernetes API",   "critical", "Kubernetes control plane exposed"),
    7474:  ("Neo4j",            "critical", "Graph database exposed"),
    8080:  ("HTTP Alt",         "elevated", "Alternative HTTP — may be dev/admin interface"),
    8443:  ("HTTPS Alt",        "elevated", "Alternative HTTPS — verify what service is running"),
    8888:  ("Jupyter",          "critical", "Jupyter notebook — arbitrary code execution if unauthenticated"),
    9000:  ("SonarQube/PHP-FPM","elevated", "Dev tooling or PHP process manager exposed"),
    9200:  ("Elasticsearch",    "critical", "Elasticsearch exposed — commonly unauthenticated, full data access"),
    9300:  ("Elasticsearch",    "critical", "Elasticsearch cluster comms exposed"),
    11211: ("Memcached",        "critical", "Cache server exposed — data exfiltration and amplification attacks"),
    27017: ("MongoDB",          "critical", "Database port exposed — commonly unauthenticated"),
    27018: ("MongoDB",          "critical", "Database shard exposed"),
    50070: ("Hadoop HDFS",      "critical", "Hadoop namenode web UI exposed"),
}

MANAGEMENT_PORTS = {
    # Ports that signal internal-only tooling exposed to internet
    8080, 8443, 8888, 9000, 9090, 9200, 9300,
    4848,   # GlassFish admin
    8161,   # ActiveMQ admin
    15672,  # RabbitMQ management
    16379,  # Redis Sentinel
    5601,   # Kibana
    3000,   # Grafana / dev servers
    4200,   # Angular dev
    3001,   # React dev
}


# ── Data classes ───────────────────────────────────────────────────────────

@dataclass
class ShodanPortFinding:
    port:           int
    protocol:       str
    service:        Optional[str]
    banner:         Optional[str]
    severity:       str
    plain_english:  str
    cpes:           list[str] = field(default_factory=list)
    cves:           list[str] = field(default_factory=list)


@dataclass
class ShodanHostProfile:
    """
    Shodan data for a single resolved IP.
    Covers ports, services, CVEs, and geolocation.
    """
    ip:                 str
    subdomain:          Optional[str] = None  # Which subdomain resolved here

    # Location
    country:            Optional[str] = None
    city:               Optional[str] = None
    org:                Optional[str] = None
    isp:                Optional[str] = None
    asn:                Optional[str] = None

    # Ports and services
    open_ports:         list[int] = field(default_factory=list)
    port_findings:      list[ShodanPortFinding] = field(default_factory=list)

    # Vulnerabilities
    cves:               list[str] = field(default_factory=list)
    vuln_count:         int = 0

    # Summary scores
    critical_port_count: int = 0
    management_exposed:  bool = False

    # Metadata
    last_seen:          Optional[str] = None
    shodan_score:       Optional[int] = None  # Shodan's own score if present
    error:              Optional[str] = None
    from_cache:         bool = False


@dataclass
class FaviconPivotResult:
    """
    Results of a Shodan favicon hash pivot.
    Finds other hosts using the same favicon as the target brand.
    """
    mmh3_hash:          int
    total_matches:      int = 0
    matches:            list[dict] = field(default_factory=list)
    # Each match: {ip, port, hostname, org, country, last_seen}
    suspicious:         list[dict] = field(default_factory=list)
    # Suspicious = matches not on known CDN/cloud ASNs
    error:              Optional[str] = None


# ── Known hosting providers to filter from favicon pivot ──────────────────

KNOWN_HOSTING_ASNS = {
    # Major cloud and CDN providers — legitimate to serve the same favicon
    # (e.g. Cloudflare caches it, AWS CloudFront serves it from multiple PoPs)
    "AS13335",  # Cloudflare
    "AS15169",  # Google
    "AS8075",   # Microsoft Azure
    "AS14618",  # Amazon AWS
    "AS16509",  # Amazon AWS
    "AS20940",  # Akamai
    "AS54113",  # Fastly
    "AS32934",  # Meta
    "AS2906",   # Netflix
}


# ── Shodan API client ──────────────────────────────────────────────────────

class ShodanClient:

    BASE = "https://api.shodan.io"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=15.0)
        return self

    async def __aexit__(self, *_):
        if self._client:
            await self._client.aclose()

    async def _get(self, path: str, params: dict = None) -> dict:
        p = {"key": self.api_key}
        if params:
            p.update(params)
        resp = await self._client.get(f"{self.BASE}{path}", params=p)
        resp.raise_for_status()
        return resp.json()

    async def host(self, ip: str) -> dict:
        """Fetch all Shodan data for a single IP. Costs 1 query credit."""
        return await self._get(f"/shodan/host/{ip}")

    async def search(self, query: str, limit: int = 20) -> dict:
        """Run a Shodan search query. Costs 1 query credit."""
        return await self._get(
            "/shodan/host/search",
            {"query": query, "limit": limit}
        )

    async def dns_domain(self, domain: str) -> dict:
        """Shodan passive DNS for a domain. Free — no credit cost."""
        return await self._get(f"/dns/domain/{domain}")

    async def count(self, query: str) -> int:
        """Count matches for a query without fetching results. Free."""
        data = await self._get("/shodan/host/count", {"query": query})
        return data.get("total", 0)


# ── IP enrichment ──────────────────────────────────────────────────────────

def _parse_host_response(ip: str, data: dict, subdomain: str = None) -> ShodanHostProfile:
    """Parse a Shodan host response into a structured profile."""
    profile = ShodanHostProfile(
        ip=ip,
        subdomain=subdomain,
        country=data.get("country_name"),
        city=data.get("city"),
        org=data.get("org"),
        isp=data.get("isp"),
        asn=data.get("asn"),
        open_ports=sorted(data.get("ports", [])),
        last_seen=data.get("last_update"),
    )

    # Collect all CVEs across all services
    all_cves = set()
    if "vulns" in data:
        all_cves.update(data["vulns"].keys())
    profile.cves = sorted(all_cves)
    profile.vuln_count = len(all_cves)

    # Analyse each port/service
    for service in data.get("data", []):
        port     = service.get("port", 0)
        protocol = service.get("transport", "tcp")
        product  = service.get("product", "")
        banner   = (service.get("data", "") or "")[:200]

        # Service-level CVEs
        svc_cves = list((service.get("vulns") or {}).keys())
        cpes     = service.get("cpe", []) or []

        if port in HIGH_RISK_PORTS:
            _, severity, plain_english = HIGH_RISK_PORTS[port]

            # Escalate severity if CVEs are present on this port
            if svc_cves and severity == "elevated":
                severity = "critical"

            profile.port_findings.append(ShodanPortFinding(
                port=port,
                protocol=protocol,
                service=product or HIGH_RISK_PORTS[port][0],
                banner=banner.strip() or None,
                severity=severity,
                plain_english=plain_english,
                cpes=cpes,
                cves=svc_cves,
            ))

        if port in MANAGEMENT_PORTS:
            profile.management_exposed = True

    # Summary counts
    profile.critical_port_count = sum(
        1 for f in profile.port_findings if f.severity == "critical"
    )

    return profile


async def enrich_ips(
    ip_subdomain_pairs: list[tuple[str, str]],
    client: ShodanClient,
    semaphore: asyncio.Semaphore,
) -> list[ShodanHostProfile]:
    """
    Enrich a list of (ip, subdomain) pairs with Shodan host data.
    Deduplicates IPs — if two subdomains resolve to the same IP,
    only one Shodan call is made.
    """
    # Deduplicate IPs, keeping first subdomain association
    seen_ips: dict[str, str] = {}
    for ip, subdomain in ip_subdomain_pairs:
        if ip not in seen_ips:
            seen_ips[ip] = subdomain

    async def fetch_one(ip: str, subdomain: str) -> ShodanHostProfile:
        async with semaphore:
            try:
                data = await client.host(ip)
                return _parse_host_response(ip, data, subdomain)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    # IP not in Shodan index — not an error
                    return ShodanHostProfile(
                        ip=ip, subdomain=subdomain,
                        error="not_in_shodan"
                    )
                return ShodanHostProfile(
                    ip=ip, subdomain=subdomain,
                    error=f"http_{e.response.status_code}"
                )
            except Exception as e:
                return ShodanHostProfile(
                    ip=ip, subdomain=subdomain,
                    error=str(e)[:100]
                )

    tasks = [
        fetch_one(ip, subdomain)
        for ip, subdomain in seen_ips.items()
    ]
    return await asyncio.gather(*tasks)


# ── Favicon pivot ──────────────────────────────────────────────────────────

async def favicon_pivot(
    mmh3_hash: int,
    client: ShodanClient,
    limit: int = 50,
    exclude_known_hosting: bool = True,
) -> FaviconPivotResult:
    """
    Find all hosts Shodan has seen serving a given favicon hash.
    Filters out known CDN/cloud providers to surface suspicious matches.
    """
    result = FaviconPivotResult(mmh3_hash=mmh3_hash)
    query  = f"http.favicon.hash:{mmh3_hash}"

    try:
        # Get count first (free)
        result.total_matches = await client.count(query)

        if result.total_matches == 0:
            return result

        # Fetch actual matches (costs 1 credit)
        data = await client.search(query, limit=limit)

        for match in data.get("matches", []):
            ip_str  = match.get("ip_str", "")
            port    = match.get("port", 443)
            hostnames = match.get("hostnames", [])
            org     = match.get("org", "")
            country = match.get("location", {}).get("country_name", "")
            asn     = match.get("asn", "")
            last    = match.get("timestamp", "")

            entry = {
                "ip":         ip_str,
                "port":       port,
                "hostnames":  hostnames,
                "org":        org,
                "country":    country,
                "asn":        asn,
                "last_seen":  last[:10] if last else None,
                "shodan_url": f"https://www.shodan.io/host/{ip_str}",
            }
            result.matches.append(entry)

            # Flag as suspicious if not on a known major hosting provider
            if exclude_known_hosting:
                asn_tag = f"AS{asn}" if asn and not str(asn).startswith("AS") else str(asn)
                if asn_tag not in KNOWN_HOSTING_ASNS:
                    result.suspicious.append(entry)
            else:
                result.suspicious = result.matches

    except Exception as e:
        result.error = str(e)[:200]

    return result


# ── Report section builders ────────────────────────────────────────────────

def build_port_exposure_section(
    profiles: list[ShodanHostProfile],
) -> dict:
    """
    Aggregate port and service findings across all enriched IPs.
    Returns structured data for the report's service exposure section.
    """
    all_findings = []
    critical_findings = []
    all_cves = set()
    management_subdomains = []

    for p in profiles:
        if p.error:
            continue

        for f in p.port_findings:
            finding = {
                "severity":     f.severity,
                "code":         f"PORT_{f.port}_EXPOSED",
                "title":        f"{f.service} exposed on {p.subdomain or p.ip}",
                "port":         f.port,
                "protocol":     f.protocol,
                "service":      f.service,
                "ip":           p.ip,
                "subdomain":    p.subdomain,
                "detail":       f.plain_english,
                "cves":         f.cves,
                "banner":       f.banner,
                # Plain English for exec summary
                "exec_detail":  _port_plain_english(f, p),
            }
            all_findings.append(finding)
            if f.severity == "critical":
                critical_findings.append(finding)
            all_cves.update(f.cves)

        if p.management_exposed:
            management_subdomains.append(p.subdomain or p.ip)

    # Sort: critical first, then by port number
    all_findings.sort(key=lambda x: (0 if x["severity"] == "critical" else 1, x["port"]))

    # CVE summary
    cve_list = sorted(all_cves)

    return {
        "total_findings":       len(all_findings),
        "critical_count":       len(critical_findings),
        "findings":             all_findings,
        "cves_found":           cve_list,
        "cve_count":            len(cve_list),
        "management_subdomains": management_subdomains,
        # Exec summary — only the most impactful findings
        "exec_findings":        [f for f in all_findings if f["severity"] == "critical"][:5],
    }


def _port_plain_english(f: ShodanPortFinding, p: ShodanHostProfile) -> str:
    """Generate plain English description for the exec summary layer."""
    base = f.plain_english

    if f.cves:
        cve_count = len(f.cves)
        base += (
            f" Additionally, {cve_count} known {'vulnerability' if cve_count == 1 else 'vulnerabilities'} "
            f"({'CVE: ' + f.cves[0] if cve_count == 1 else 'including ' + f.cves[0]}) "
            f"found on this service."
        )

    if p.subdomain:
        base = f"Port {f.port} ({f.service}) is open on {p.subdomain}. {base}"
    else:
        base = f"Port {f.port} ({f.service}) is open on {p.ip}. {base}"

    return base


def build_favicon_pivot_section(
    pivot: FaviconPivotResult,
    brand_domain: str,
) -> dict:
    """
    Format favicon pivot results for the report.
    """
    if pivot.error:
        return {"error": pivot.error, "findings": []}

    findings = []

    if pivot.total_matches == 0:
        findings.append({
            "severity": "info",
            "code":     "FAVICON_NO_MATCHES",
            "title":    "No other hosts found serving this favicon",
            "detail":   f"Shodan has not indexed any other hosts using the "
                        f"same favicon hash as {brand_domain}. "
                        f"No external phishing infrastructure detected via this signal.",
        })

    elif pivot.suspicious:
        findings.append({
            "severity": "critical" if len(pivot.suspicious) > 2 else "elevated",
            "code":     "FAVICON_SUSPICIOUS_HOSTS",
            "title":    f"Brand favicon detected on {len(pivot.suspicious)} unrelated host(s)",
            "detail":   (
                f"Shodan found {pivot.total_matches} host(s) serving the same favicon as {brand_domain}. "
                f"{len(pivot.suspicious)} of these are on infrastructure not associated with known "
                f"CDN or cloud providers — indicating potential phishing or brand impersonation sites "
                f"copying the brand's visual identity."
            ),
            "matches":  pivot.suspicious[:10],
            "shodan_query": f"http.favicon.hash:{pivot.mmh3_hash}",
        })

    elif pivot.total_matches > 0:
        # All matches are on known hosting providers — likely CDN/cache
        findings.append({
            "severity": "info",
            "code":     "FAVICON_CDN_ONLY",
            "title":    f"Favicon found on {pivot.total_matches} host(s) — all major providers",
            "detail":   (
                f"Shodan found {pivot.total_matches} host(s) serving this favicon, "
                f"all attributable to major CDN or cloud providers. "
                f"This is consistent with normal CDN caching behaviour, not impersonation."
            ),
        })

    return {
        "mmh3_hash":        pivot.mmh3_hash,
        "total_matches":    pivot.total_matches,
        "suspicious_count": len(pivot.suspicious),
        "shodan_query":     f"http.favicon.hash:{pivot.mmh3_hash}",
        "shodan_url":       f"https://www.shodan.io/search?query=http.favicon.hash:{pivot.mmh3_hash}",
        "findings":         findings,
        "suspicious_hosts": pivot.suspicious[:10],
    }


# ── Polars output ──────────────────────────────────────────────────────────

def profiles_to_dataframe(profiles: list[ShodanHostProfile]) -> pl.DataFrame:
    """Flatten Shodan host profiles into a Polars DataFrame."""
    rows = []
    for p in profiles:
        rows.append({
            "ip":                   p.ip,
            "subdomain":            p.subdomain,
            "country":              p.country,
            "org":                  p.org,
            "asn":                  p.asn,
            "open_ports":           json.dumps(p.open_ports),
            "critical_port_count":  p.critical_port_count,
            "management_exposed":   p.management_exposed,
            "cve_count":            p.vuln_count,
            "cves":                 json.dumps(p.cves),
            "finding_count":        len(p.port_findings),
            "findings_json":        json.dumps([
                {
                    "port":     f.port,
                    "service":  f.service,
                    "severity": f.severity,
                    "detail":   f.plain_english,
                    "cves":     f.cves,
                }
                for f in p.port_findings
            ]),
            "last_seen":            p.last_seen,
            "error":                p.error,
        })
    return pl.DataFrame(rows)


# ── Top-level report pipeline ──────────────────────────────────────────────

async def enrich_report_with_shodan(
    domain: str,
    ip_subdomain_pairs: list[tuple[str, str]],
    favicon_mmh3: Optional[int],
    api_key: str,
    ip_concurrency: int = 5,
) -> dict:
    """
    Main entry point. Given resolved IPs and the brand favicon hash,
    returns all Shodan enrichment data ready for the report.

    ip_subdomain_pairs: [(ip, subdomain), ...] from your A record resolution
    favicon_mmh3: the MMH3 hash from http_enrichment.py favicon fetch
    """
    semaphore = asyncio.Semaphore(ip_concurrency)

    async with ShodanClient(api_key) as client:
        tasks = []

        # IP enrichment — deduplicated
        ip_task = asyncio.create_task(
            enrich_ips(ip_subdomain_pairs, client, semaphore)
        )
        tasks.append(("ips", ip_task))

        # Favicon pivot — only if we have the hash
        if favicon_mmh3 is not None:
            fav_task = asyncio.create_task(
                favicon_pivot(favicon_mmh3, client)
            )
            tasks.append(("favicon", fav_task))

        # Await all
        results = {}
        for name, task in tasks:
            results[name] = await task

    # Build report sections
    ip_profiles  = results.get("ips", [])
    fav_result   = results.get("favicon")

    port_section = build_port_exposure_section(ip_profiles)
    fav_section  = (
        build_favicon_pivot_section(fav_result, domain)
        if fav_result else None
    )

    return {
        "port_exposure":    port_section,
        "favicon_pivot":    fav_section,
        "ip_profiles":      profiles_to_dataframe(ip_profiles),
        "raw_profiles":     ip_profiles,
    }


# ── Demo ───────────────────────────────────────────────────────────────────

async def demo():
    """
    Demo using synthetic data — no real API key needed.
    Shows the structure of output and finding generation.
    """
    # Simulate a Shodan host response for a risky subdomain
    synthetic_host = {
        "ip_str":       "203.0.113.42",
        "org":          "ACME Corp Hosting",
        "isp":          "SomeISP",
        "asn":          "AS64496",
        "country_name": "United Kingdom",
        "city":         "London",
        "ports":        [22, 443, 3306, 6379, 9200],
        "last_update":  "2026-04-18T09:00:00.000Z",
        "vulns":        {
            "CVE-2024-1234": {"cvss": 9.8},
            "CVE-2023-5678": {"cvss": 7.5},
        },
        "data": [
            {
                "port": 3306, "transport": "tcp",
                "product": "MySQL", "data": "MySQL 5.7.39\n",
                "vulns": {"CVE-2024-1234": {"cvss": 9.8}},
                "cpe": ["cpe:/a:mysql:mysql:5.7.39"],
            },
            {
                "port": 6379, "transport": "tcp",
                "product": "Redis", "data": "+PONG\r\n",
                "vulns": {},
            },
            {
                "port": 9200, "transport": "tcp",
                "product": "Elasticsearch",
                "data": '{"name":"node-1","cluster_name":"prod-cluster"}',
                "vulns": {"CVE-2023-5678": {"cvss": 7.5}},
            },
            {
                "port": 22, "transport": "tcp",
                "product": "OpenSSH",
                "data": "SSH-2.0-OpenSSH_8.9p1\r\n",
            },
        ],
    }

    profile = _parse_host_response(
        "203.0.113.42", synthetic_host, subdomain="api.acme-corp.com"
    )

    port_section = build_port_exposure_section([profile])

    print("── Port exposure section ──")
    print(f"Total findings:    {port_section['total_findings']}")
    print(f"Critical findings: {port_section['critical_count']}")
    print(f"CVEs found:        {port_section['cves_found']}")
    print(f"Management exposed: {port_section['management_subdomains']}")
    print()

    for f in port_section["findings"]:
        print(f"[{f['severity'].upper():8}] Port {f['port']:5} — {f['service']}")
        print(f"            {f['detail']}")
        if f["cves"]:
            print(f"            CVEs: {', '.join(f['cves'])}")
        print()

    print("── Exec summary findings ──")
    for f in port_section["exec_findings"]:
        print(f"  CRITICAL: {f['exec_detail'][:100]}")

    # Favicon pivot demo
    synthetic_pivot = FaviconPivotResult(
        mmh3_hash = -1234567890,
        total_matches = 3,
        matches = [
            {"ip": "104.21.10.1",  "port": 443, "org": "Cloudflare", "asn": "13335", "country": "US"},
            {"ip": "185.220.101.5","port": 443, "org": "Shady Hosting Ltd", "asn": "99999", "country": "RU"},
            {"ip": "92.118.160.10","port": 443, "org": "Bulletproof VPS", "asn": "88888", "country": "NL"},
        ],
        suspicious = [
            {"ip": "185.220.101.5", "port": 443, "org": "Shady Hosting Ltd", "asn": "99999", "country": "RU"},
            {"ip": "92.118.160.10", "port": 443, "org": "Bulletproof VPS",   "asn": "88888", "country": "NL"},
        ],
    )

    fav_section = build_favicon_pivot_section(synthetic_pivot, "acme-corp.com")
    print("\n── Favicon pivot section ──")
    print(f"Total matches:    {fav_section['total_matches']}")
    print(f"Suspicious hosts: {fav_section['suspicious_count']}")
    print(f"Shodan URL:       {fav_section['shodan_url']}")
    for f in fav_section["findings"]:
        print(f"\n[{f['severity'].upper():8}] {f['title']}")
        print(f"  {f['detail']}")


if __name__ == "__main__":
    asyncio.run(demo())
