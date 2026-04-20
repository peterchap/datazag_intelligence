"""
Report generation pipeline — integrates all enrichment modules.

Execution order:
  1. Fresh DNS fetch + subdomain corpus (parallel)
  2. Root domain HTTP enrichment (parallel with step 1)
  3. Subdomain HTTP enrichment (after step 1 — needs live A records)
  4. Prefix/ASN scoring (after step 1 — needs resolved IPs)
  5. Shodan enrichment (after step 3 — needs IPs + favicon MMH3)
  6. Certspotter cert analysis (parallel with step 1)
  7. Assemble report sections

Total wall time target: 15-25 seconds for a domain like Adaptavist.
Dominated by Certspotter fetch and Shodan API calls.
"""

import asyncio
import os
from dataclasses import dataclass, field
from typing import Optional

import duckdb

from http_enrichment import (
    HTTPEnrichmentResult,
    enrich_subdomains_batch,
    build_header_report_section,
    results_to_dataframe,
)
from shodan_enrichment import (
    enrich_report_with_shodan,
    build_port_exposure_section,
    build_favicon_pivot_section,
)


# ── Report structure ───────────────────────────────────────────────────────

@dataclass
class ReportSection:
    """A single section of the infrastructure report."""
    id:             str
    title:          str
    score:          float = 0.0
    severity:       str = "info"      # critical / elevated / low / info / pass
    findings:       list[dict] = field(default_factory=list)
    data:           dict = field(default_factory=dict)
    exec_summary:   str = ""          # Plain English for underwriter layer
    available:      bool = True       # False if data source unavailable


@dataclass
class InfrastructureReport:
    """Complete infrastructure intelligence report for a domain."""
    domain:         str
    generated_at:   str
    overall_score:  float = 0.0
    overall_severity: str = "info"

    # Report sections — ordered as they appear in the document
    sections:       list[ReportSection] = field(default_factory=list)

    # Raw data for downstream use (JSON API response)
    raw:            dict = field(default_factory=dict)


# ── Target selection for HTTP enrichment ──────────────────────────────────

SENSITIVE_PREFIXES = {
    "payment", "pay", "login", "auth", "account", "admin",
    "portal", "secure", "checkout", "signin", "id", "sso",
}


def build_http_targets(
    domain: str,
    dns_data: dict,
    subdomains: list[dict],
    limit: int = 50,
) -> list[str]:
    """
    Build ordered list of targets for HTTP enrichment.
    Priority: root domain → sensitive subdomains → core production.
    Excludes staff sandboxes and dynamic DNS subdomains.
    """
    targets = []

    # Root domain always first
    if dns_data.get("a_records"):
        targets.append(domain)

    # Sensitive subdomains — always included regardless of cap
    sensitive = [
        s["dns_name"] for s in subdomains
        if s.get("a_records") and any(
            kw in s["dns_name"].split(".")[0].lower()
            for kw in SENSITIVE_PREFIXES
        )
    ]
    targets.extend(sensitive)

    # Core production — exclude staff sandboxes and dyn DNS
    production = [
        s["dns_name"] for s in subdomains
        if s.get("a_records")
        and s["dns_name"] not in sensitive
        and s["dns_name"] != domain
        and "staff." not in s["dns_name"]
        and ".dyn." not in s["dns_name"]
        and "sandbox" not in s["dns_name"].lower()
        and s["dns_name"].count(".") == (domain.count(".") + 1)
    ]
    targets.extend(production)

    # Deduplicate preserving order
    seen = set()
    ordered = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)

    return ordered[:limit]


def extract_ip_subdomain_pairs(
    http_results: list[HTTPEnrichmentResult],
    dns_data: dict,
    domain: str,
) -> list[tuple[str, str]]:
    """
    Extract (ip, subdomain) pairs for Shodan enrichment.
    Skips CDN IPs — Shodan data for Cloudflare/Fastly IPs is not
    useful for per-domain service exposure analysis.
    """
    CDN_ASNS = {"cloudflare", "fastly", "akamai", "aws_cloudfront",
                 "vercel", "netlify", "azure_cdn", "google_cloud"}

    pairs = []
    for result in http_results:
        if result.cdn_detected in CDN_ASNS:
            continue
        # Get resolved IPs from DNS data
        sub_dns = next(
            (s for s in [{"dns_name": domain, **dns_data}]
             if s.get("dns_name") == result.subdomain),
            None
        )
        if sub_dns and sub_dns.get("a_records"):
            for ip in sub_dns["a_records"]:
                pairs.append((ip, result.subdomain))

    return pairs


# ── Section builders ───────────────────────────────────────────────────────

def build_http_header_section(
    http_results: list[HTTPEnrichmentResult],
) -> ReportSection:
    """Build the HTTP security headers report section."""
    import polars as pl
    df = results_to_dataframe(http_results)
    live_df = df.filter(pl.col("reachable"))
    summary = build_header_report_section(live_df)

    # Overall severity from findings
    severities = [f["severity"] for f in summary["findings"]]
    severity = (
        "critical"  if "critical"  in severities else
        "elevated"  if "elevated"  in severities else
        "low"       if "low"       in severities else
        "pass"
    )

    # Exec summary
    lines = []
    if summary["hsts_coverage_pct"] < 50:
        lines.append(
            f"HTTPS enforcement (HSTS) is missing on "
            f"{100 - summary['hsts_coverage_pct']:.0f}% of web-facing subdomains."
        )
    if summary["csp_coverage_pct"] < 30:
        lines.append(
            "Most web pages have no browser-level protection against script injection."
        )
    if summary["server_disclosures"] > 0:
        lines.append(
            f"Server software versions are publicly disclosed on "
            f"{summary['server_disclosures']} subdomains."
        )

    return ReportSection(
        id="http_headers",
        title="HTTP security headers",
        score=sum(r.header_score for r in http_results),
        severity=severity,
        findings=summary["findings"],
        data=summary,
        exec_summary=" ".join(lines) if lines else
             "HTTP security header configuration is adequate.",
    )


def build_port_exposure_report_section(shodan_result: dict) -> ReportSection:
    """Build the service exposure section from Shodan port data."""
    section_data = shodan_result.get("port_exposure", {})
    findings     = section_data.get("findings", [])
    cves         = section_data.get("cves_found", [])
    critical     = section_data.get("critical_count", 0)

    severity = (
        "critical" if critical > 0 else
        "elevated" if findings  else
        "pass"
    )

    # Score — 3pts per critical finding, 1pt per elevated
    score = sum(
        3 if f["severity"] == "critical" else
        1 if f["severity"] == "elevated" else 0
        for f in findings
    )

    # Exec summary
    lines = []
    if critical > 0:
        services = list({f["service"] for f in findings if f["severity"] == "critical"})
        lines.append(
            f"{critical} critical service(s) are exposed to the internet "
            f"({', '.join(services[:3])}) and should not be externally accessible."
        )
    if cves:
        lines.append(
            f"{len(cves)} known {'vulnerability' if len(cves)==1 else 'vulnerabilities'} "
            f"identified on exposed services "
            f"({'including ' + cves[0] if cves else ''})."
        )
    if section_data.get("management_subdomains"):
        lines.append(
            "Internal management interfaces are accessible from the internet."
        )

    return ReportSection(
        id="port_exposure",
        title="Service and port exposure",
        score=score,
        severity=severity,
        findings=findings,
        data=section_data,
        exec_summary=" ".join(lines) if lines else
             "No unexpectedly exposed services detected.",
    )


def build_favicon_pivot_report_section(
    shodan_result: dict,
    domain: str,
) -> ReportSection:
    """Build the brand favicon pivot section from Shodan data."""
    fav_data    = shodan_result.get("favicon_pivot")
    if not fav_data:
        return ReportSection(
            id="favicon_pivot",
            title="Brand favicon monitoring",
            available=False,
            exec_summary="Favicon hash not captured — section unavailable.",
        )

    findings    = fav_data.get("findings", [])
    suspicious  = fav_data.get("suspicious_count", 0)

    severity = (
        "critical" if suspicious > 2 else
        "elevated" if suspicious > 0 else
        "info"
    )
    score = suspicious * 2.0

    # Exec summary
    if suspicious > 0:
        exec_summary = (
            f"The brand's visual identity (favicon) has been detected on "
            f"{suspicious} unrelated host(s) not associated with known hosting providers. "
            f"This is a strong indicator of active phishing or brand impersonation infrastructure."
        )
    else:
        exec_summary = (
            "No external hosts found reproducing the brand's favicon. "
            "No phishing infrastructure detected via this signal."
        )

    return ReportSection(
        id="favicon_pivot",
        title="Brand favicon monitoring",
        score=score,
        severity=severity,
        findings=findings,
        data=fav_data,
        exec_summary=exec_summary,
    )


# ── Main report pipeline ───────────────────────────────────────────────────

async def generate_domain_report(
    domain: str,
    con: duckdb.DuckDBPyConnection,
    shodan_api_key: Optional[str] = None,
    prefix_table: str = "prefixes",
) -> InfrastructureReport:
    """
    Full report generation pipeline.

    Steps run in parallel where possible:
    - DNS + subdomains + root HTTP all start simultaneously
    - Subdomain HTTP runs after DNS (needs live A records)
    - Shodan runs after HTTP (needs IPs and favicon MMH3)
    - Certspotter runs in parallel with everything
    """
    from datetime import datetime, timezone
    generated_at = datetime.now(timezone.utc).isoformat()

    # ── Step 1: Parallel initial fetch ────────────────────────────────────
    # DNS, subdomains, and root domain HTTP all start at the same time.
    # Root domain HTTP runs immediately — we don't need subdomain data for it.

    dns_task        = asyncio.create_task(_fresh_dns_fetch(domain))
    subdomain_task  = asyncio.create_task(_get_subdomain_corpus(domain))
    root_http_task  = asyncio.create_task(
        enrich_subdomains_batch(
            [domain],
            concurrency=1,
            fetch_favicon=True,
            fetch_page=True,
        )
    )
    cert_task       = asyncio.create_task(_get_cert_analysis(domain))

    dns_data, subdomains, root_http, cert_data = await asyncio.gather(
        dns_task, subdomain_task, root_http_task, cert_task
    )

    # ── Step 2: Subdomain HTTP enrichment ─────────────────────────────────
    # Now we have live A records from DNS — build the target list.

    targets = build_http_targets(domain, dns_data, subdomains, limit=50)
    # Root domain already enriched — skip it in subdomain pass
    sub_targets = [t for t in targets if t != domain]

    sub_http = await enrich_subdomains_batch(
        sub_targets,
        concurrency=20,
        fetch_favicon=True,
        fetch_page=False,    # Page content only for root domain
    )

    all_http = root_http + sub_http

    # ── Step 3: Prefix/ASN scoring ────────────────────────────────────────
    prefix_section = await asyncio.to_thread(
        _score_dns_prefix_risk, dns_data, subdomains, con, prefix_table
    )

    # ── Step 4: Shodan enrichment ─────────────────────────────────────────
    # Needs IPs from HTTP enrichment + favicon MMH3 from root domain HTTP.

    shodan_result = None
    if shodan_api_key:
        ip_pairs = extract_ip_subdomain_pairs(all_http, dns_data, domain)

        # Favicon MMH3 from the root domain HTTP result
        root_favicon_mmh3 = (
            root_http[0].favicon.mmh3
            if root_http and root_http[0].favicon.found
            else None
        )

        shodan_result = await enrich_report_with_shodan(
            domain=domain,
            ip_subdomain_pairs=ip_pairs,
            favicon_mmh3=root_favicon_mmh3,
            api_key=shodan_api_key,
            ip_concurrency=5,       # Conservative — Shodan rate limits
        )

    # ── Step 5: Assemble sections ──────────────────────────────────────────

    sections = []

    # DNS and email security (from existing pipeline)
    sections.append(_build_dns_section(dns_data, domain))
    sections.append(_build_email_section(dns_data))

    # Subdomain attack surface
    sections.append(_build_subdomain_section(subdomains, domain))

    # Certificate intelligence
    sections.append(_build_cert_section(cert_data))

    # Infrastructure / BGP risk
    sections.append(prefix_section)

    # HTTP security headers
    sections.append(build_http_header_section(all_http))

    # Shodan sections — conditional on API key
    if shodan_result:
        sections.append(build_port_exposure_report_section(shodan_result))
        sections.append(build_favicon_pivot_report_section(shodan_result, domain))
    else:
        sections.append(ReportSection(
            id="port_exposure",
            title="Service and port exposure",
            available=False,
            exec_summary="Shodan API key not configured — section unavailable.",
        ))
        sections.append(ReportSection(
            id="favicon_pivot",
            title="Brand favicon monitoring",
            available=False,
            exec_summary="Shodan API key not configured — section unavailable.",
        ))

    # ── Step 6: Overall score ──────────────────────────────────────────────

    total_score = sum(s.score for s in sections if s.available)
    overall_severity = (
        "critical" if any(s.severity == "critical" for s in sections) else
        "elevated" if any(s.severity == "elevated" for s in sections) else
        "low"      if any(s.severity == "low"      for s in sections) else
        "pass"
    )

    return InfrastructureReport(
        domain=domain,
        generated_at=generated_at,
        overall_score=round(total_score, 2),
        overall_severity=overall_severity,
        sections=sections,
        raw={
            "dns":      dns_data,
            "http":     [vars(r) for r in all_http],
            "shodan":   shodan_result or {},
            "certs":    cert_data,
            "prefixes": prefix_section.data,
        },
    )


# ── Stub functions (replace with your actual implementations) ──────────────

async def _fresh_dns_fetch(domain: str) -> dict:
    """Replace with your existing DNS resolver."""
    await asyncio.sleep(0)
    return {
        "domain":       domain,
        "a_records":    ["93.184.216.34"],
        "mx_records":   [(10, "aspmx.l.google.com")],
        "ns_records":   ["ns1.example.com", "ns2.example.com"],
        "dmarc_policy": "reject",
        "spf_record":   "v=spf1 include:_spf.google.com ~all",
        "txt_records":  [],
    }


async def _get_subdomain_corpus(domain: str) -> list[dict]:
    """Replace with your Certspotter + brute force subdomain enumeration."""
    await asyncio.sleep(0)
    return []


async def _get_cert_analysis(domain: str) -> dict:
    """Replace with your Certspotter CertAnalysis pipeline."""
    await asyncio.sleep(0)
    return {}


def _score_dns_prefix_risk(
    dns_data: dict,
    subdomains: list[dict],
    con: duckdb.DuckDBPyConnection,
    prefix_table: str,
) -> ReportSection:
    """Replace with your prefix/ASN scoring from the prefix table."""
    return ReportSection(
        id="infrastructure_risk",
        title="Infrastructure and routing risk",
        score=0.0,
        severity="info",
        findings=[],
        data={},
        exec_summary="BGP prefix risk analysis complete.",
    )


# ── Placeholder section builders ───────────────────────────────────────────
# Replace these with your existing section builders as you integrate.

def _build_dns_section(dns_data: dict, domain: str) -> ReportSection:
    findings = []
    score = 0.0

    if dns_data.get("dmarc_policy") in (None, "none", "absent"):
        findings.append({
            "severity": "critical",
            "code":     "DMARC_ABSENT_OR_NONE",
            "title":    "DMARC policy absent or set to none",
            "detail":   f"{domain} can be freely spoofed for email fraud. "
                        f"No enforcement action is taken on failing messages.",
        })
        score += 3.0

    severity = "critical" if score >= 3 else "elevated" if score > 0 else "pass"
    return ReportSection(
        id="dns_email_security",
        title="DNS and email security",
        score=score,
        severity=severity,
        findings=findings,
        data=dns_data,
        exec_summary=(
            f"{domain} has no DMARC enforcement — email from this domain cannot be verified "
            "and can be freely forged by attackers."
            if score >= 3 else
            "Email authentication configuration is adequate."
        ),
    )


def _build_email_section(dns_data: dict) -> ReportSection:
    return ReportSection(
        id="email_infrastructure",
        title="Email infrastructure",
        score=0.0,
        severity="info",
        findings=[],
        data=dns_data,
        exec_summary="Email infrastructure analysis complete.",
    )


def _build_subdomain_section(subdomains: list[dict], domain: str) -> ReportSection:
    count = len(subdomains)
    return ReportSection(
        id="subdomain_attack_surface",
        title="Subdomain attack surface",
        score=0.0,
        severity="info",
        findings=[],
        data={"subdomain_count": count},
        exec_summary=f"{count} subdomains identified across the {domain} estate.",
    )


def _build_cert_section(cert_data: dict) -> ReportSection:
    return ReportSection(
        id="certificate_intelligence",
        title="Certificate intelligence",
        score=0.0,
        severity="info",
        findings=[],
        data=cert_data,
        exec_summary="Certificate analysis complete.",
    )


# ── Report output helpers ──────────────────────────────────────────────────

def report_to_dict(report: InfrastructureReport) -> dict:
    """Serialise report to a dict for JSON API response or storage."""
    return {
        "domain":           report.domain,
        "generated_at":     report.generated_at,
        "overall_score":    report.overall_score,
        "overall_severity": report.overall_severity,
        "sections":         [
            {
                "id":           s.id,
                "title":        s.title,
                "score":        s.score,
                "severity":     s.severity,
                "findings":     s.findings,
                "exec_summary": s.exec_summary,
                "available":    s.available,
                "data":         s.data,
            }
            for s in report.sections
        ],
    }


def print_report_summary(report: InfrastructureReport):
    """Print a readable summary of the report to stdout."""
    print(f"\n{'='*60}")
    print(f"  Infrastructure Report — {report.domain}")
    print(f"  Generated: {report.generated_at}")
    print(f"  Overall:   {report.overall_severity.upper()} (score: {report.overall_score})")
    print(f"{'='*60}\n")

    for section in report.sections:
        if not section.available:
            print(f"  [{section.id}] — unavailable")
            continue

        sev_label = {
            "critical": "CRIT",
            "elevated": "ELEV",
            "low":      "LOW ",
            "info":     "INFO",
            "pass":     "PASS",
        }.get(section.severity, "????")

        print(f"  [{sev_label}] {section.title} (score: {section.score})")

        if section.findings:
            for f in section.findings[:3]:
                sev = f.get("severity", "info").upper()[:4]
                title = f.get("title", "")[:60]
                print(f"         [{sev}] {title}")
            if len(section.findings) > 3:
                print(f"         ... and {len(section.findings)-3} more findings")

        if section.exec_summary:
            print(f"         → {section.exec_summary[:100]}")
        print()


# ── Demo ───────────────────────────────────────────────────────────────────

async def demo():
    """
    Demo run without a real DuckDB connection or Shodan API key.
    Shows the report structure and section assembly.
    Shodan section will be marked unavailable without an API key.
    """
    con = duckdb.connect(":memory:")

    # Set SHODAN_API_KEY env var to test with real Shodan data
    shodan_key = os.environ.get("SHODAN_API_KEY")

    report = await generate_domain_report(
        domain="example.com",
        con=con,
        shodan_api_key=shodan_key,
    )

    print_report_summary(report)

    import json
    print("── JSON output (first section) ──")
    d = report_to_dict(report)
    print(json.dumps(d["sections"][0], indent=2))


if __name__ == "__main__":
    asyncio.run(demo())
