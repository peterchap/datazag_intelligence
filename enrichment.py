"""
enrichment.py — HTTP and Shodan enrichment bridge for run.py

Sits between passive_security_findings_v2() and enrich_with_narrative()
in the existing pipeline. Takes the parsed canonical record and raw JSON,
returns two new output dict sections:

    output["http_enrichment"]   — headers, CSP, HSTS, server disclosure
    output["shodan_enrichment"] — port exposure, favicon pivot

Both are optional and fail gracefully — if HTTP times out or Shodan
key is not set, the sections are present but marked available=False.

Usage in run.py:

    from enrichment import enrich_http_and_shodan

    # After passive findings, before narrative:
    http_section, shodan_section = await enrich_http_and_shodan(
        domain=domain,
        record=record,
        raw=raw,
        shodan_api_key=os.environ.get("SHODAN_API_KEY"),
    )
    output["http_enrichment"]  = http_section
    output["shodan_enrichment"] = shodan_section

    # The findings lists are merged into the main findings list so the
    # narrative and renderer see them automatically:
    findings.extend(http_section.get("findings", []))
    findings.extend(shodan_section.get("findings", []))
"""

import asyncio
import json
from typing import Optional, Any


# ── HTTP enrichment imports ────────────────────────────────────────────────

try:
    from http_enrichment import (
        enrich_subdomains_batch,
        build_header_report_section,
        results_to_dataframe,
    )
    import polars as pl
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False


# ── Shodan enrichment imports ──────────────────────────────────────────────

try:
    from shodan_enrichment import (
        enrich_report_with_shodan,
    )
    SHODAN_MODULE_AVAILABLE = True
except ImportError:
    SHODAN_MODULE_AVAILABLE = False


# ── CDN ASNs to skip for Shodan (shared IPs, not useful per-domain) ────────

CDN_ASNS = {
    "cloudflare", "fastly", "akamai", "aws_cloudfront",
    "vercel", "netlify", "azure_cdn", "google_cloud", "sucuri",
}

SENSITIVE_PREFIXES = {
    "payment", "pay", "login", "auth", "account", "admin",
    "portal", "secure", "checkout", "signin", "id", "sso", "api",
}


# ── Target extraction from existing DNS record ─────────────────────────────

def _extract_http_targets(domain: str, record: Any, limit: int = 50) -> list[str]:
    """
    Build ordered target list for HTTP enrichment from the canonical record.
    Unlike report_pipeline.py we don't do a fresh DNS fetch — we use what
    the corpus already resolved.

    Priority: root domain → sensitive subdomains → core production.
    """
    targets = []

    # Root domain — always first if it has an A record
    if record.a_records:
        targets.append(domain)

    # Subdomains from the corpus record if present
    # The canonical record may have a subdomains list depending on your adapter
    subdomains = getattr(record, "subdomains", []) or []

    sensitive = []
    production = []

    for sub in subdomains:
        # sub may be a string or a dict with dns_name
        name = sub if isinstance(sub, str) else sub.get("dns_name", "")
        if not name or name == domain:
            continue

        prefix = name.split(".")[0].lower()

        if prefix in SENSITIVE_PREFIXES:
            sensitive.append(name)
        elif (
            "staff." not in name
            and ".dyn." not in name
            and "sandbox" not in name.lower()
        ):
            production.append(name)

    targets.extend(sensitive)
    targets.extend(production)

    # Deduplicate preserving order
    seen = set()
    ordered = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)

    return ordered[:limit]


def _extract_ip_pairs(
    domain: str,
    record: Any,
    http_results: list,
) -> list[tuple[str, str]]:
    """
    Extract (ip, subdomain) pairs for Shodan enrichment.
    Uses A records from the canonical record.
    Skips CDN IPs — Shodan data for shared CDN IPs is not useful per-domain.
    """
    pairs = []

    # Build a name → IPs index from the record
    ip_map: dict[str, list[str]] = {}

    # Root domain IPs
    if record.a_records:
        ip_map[domain] = list(record.a_records)

    # Subdomains
    for sub in getattr(record, "subdomains", []) or []:
        name = sub if isinstance(sub, str) else sub.get("dns_name", "")
        ips  = [] if isinstance(sub, str) else (sub.get("a_records") or [])
        if name and ips:
            ip_map[name] = list(ips)

    # Match against HTTP results, skip CDN subdomains
    for result in http_results:
        if result.cdn_detected in CDN_ASNS:
            continue
        ips = ip_map.get(result.subdomain, [])
        for ip in ips:
            pairs.append((ip, result.subdomain))

    # If no HTTP results matched, fall back to root domain IPs directly
    if not pairs and record.a_records:
        for ip in record.a_records:
            pairs.append((ip, domain))

    # Deduplicate by IP (one Shodan call per IP regardless of subdomain count)
    seen_ips: dict[str, str] = {}
    deduped = []
    for ip, sub in pairs:
        if ip not in seen_ips:
            seen_ips[ip] = sub
            deduped.append((ip, sub))

    return deduped


# ── HTTP section builder ───────────────────────────────────────────────────

def _build_http_section(http_results: list) -> dict:
    """
    Build the http_enrichment output section from HTTP results.
    Returns a dict that slots directly into output["http_enrichment"].
    """
    if not http_results:
        return {
            "available": False,
            "reason":    "No live subdomains to enrich",
            "findings":  [],
        }

    try:
        df = results_to_dataframe(http_results)
        live_df = df.filter(pl.col("reachable"))
        summary = build_header_report_section(live_df)
    except Exception as e:
        return {
            "available": False,
            "reason":    f"Header aggregation failed: {str(e)[:100]}",
            "findings":  [],
        }

    # Normalise findings to match the existing findings schema in run.py
    # run.py uses: severity, category, label, description
    normalised_findings = []
    for f in summary.get("findings", []):
        sev_map = {
            "critical": "critical",
            "elevated": "high",
            "low":      "medium",
            "info":     "low",
            "pass":     "low",
        }

        # Build evidence from available fields
        sub       = f.get("subdomain", "")
        pct       = f.get("pct") or f.get("coverage_pct")
        count     = f.get("count") or f.get("affected_count")
        sample    = f.get("sample") or f.get("affected", [])
        sample_str = ", ".join(sample[:3]) if isinstance(sample, list) else str(sample or "")

        evidence_parts = []
        if count is not None:
            evidence_parts.append(f"{count} subdomains affected")
        if pct is not None:
            evidence_parts.append(f"{pct}% coverage")
        if sample_str:
            evidence_parts.append(f"Sample: {sample_str}")
        if sub:
            evidence_parts.append(f"Subdomain: {sub}")
        evidence = " — ".join(evidence_parts) if evidence_parts else (f.get("detail", "") or "")[:120]

        normalised_findings.append({
            # finding key is required for deduplication in run.py
            "finding":     f.get("code", ""),
            "severity":    sev_map.get(f.get("severity", "low"), "low"),
            "category":    "http_security",
            "title":       f.get("title", ""),
            "evidence":    evidence,
            "detail":      f.get("detail") or f.get("description", ""),
            "remediation": f.get("remediation") or f.get("fix", ""),
            # Renderer extras
            "subdomain":   sub,
            "csp_value":   f.get("csp_value"),
        })

    # Per-subdomain detail for the technical report section
    per_subdomain = []
    for r in http_results:
        if not r.reachable:
            continue
        per_subdomain.append({
            "subdomain":         r.subdomain,
            "status_code":       r.status_code,
            "cdn":               r.cdn_detected,
            "hsts":              r.hsts_present,
            "hsts_max_age":      r.hsts_max_age,
            "hsts_includes_sub": r.hsts_includes_sub,
            "csp_present":       r.csp_present,
            "csp_value":         r.csp_value,
            "x_frame_options":   r.x_frame_options,
            "x_content_type":    r.x_content_type,
            "server":            r.server_header,
            "x_powered_by":      r.x_powered_by,
            "header_score":      r.header_score,
            "is_sensitive":      r.is_sensitive,
            "favicon_mmh3":      r.favicon.mmh3     if r.favicon else None,
            "favicon_md5":       r.favicon.md5      if r.favicon else None,
            "favicon_found":     r.favicon.found    if r.favicon else False,
        })

    return {
        "available":            True,
        "total_live":           summary.get("total_live", 0),
        "hsts_coverage_pct":    summary.get("hsts_coverage_pct", 0),
        "csp_coverage_pct":     summary.get("csp_coverage_pct", 0),
        "xfo_coverage_pct":     summary.get("xfo_coverage_pct", 0),
        "server_disclosures":   summary.get("server_disclosures", 0),
        "favicon_clusters":     summary.get("favicon_clusters", 0),
        "cdn_breakdown":        summary.get("cdn_breakdown", []),
        "worst_subdomains":     summary.get("worst_subdomains", []),
        "per_subdomain":        per_subdomain,
        "findings":             normalised_findings,
        # Raw for renderer access
        "_summary":             summary,
        "_http_results":        [
            {k: v for k, v in vars(r).items()
             if k not in ("raw_headers", "redirect_chain", "findings")}
            for r in http_results
        ],
    }


# ── Shodan section builder ─────────────────────────────────────────────────

def _build_shodan_section(shodan_result: dict, domain: str) -> dict:
    """
    Build the shodan_enrichment output section.
    Normalises Shodan findings to the run.py findings schema.
    """
    if not shodan_result:
        return {
            "available": False,
            "reason":    "Shodan API key not configured",
            "findings":  [],
        }

    port_data = shodan_result.get("port_exposure", {})
    fav_data  = shodan_result.get("favicon_pivot")

    normalised_findings = []

    # Port exposure findings
    for f in port_data.get("findings", []):
        sev_map = {"critical": "critical", "elevated": "high",
                   "low": "medium", "info": "low"}
        normalised_findings.append({
            "severity":    sev_map.get(f.get("severity", "low"), "low"),
            "category":    "port_exposure",
            "label":       f.get("code", f"PORT_{f.get('port','')}_EXPOSED"),
            "description": f.get("exec_detail") or f.get("detail", ""),
            "title":       f.get("title", ""),
            "port":        f.get("port"),
            "service":     f.get("service"),
            "cves":        f.get("cves", []),
            "subdomain":   f.get("subdomain"),
        })

    # Favicon pivot findings
    if fav_data:
        for f in fav_data.get("findings", []):
            sev_map = {"critical": "critical", "elevated": "high",
                       "info": "low"}
            normalised_findings.append({
                "severity":    sev_map.get(f.get("severity", "low"), "low"),
                "category":    "brand_protection",
                "label":       f.get("code", "FAVICON_PIVOT"),
                "description": f.get("detail", ""),
                "title":       f.get("title", ""),
                "shodan_query": fav_data.get("shodan_query"),
            })

    return {
        "available":            True,

        # Port exposure summary
        "port_findings_count":  port_data.get("total_findings", 0),
        "critical_ports":       port_data.get("critical_count", 0),
        "cves_found":           port_data.get("cves_found", []),
        "cve_count":            port_data.get("cve_count", 0),
        "management_exposed":   port_data.get("management_subdomains", []),
        "port_findings":        port_data.get("findings", []),

        # Favicon pivot summary
        "favicon_pivot":        fav_data,
        "favicon_suspicious":   (fav_data or {}).get("suspicious_count", 0),

        # Merged findings for main findings list
        "findings":             normalised_findings,
    }


# ── Main enrichment entry point ────────────────────────────────────────────

async def enrich_http_and_shodan(
    domain: str,
    record: Any,
    raw: dict,
    shodan_api_key: Optional[str] = None,
    http_concurrency: int = 20,
    http_timeout: float = 8.0,
) -> tuple[dict, dict]:
    """
    Main entry point for run.py integration.

    Returns (http_section, shodan_section) — both dicts are safe to assign
    directly into output["http_enrichment"] and output["shodan_enrichment"].

    Each section has a "findings" list using the run.py schema
    (severity / category / label / description) ready to extend the
    main findings list.

    Fails gracefully — on any error, returns sections with available=False.
    """
    http_section    = {"available": False, "findings": []}
    shodan_section  = {"available": False, "findings": []}

    # ── HTTP enrichment ────────────────────────────────────────────────────

    if not HTTP_AVAILABLE:
        http_section["reason"] = "http_enrichment module not found"
    else:
        try:
            targets = _extract_http_targets(domain, record)

            if targets:
                print(f"  HTTP enrichment — {len(targets)} targets...")
                http_results = await enrich_subdomains_batch(
                    targets,
                    concurrency=http_concurrency,
                    fetch_favicon=True,
                    fetch_page=(domain in targets),  # Full page only for root
                    timeout=http_timeout,
                )
                http_section = _build_http_section(http_results)

                live_count = sum(1 for r in http_results if r.reachable)
                print(f"  HTTP — {live_count}/{len(targets)} live, "
                      f"{len(http_section.get('findings', []))} findings")
            else:
                http_section = {
                    "available": False,
                    "reason":    "No A records — domain not live",
                    "findings":  [],
                }

        except Exception as e:
            http_section = {
                "available": False,
                "reason":    f"HTTP enrichment error: {str(e)[:200]}",
                "findings":  [],
            }
            print(f"  HTTP enrichment failed: {e}")

    # ── Shodan enrichment ──────────────────────────────────────────────────

    if not SHODAN_MODULE_AVAILABLE:
        shodan_section["reason"] = "shodan_enrichment module not found"

    elif not shodan_api_key:
        shodan_section["reason"] = "SHODAN_API_KEY not set"

    else:
        try:
            # Extract IP pairs from record + HTTP results
            http_results_for_shodan = []
            if http_section.get("available") and HTTP_AVAILABLE:
                # Re-run to get full result objects — or pull from _http_results
                # For now use the IPs directly from the record
                pass

            ip_pairs = _extract_ip_pairs(domain, record, http_results_for_shodan)

            # Favicon MMH3 — from HTTP enrichment if available
            favicon_mmh3 = None
            if http_section.get("available"):
                for sub_data in http_section.get("per_subdomain", []):
                    if sub_data.get("subdomain") == domain and sub_data.get("favicon_mmh3"):
                        favicon_mmh3 = sub_data["favicon_mmh3"]
                        break

            if ip_pairs or favicon_mmh3:
                print(f"  Shodan enrichment — {len(ip_pairs)} IPs"
                      f"{', favicon pivot' if favicon_mmh3 else ''}...")

                result = await enrich_report_with_shodan(
                    domain=domain,
                    ip_subdomain_pairs=ip_pairs,
                    favicon_mmh3=favicon_mmh3,
                    api_key=shodan_api_key,
                    ip_concurrency=5,
                )
                shodan_section = _build_shodan_section(result, domain)

                print(f"  Shodan — {shodan_section.get('critical_ports', 0)} critical "
                      f"ports, {shodan_section.get('cve_count', 0)} CVEs, "
                      f"{shodan_section.get('favicon_suspicious', 0)} suspicious favicon matches")
            else:
                shodan_section = {
                    "available": False,
                    "reason":    "No IP addresses to enrich",
                    "findings":  [],
                }

        except Exception as e:
            shodan_section = {
                "available": False,
                "reason":    f"Shodan enrichment error: {str(e)[:200]}",
                "findings":  [],
            }
            print(f"  Shodan enrichment failed: {e}")

    return http_section, shodan_section
