# test_integrations.py
import asyncio
import os
from dotenv import load_dotenv
load_dotenv()

async def test_certspotter():
    """Should return subdomains and cert analysis without error."""
    from cert_pipeline import fetch_certspotter_subdomains
    result = await fetch_certspotter_subdomains("example.com")

    assert "subdomains"    in result
    assert "cert_analysis" in result
    assert "summary"       in result["cert_analysis"]

    summary = result["cert_analysis"]["summary"]
    print(f"  subdomains:     {summary['total_unique_subdomains']}")
    print(f"  wildcard zones: {summary['wildcard_zones']}")
    print(f"  missed renewals:{summary['missed_renewals']}")
    return result

async def test_rdap():
    """Should return structured registration data."""
    from rdap_lookup import rdap_lookup_async
    result = await rdap_lookup_async("example.com")

    assert "rdap_available"  in result
    assert "domain_age_days" in result
    assert "registrar_name"  in result

    print(f"  available:      {result['rdap_available']}")
    print(f"  age (days):     {result['domain_age_days']}")
    print(f"  registrar:      {result['registrar_name']}")
    print(f"  DNSSEC:         {result['dnssec_enabled']}")
    print(f"  rdap risk:      {result['rdap_risk_score']}")
    return result

async def test_http_enrichment():
    """Should return header and favicon data for a live domain."""
    from http_enrichment import enrich_subdomains_batch, results_to_dataframe
    import polars as pl

    results = await enrich_subdomains_batch(
        ["example.com"],
        concurrency=1,
        fetch_favicon=True,
        fetch_page=False,
    )
    assert len(results) == 1
    r = results[0]

    print(f"  reachable:      {r.reachable}")
    print(f"  status:         {r.status_code}")
    print(f"  hsts:           {r.hsts_present}")
    print(f"  csp:            {r.csp_present}")
    print(f"  cdn:            {r.cdn_detected}")
    print(f"  favicon mmh3:   {r.favicon.mmh3 if r.favicon else None}")
    print(f"  header score:   {r.header_score}")
    return results

async def test_full_pipeline_no_pyarrow():
    """
    Full compile_pure_dns_report on a known domain.
    Skips PyArrow (PIPELINE_MODULES_AVAILABLE=False in test env).
    Validates the output contract that run.py expects.
    """
    from dns_report import compile_pure_dns_report
    raw = await compile_pure_dns_report("example.com")

    # Top-level keys run.py reads
    required_keys = [
        "domain", "scanned_at_utc", "dns_profile",
        "subdomains", "cert_analysis", "rdap",
        "https_cert_ok", "has_security_txt",
        "smtp_cert_ok", "domain_age_days",
        "bgp_routing", "ip_reputation",
        "infrastructure_concentration", "certificate_intelligence",
        "geolocation_jurisdiction", "historical_velocity",
        "abuse_contact_quality", "web_security", "active_scanning",
    ]
    missing = [k for k in required_keys if k not in raw]
    if missing:
        print(f"  MISSING KEYS: {missing}")
    assert not missing

    # Spot-check specific values
    assert raw["domain"] == "example.com"
    assert isinstance(raw["subdomains"], list)
    assert isinstance(raw["rdap"], dict)
    assert "summary" in raw.get("cert_analysis", {})

    print(f"  domain:         {raw['domain']}")
    print(f"  subdomains:     {len(raw['subdomains'])}")
    print(f"  rdap available: {raw['rdap'].get('rdap_available')}")
    print(f"  https ok:       {raw['https_cert_ok']}")
    print(f"  age days:       {raw['domain_age_days']}")
    return raw

async def main():
    tests = [
        ("certspotter",       test_certspotter),
        ("rdap",              test_rdap),
        ("http_enrichment",   test_http_enrichment),
        ("full_pipeline",     test_full_pipeline_no_pyarrow),
    ]
    for name, test_fn in tests:
        print(f"\n── {name} ──")
        try:
            await test_fn()
            print(f"PASS  {name}")
        except Exception as e:
            print(f"FAIL  {name}: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())