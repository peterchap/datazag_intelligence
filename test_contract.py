# test_contract.py — run against a known domain
import asyncio, json
from dotenv import load_dotenv
load_dotenv()

async def test_against_known_domain():
    from dns_report import compile_pure_dns_report

    # Use a domain where you know the expected values
    domain = "adaptavist.com"  # or any domain you've previously run
    raw    = await compile_pure_dns_report(domain)

    # Save full output for inspection
    with open(f"/tmp/{domain}_test_output.json", "w") as f:
        json.dump(raw, f, indent=2, default=str)
    print(f"Full output saved to /tmp/{domain}_test_output.json")

    # Spot-check values you know should be true
    dns = raw["dns_profile"]

    # Should have MX records
    mx = dns["records"].get("MX", {}).get("raw", [])
    print(f"MX records:    {mx}")
    assert mx, "No MX records found"

    # DMARC should be present for Adaptavist
    dmarc = dns.get("dmarc_auth", {})
    print(f"DMARC:         {dmarc.get('raw', 'NOT FOUND')}")

    # Subdomains from Certspotter
    subs = raw["subdomains"]
    print(f"Subdomains:    {len(subs)} total")
    print(f"Sample:        {[s['dns_name'] for s in subs[:5]]}")

    # RDAP data
    rdap = raw["rdap"]
    print(f"Registrar:     {rdap.get('registrar_name')}")
    print(f"Age:           {rdap.get('domain_age_days')} days")
    print(f"DNSSEC:        {rdap.get('dnssec_enabled')}")

if __name__ == "__main__":
    asyncio.run(test_against_known_domain())