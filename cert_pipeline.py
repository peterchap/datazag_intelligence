import asyncio
import httpx
import os
from datetime import datetime, timezone
from datetime import datetime, timezone

async def fetch_certspotter_subdomains(domain: str) -> dict:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"
    token = os.environ.get("CERTSPOTTER_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=15.0)
            if resp.status_code != 200:
                print(f"Certspotter HTTP {resp.status_code}")
                return {"subdomains": [], "cert_analysis": {}}
            
            data = resp.json()
            subdomains = []
            seen = set()
            
            expired = []
            
            now = datetime.now(timezone.utc)
            
            for item in data:
                names = item.get("dns_names", [])
                
                not_after_str = item.get("not_after", "")
                is_expired = False
                days_remaining = None
                
                if not_after_str:
                    try:
                        dt = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                        days_remaining = (dt - now).days
                        is_expired = days_remaining < 0
                    except:
                        pass
                
                for name in names:
                    name = name.lstrip("*.")
                    if name.endswith(domain) and name not in seen:
                        seen.add(name)
                        
                        sub = {
                            "dns_name": name,
                            "source": "certspotter",
                            "is_expired": is_expired,
                            "days_remaining": days_remaining
                        }
                        subdomains.append(sub)
                        
                        if is_expired:
                            expired.append(sub)
                        
            return {
                "subdomains": subdomains,
                "cert_analysis": {
                    "summary": {
                        "total_unique_subdomains": len(subdomains),
                        "expired": len(expired),
                    },
                    "expired": expired
                }
            }
    except Exception as e:
        print(f"Certspotter Error: {e}")
        return {"subdomains": [], "cert_analysis": {}}
