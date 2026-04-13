# narrative.py
import os
import json
import aiohttp
from typing import Optional

async def enrich_with_narrative(
    domain: str,
    score: int,
    risk_band: str,
    findings: list[dict],
    saas_stack: list[str],
    email_auth_summary: str,
    partner_context: Optional[str] = None,
    threat_context: Optional[str] = None,
    audience: str = "insurer",
) -> dict:
    
    AUDIENCE_TONE = {
        "insurer":    "a cyber insurance underwriter assessing policy risk",
        "consultant": "a security consultant preparing a client briefing",
        "it":         "an IT security manager reviewing their own infrastructure",
        "sales":      "a sales team preparing a prospect outreach brief",
    }

    top_findings = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']}: {f.get('detail','')[:150]}"
        for f in sorted(findings, key=lambda x: 
            ["critical","high","medium","info"].index(x.get("severity","info"))
        )[:6]
    )

    prompt = f"""You are producing a DNS intelligence brief for {AUDIENCE_TONE[audience]}.

Domain: {domain}
Risk score: {score}/100 ({risk_band})
{f'Partner context: {partner_context}' if partner_context else ''}
{f'Threat context: {threat_context}' if threat_context else ''}
Email auth: {email_auth_summary}
SaaS stack: {', '.join(saas_stack[:10]) if saas_stack else 'minimal'}

Top findings:
{top_findings}

Return ONLY a JSON object with these three fields:
{{
  "key_finding": "Single most important finding. One sentence. Specific.",
  "executive_summary": "2-3 sentences. Lead with highest severity.",
  "threat_narrative": "3-5 sentences of interpretive analysis for {AUDIENCE_TONE[audience]}."
}}"""

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 600,
                "messages": [{"role": "user", "content": prompt}],
            },
        ) as resp:
            data = await resp.json()

    text = data["content"][0]["text"].strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return json.loads(text)