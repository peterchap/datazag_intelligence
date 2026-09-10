"""
healthreport/renderer.py
------------------------
HealthReportRenderer — produces the v8 master Trusted-Platform-Impersonation report.

Architecture
------------
- Inherits from BaseRenderer (in `renderers.py`) to reuse all the data attribute
  binding (self.domain, self.tech, self.findings, etc.).
- Overrides to_html / to_markdown / to_dict / render — does NOT use _html_shell_branded
  because the v8 design's multi-page A4 paginated structure is different enough to
  build its own shell.
- HTML is built via a single Jinja2 template constant (HEALTH_REPORT_TEMPLATE) for
  cleanliness around the page-5 vendor league-table loop.
- All hardcoded values from the v8 mockup are replaced with data bindings; placeholders
  marked TODO will resolve once the relevant pipeline modules are extended.

Pages
-----
01  Cover (page 1)
02  TOC (page 2)
03  At a glance (page 3)
04  Why this matters (page 4)
05  Your vendor footprint (page 5)
[06–10 to follow once section 04 dataset is specced]
"""

from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, BaseLoader, select_autoescape

from branding import BrandConfig
from intelligence_contract import (
    Annotation,
    PlatformImpersonation,
    ReportViewModel,
    redact_for_teaser,
)

from .audiences import AudienceConfig, TIERS, get_audience
from .grade import score_to_grade, TrustGrade


# ---------------------------------------------------------------------------
# Vendor / platform desirability table
# ---------------------------------------------------------------------------
# Static for v1. The intent in production is for these scores to come from a
# rolling 30-day count of certificate-issuance volume per imitated platform,
# computed by the AII pipeline. For now: hand-calibrated weights that match the
# pattern observed in the April 2026 corpus.

# The IT tear-off caps here: past ten items a work list stops being actioned.
REMEDIATION_PLAN_MAX = 10

# How much the ABSENCE of each control actually costs you. This is a SEPARATE
# dimension from whether it is deployed: "missing" is a maturity state, not a
# severity. Rating every gap High put security.txt and BIMI beside DMARC and an
# active C2 listing, which is the fastest way to lose a security reader — the one
# most likely to check whether the severities mean anything.
#
#   high    — your domain can be spoofed, hijacked, or silently mis-issued against
#   medium  — a real hardening gap, but it needs another failure to matter
#   low     — reporting, disclosure or brand-visibility value; not a vulnerability
CONTROL_IMPACT: dict[str, str] = {
    "DMARC enforcement":       "high",     # anyone can send as you; deliverability
    "SPF strict mode":         "high",
    "Registrar locks":         "high",     # domain hijack / transfer-out
    "DNSSEC":                  "medium",
    "CAA records":             "medium",   # mis-issuance barrier
    "MTA-STS":                 "medium",
    "DKIM signing":            "medium",
    "HSTS deployment":         "medium",
    "TLS-RPT":                 "low",      # reporting channel only
    "BIMI":                    "low",      # brand visibility, not a security control
    "security.txt":            "low",      # disclosure convenience
    "Abuse contact published": "low",
}


_OBSERVATORY_CACHE: "Observatory | None" = None


def _load_observatory() -> "Observatory":
    """One load per process. A report run renders many domains; the corpus figures
    are the same for all of them."""
    global _OBSERVATORY_CACHE
    if _OBSERVATORY_CACHE is None:
        try:
            from observatory import load as _obs_load
            _OBSERVATORY_CACHE = _obs_load()
        except Exception as e:      # never fatal: the benchmark line is optional
            print(f"  observatory unavailable ({type(e).__name__}) — benchmark line omitted")
            from observatory import Observatory as _Obs
            _OBSERVATORY_CACHE = _Obs.unavailable()
    return _OBSERVATORY_CACHE


def _join_clauses(parts: list[str]) -> str:
    """a, b and c — the Oxford-free join an executive line wants."""
    if len(parts) <= 1:
        return parts[0] if parts else ""
    return ", ".join(parts[:-1]) + " and " + parts[-1]


_LOCK_TOKENS = ("transferprohibited", "deleteprohibited", "updateprohibited", "renewprohibited")


def _locks_from_status(status: str | None) -> int:
    """Count registrar locks from the RDAP status string on the contract, so the
    audit does not depend on the legacy dict being populated."""
    low = (status or "").lower()
    return sum(1 for t in _LOCK_TOKENS if t in low)


def control_impact(name: str) -> str:
    return CONTROL_IMPACT.get((name or "").strip(), "medium")

PLATFORM_DESIRABILITY: dict[str, dict[str, Any]] = {
    # name (lowercase substring match)        rank weight, role, reason
    "microsoft 365":      {"weight": 100, "tier": "high",
                           "role": "Email, identity, productivity · primary work environment",
                           "why": "Works on any office worker, and the credentials unlock email, "
                                  "files and SSO into other tools. The most-impersonated "
                                  "platform in our data."},
    "google workspace":   {"weight": 90, "tier": "high",
                           "role": "Search Console, calendar, productivity · secondary work environment",
                           "why": "Unlocks email, drive and calendar. Search Console access also "
                                  "lets attackers manipulate your search visibility."},
    "okta":               {"weight": 85, "tier": "high",
                           "role": "Identity provider · single sign-on",
                           "why": "Okta credentials ARE the keys — one captured login unlocks "
                                  "every application behind the SSO."},
    "docusign":           {"weight": 70, "tier": "med-high",
                           "role": "Document signing · contract workflow",
                           "why": "Urgency lures ('document awaiting signature') that work on "
                                  "staff at every level. A phishing staple."},
    "mailchimp":          {"weight": 75, "tier": "med-high",
                           "role": "Marketing email, customer mailing list · outbound channel",
                           "why": "Unlocks the customer mailing list directly — the fastest path "
                                  "from staff compromise to brand impersonation at scale, sent "
                                  "from your real account."},
    "apple":              {"weight": 50, "tier": "med",
                           "role": "Apple Business / device management",
                           "why": "Apple ID credentials unlock device management and App Store access."},
    "zoho":               {"weight": 45, "tier": "med",
                           "role": "CRM, productivity, campaign tooling",
                           "why": "Zoho credentials unlock CRM, support, and campaign infrastructure."},
    "citrix":             {"weight": 40, "tier": "med",
                           "role": "Mobile device management",
                           "why": "Citrix admin credentials unlock device fleet management."},
    "mailgun":            {"weight": 25, "tier": "low",
                           "role": "Transactional email infrastructure",
                           "why": "Mailgun credentials unlock outbound email sending; less directly "
                                  "actionable but enables high-volume campaigns."},
    "email signatures":   {"weight": 15, "tier": "low",
                           "role": "Email signature management",
                           "why": "Lower-value target; signature infrastructure rather than identity."},

    # ── Ticketing / ITSM / helpdesk — detected via CNAME ─────────────────
    "zoho desk":          {"weight": 50, "tier": "med",
                           "role": "Helpdesk · client-facing ticket workflow",
                           "why": "Ticketing platforms carry customer correspondence and access "
                                  "controls. A fake login captures support agent credentials and "
                                  "exposes client interactions."},
    "zoho crm":           {"weight": 60, "tier": "med-high",
                           "role": "CRM · sales pipeline and customer records",
                           "why": "CRM credentials unlock customer lists, sales opportunities, "
                                  "and contact data. Used for downstream phishing of those "
                                  "customers in your name."},
    "zoho mail":          {"weight": 70, "tier": "med-high",
                           "role": "Business email · primary correspondence",
                           "why": "Email credentials unlock most other access. Zoho Mail is an "
                                  "increasingly common target as adoption grows."},
    "zoho generic":       {"weight": 35, "tier": "med",
                           "role": "Zoho platform (specific module not identified)",
                           "why": "Zoho ecosystem account — full platform scope depends on "
                                  "which modules are licensed."},
    "zendesk":            {"weight": 55, "tier": "med",
                           "role": "Helpdesk · customer ticket workflow",
                           "why": "Zendesk credentials unlock customer interaction history and "
                                  "support workflows. Frequently impersonated."},
    "freshservice":       {"weight": 50, "tier": "med",
                           "role": "ITSM · internal IT service management",
                           "why": "Freshservice access controls internal IT processes and "
                                  "service desk operations."},
    "freshdesk":          {"weight": 50, "tier": "med",
                           "role": "Helpdesk · customer support workflow",
                           "why": "Freshdesk credentials unlock customer support history."},
    "servicenow":         {"weight": 60, "tier": "med-high",
                           "role": "Enterprise ITSM platform",
                           "why": "ServiceNow handles change management, incidents, and approvals. "
                                  "High-value target for ransomware-precursor reconnaissance."},
    "atlassian":          {"weight": 65, "tier": "med-high",
                           "role": "Jira · Confluence · code and process tooling",
                           "why": "Atlassian credentials unlock issue trackers and wikis that "
                                  "often contain credentials, infrastructure detail, and "
                                  "operational secrets."},
    "help scout":         {"weight": 40, "tier": "med",
                           "role": "Helpdesk · customer support workflow",
                           "why": "Smaller-scale helpdesk; lower impersonation volume but still active."},
    "intercom":           {"weight": 45, "tier": "med",
                           "role": "Customer messaging platform",
                           "why": "Intercom credentials unlock customer conversation history and "
                                  "outbound messaging."},
    "salesforce":         {"weight": 80, "tier": "high",
                           "role": "Enterprise CRM · sales and customer-data system of record",
                           "why": "Salesforce holds the customer list of record for many "
                                  "businesses. A compromise enables downstream customer phishing "
                                  "at scale. Heavily impersonated in our certificate-issuance data."},
    "hubspot":            {"weight": 65, "tier": "med-high",
                           "role": "CRM and marketing automation",
                           "why": "HubSpot credentials unlock customer lists and marketing "
                                  "send infrastructure; used to send phishing from your real domain."},
    "pipedrive":          {"weight": 45, "tier": "med",
                           "role": "Sales CRM · pipeline management",
                           "why": "Pipedrive access exposes sales pipeline and contact data."},
    "connectwise":        {"weight": 70, "tier": "med-high",
                           "role": "MSP PSA · IT-services-firm operations",
                           "why": "ConnectWise holds the client list for IT-services firms. A "
                                  "compromise gives downstream access into every customer the "
                                  "firm serves — high-value lateral pathway."},
    "autotask":           {"weight": 65, "tier": "med-high",
                           "role": "MSP PSA · IT-services operations",
                           "why": "Autotask holds client and ticket data for IT-services firms; "
                                  "similar threat model to ConnectWise."},
    "cloudflare":         {"weight": 25, "tier": "low",
                           "role": "CDN · edge network",
                           "why": "Cloudflare itself is rarely the lure; sub-credentials are "
                                  "low-tier impersonation targets."},
    "aws":                {"weight": 30, "tier": "low",
                           "role": "Cloud infrastructure",
                           "why": "AWS console credentials are high-value but rarely the "
                                  "front-line lure; targeting tends to be via the user's own apps."},
    "azure":              {"weight": 30, "tier": "low",
                           "role": "Cloud infrastructure",
                           "why": "Azure portal credentials are similar in profile to AWS — "
                                  "high impact when compromised, but not a typical phishing lure."},
    "vercel":             {"weight": 20, "tier": "low",
                           "role": "Frontend hosting platform",
                           "why": "Vercel deployments — lower impersonation volume."},
    "netlify":            {"weight": 20, "tier": "low",
                           "role": "Frontend hosting platform",
                           "why": "Netlify deployments — lower impersonation volume."},
    "statuspage":         {"weight": 15, "tier": "low",
                           "role": "Operational status page",
                           "why": "Statuspage credentials are low-value compared to identity platforms."},
    "betterstack":        {"weight": 15, "tier": "low",
                           "role": "Operational monitoring · status page",
                           "why": "Operational monitoring tool — low impersonation appeal."},
    "notion":             {"weight": 45, "tier": "med",
                           "role": "Knowledge base · documentation platform",
                           "why": "Notion workspaces often contain internal secrets, credentials, "
                                  "and operational detail. Worth phishing if scope is known."},
    "gitbook":            {"weight": 30, "tier": "med",
                           "role": "Documentation platform",
                           "why": "Docs platform — moderate impersonation appeal."},
    "shopify":            {"weight": 70, "tier": "med-high",
                           "role": "E-commerce platform",
                           "why": "Shopify admin credentials unlock payment configuration, "
                                  "customer data, and order workflow. Active impersonation target."},
    "sendgrid":           {"weight": 35, "tier": "med",
                           "role": "Transactional email infrastructure",
                           "why": "SendGrid credentials unlock outbound mail sending — "
                                  "infrastructure for high-volume phishing campaigns."},
    "wordpress engine":   {"weight": 30, "tier": "med",
                           "role": "Managed WordPress hosting",
                           "why": "WP-Engine credentials unlock content management on hosted sites."},
    # additions can be appended; the lookup uses substring matching
}

DEFAULT_PLATFORM_ENTRY = {
    "weight": 30, "tier": "med",
    "role": "SaaS platform",
    "why": "Identity platform — credentials may unlock account access.",
}

# Email-auth / DNS concepts that leak out of txt_intelligence or SPF parsing but
# are NOT trusted platforms — they must never be rendered as part of the stack
# ("SPF Policy" showing as a SaaS platform the customer 'uses' kills credibility).
_NON_PLATFORM_NAMES = {
    "spf", "spf policy", "spf record", "dmarc", "dmarc policy", "dmarc record",
    "dkim", "dkim policy", "dnssec", "caa", "bimi", "mta sts", "tls rpt",
    "email authentication", "verification", "security txt", "txt", "dns",
    "ns", "mx", "a record", "aaaa", "cname",
}


def _norm_platform_display(s: str) -> str:
    """Normalise a platform name for stop-list comparison: lowercase, and
    collapse separators/punctuation to single spaces."""
    out = []
    for ch in (s or "").lower():
        out.append(ch if ch.isalnum() else " ")
    return " ".join("".join(out).split())


def is_platform_name(s: str) -> bool:
    """False for email-auth/DNS tokens that must not appear as platforms."""
    return bool((s or "").strip()) and _norm_platform_display(s) not in _NON_PLATFORM_NAMES


# MX hostnames → owning platform. MX is a STRONG signal: it's where the domain
# actually receives mail right now, unlike a TXT verification token which only
# proves someone verified the domain at some point (often stale).
_VENDOR_MX_PATTERNS: dict[str, list[str]] = {
    "microsoft 365":    ["protection.outlook.com", "mail.protection.outlook", "outlook.com"],
    "google workspace": ["aspmx.l.google.com", "googlemail.com", "google.com", "l.google.com"],
    "mimecast":         ["mimecast.com", "mimecast.co"],
    "proofpoint":       ["pphosted.com", "ppe-hosted.com", "proofpoint"],
    "mailchimp":        ["mcsv.net", "mandrillapp.com"],
    "zoho mail":        ["zoho.com", "zoho.eu", "zohomail"],
    "fastmail":         ["messagingengine.com", "fastmail"],
    "barracuda":        ["barracudanetworks.com", "barracuda"],
}

# Evidence strength: live-routing/active-use signals beat verification tokens.
# MX (receives mail) and CNAME (a subdomain actively points there) are strongest;
# SPF includes are active sending config; a TXT verification token / corpus hint
# is the weakest (may be years stale).
_EVIDENCE_STRENGTH = {"MX": 4, "CNAME": 4, "SPF": 3, "CORPUS": 2, "STACK": 1, "TXT": 1}


def _evidence_strength(evidence: list[dict]) -> int:
    return max((_EVIDENCE_STRENGTH.get(e["key"], 1) for e in evidence), default=0)


# Patterns to match TXT records back to their owning vendor.
# Each pattern is a lowercase substring that, when found in a TXT record,
# attributes that record to the named vendor.
_VENDOR_TXT_PATTERNS: dict[str, list[str]] = {
    "microsoft 365":    ["ms=", "ms84", "exchange", "outlook", "microsoftonline", "msrnp"],
    "google workspace": ["google-site-verification", "_spf.google", "googlemail"],
    "mailchimp":        ["mcsv.net", "mailchimp", "mandrill"],
    "apple":            ["apple-domain-verification", "icloud"],
    "zoho":             ["zoho-verification", "zb"],
    "citrix":           ["citrix"],
    "mailgun":          ["mailgun"],
    "email signatures": ["emailsignatures365"],
}

# Patterns to match subdomain CNAME targets back to their owning vendor.
# These give Tier-1 (direct evidence) detection — much higher confidence than
# TXT-record verification tokens, which only prove domain ownership at some
# point in the past.
_VENDOR_CNAME_PATTERNS: dict[str, list[str]] = {
    # Microsoft / Google — confirm the same platforms TXT records detected
    "microsoft 365":     ["clientconfig.microsoftonline-p.net", "outlook.com", "office.com",
                          "msappproxy.net", "sharepointonline.com"],
    "google workspace":  ["googlemail.l.google.com", "ghs.googlehosted.com", "ghs.google.com"],
    # Zoho family — Peter's example use case
    "zoho desk":         ["desk.zoho.com", "desk.zoho.eu", "desk.zoho.in", "deskcdn.com"],
    "zoho crm":          ["crm.zoho.com", "crm.zoho.eu", "crm.zoho.in"],
    "zoho mail":         ["zoho-mail.com", "zohomail.com"],
    "zoho generic":      ["zoho.com", "zohopublic.com", "zohostatic.com", "zohohost.com"],
    # Ticketing / ITSM / helpdesk
    "zendesk":           ["zendesk.com"],
    "freshservice":      ["freshservice.com"],
    "freshdesk":         ["freshdesk.com"],
    "servicenow":        ["service-now.com", "servicenow.com"],
    "atlassian":         ["atlassian.net", "atlassian.com", "jira-saas.com", "jira.com"],
    "help scout":        ["helpscoutdocs.com", "helpscout.net"],
    "intercom":          ["intercom.io", "intercom.com", "intercomcdn.com"],
    # CRM / Marketing
    "salesforce":        ["salesforce.com", "force.com", "lightning.force.com", "exacttarget.com"],
    "hubspot":           ["hubspot.com", "hubspotemail.net", "hsforms.com", "hs-sites.com", "hubspotpagebuilder.com"],
    "pipedrive":         ["pipedrive.com"],
    # MSP / IT-services PSA
    "connectwise":       ["connectwise.com", "myconnectwise.net"],
    "autotask":          ["autotask.net"],
    # Hosting / CDN / edge
    "cloudflare":        ["cloudflare.net", "pages.dev"],
    "aws":               ["amazonaws.com", "cloudfront.net", "elasticbeanstalk.com"],
    "azure":             ["azurewebsites.net", "azureedge.net", "azurefd.net"],
    "vercel":            ["vercel.app", "vercel-dns.com"],
    "netlify":           ["netlify.app", "netlify.com"],
    # Operational / docs
    "statuspage":        ["statuspage.io"],
    "betterstack":       ["betterstack.com", "betteruptime.com"],
    "notion":            ["notion.so"],
    "gitbook":           ["gitbook.io", "gitbook.com"],
    # Other commonly observed
    "shopify":           ["shopify.com", "myshopify.com"],
    "mailchimp":         ["mcsv.net", "list-manage.com"],
    "mailgun":           ["mailgun.org"],
    "sendgrid":          ["sendgrid.net"],
    "wordpress engine":  ["wpengine.com"],
}


# ---------------------------------------------------------------------------
# Jinja environment and template
# ---------------------------------------------------------------------------

_jinja_env = Environment(
    loader=BaseLoader(),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


HEALTH_REPORT_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Datazag {{ product_label }} — {{ domain }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --navy-deep: #0A141F; --navy: #0F1923; --navy-lift: #18283C; --navy-soft: #1E2C40;
    --rule-dark: rgba(255,255,255,0.10); --rule-soft: rgba(255,255,255,0.06);
    --white: #FFFFFF; --white-2: rgba(255,255,255,0.78); --white-3: rgba(255,255,255,0.55); --white-4: rgba(255,255,255,0.32);
    --cyan: #00C2FF; --cyan-deep: #0096CC; --cyan-glow: rgba(0,194,255,0.12);
    --warn: #F4B860; --bad: #FF6B6B; --good: #4ADE80;
    --paper: #FAFAF8; --ink: #0F172A; --ink-2: #334155; --ink-3: #64748B; --ink-4: #94A3B8;
    --rule-light: #E2E8F0; --rule-lighter: #F1F5F9; --cyan-page: #0096CC;
    --tag-context: #64748B; --tag-findings: #0096CC; --tag-action: #C2410C;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  @page { size: A4; margin: 0; }
  html, body { background: #FFFFFF; font-family: 'Inter', sans-serif; color: var(--white); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
  /* Page shell */
  /* min-height (not fixed height) + no clip: short pages still fill an A4 sheet,
     but long sections grow and flow onto additional sheets instead of being
     clipped (which dropped content) or spilling over the next page. */
  .page { width: 794px; min-height: 1123px; margin: 0 auto; background: var(--navy); position: relative; display: flex; flex-direction: column; page-break-after: always; }
  .page:last-child { page-break-after: auto; }
  .page::before { content: ''; position: absolute; inset: 0; background: radial-gradient(circle at 88% 8%, rgba(0,194,255,0.10) 0%, transparent 38%), radial-gradient(circle at 8% 82%, rgba(0,194,255,0.06) 0%, transparent 42%), radial-gradient(circle at 60% 50%, rgba(255,255,255,0.02) 0%, transparent 50%); pointer-events: none; z-index: 0; }
  .page::after { content: ''; position: absolute; inset: 0; background-image: linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px); background-size: 32px 32px; pointer-events: none; z-index: 0; }
  .page > * { position: relative; z-index: 1; }
  /* Top bar */
  .topbar { display: flex; justify-content: space-between; align-items: center; padding: 28px 56px 22px; border-bottom: 1px solid var(--rule-dark); }
  .brand { display: flex; align-items: center; gap: 14px; }
  .brand-mark { width: 32px; height: 32px; border-radius: 8px; background: linear-gradient(135deg, var(--cyan) 0%, var(--cyan-deep) 100%); display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 12px rgba(0,194,255,0.28); }
  .brand-mark svg { width: 18px; height: 18px; }
  .brand-wordmark { font-size: 19px; font-weight: 800; letter-spacing: -0.02em; color: var(--white); }
  .brand-divider { width: 1px; height: 22px; background: var(--rule-dark); }
  .brand-product { font-size: 11px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: var(--white-3); }
  .topbar-right { text-align: right; }
  .topbar-id { font-size: 11px; font-weight: 600; color: var(--white-3); letter-spacing: 0.06em; text-transform: uppercase; }
  .topbar-id strong { color: var(--cyan); font-weight: 700; letter-spacing: 0; text-transform: none; margin-left: 8px; font-size: 12px; }
  /* Cover content */
  .cover { flex: 1; padding: 44px 56px 40px; display: flex; flex-direction: column; }
  .eyebrow { display: inline-flex; align-items: center; gap: 10px; padding: 7px 14px; background: var(--cyan-glow); border: 1px solid rgba(0,194,255,0.28); border-radius: 100px; font-size: 10.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--cyan); align-self: flex-start; margin-bottom: 28px; }
  .eyebrow .dot { width: 5px; height: 5px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 8px var(--cyan); }
  .hero { font-size: 44px; font-weight: 800; letter-spacing: -0.028em; line-height: 1.08; color: var(--white); margin-bottom: 22px; max-width: 640px; }
  .hero .pct { color: var(--cyan); font-weight: 900; position: relative; white-space: nowrap; }
  .hero .pct::after { content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 4px; background: var(--cyan); opacity: 0.25; border-radius: 2px; }
  .hero .lead-out { display: block; font-weight: 600; color: var(--white-2); font-size: 32px; letter-spacing: -0.02em; margin-top: 14px; line-height: 1.15; }
  .deck { font-size: 14px; line-height: 1.65; color: var(--white-2); max-width: 600px; margin-bottom: 36px; }
  .deck strong { color: var(--white); font-weight: 600; }

  /* New cover (v8.4) — descriptive title + dual-score panel */
  .cover-title { font-size: 26px; font-weight: 700; letter-spacing: -0.018em; line-height: 1.22; color: var(--white); margin-bottom: 14px; max-width: 660px; }
  .cover-title .cover-domain { color: var(--cyan); font-weight: 800; }
  .cover-deck { font-size: 13px; line-height: 1.65; color: var(--white-2); max-width: 620px; margin-bottom: 22px; }
  .cover-deck strong { color: var(--white); font-weight: 600; }

  .dual-score { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
  .dual-score-card { background: linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.015) 100%); border: 1px solid var(--rule-dark); border-radius: 14px; padding: 16px 18px 14px; position: relative; overflow: hidden; }
  .dual-score-card::before { content: ''; position: absolute; top: -40px; right: -40px; width: 140px; height: 140px; border-radius: 50%; pointer-events: none; opacity: 0.4; }
  .dual-score-card.platform::before { background: radial-gradient(circle, rgba(255,107,107,0.18) 0%, transparent 70%); }
  .dual-score-card.infra::before    { background: radial-gradient(circle, rgba(0,194,255,0.18) 0%, transparent 70%); }
  .dsc-label { position: relative; z-index: 1; font-size: 9.5px; font-weight: 800; letter-spacing: 0.14em; text-transform: uppercase; color: var(--white-3); margin-bottom: 10px; display: flex; align-items: center; gap: 7px; }
  .dual-score-card.platform .dsc-label { color: var(--bad); }
  .dual-score-card.infra    .dsc-label { color: var(--cyan); }
  .dsc-icon { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border-radius: 4px; color: var(--ink); font-size: 9px; font-weight: 800; }
  .dual-score-card.platform .dsc-icon { background: var(--bad); }
  .dual-score-card.infra    .dsc-icon { background: var(--cyan); }
  .dsc-grade-ref { margin-left: auto; font-size: 10px; font-weight: 700; color: var(--white-3); letter-spacing: 0; text-transform: none; font-variant-numeric: tabular-nums; padding: 2px 8px; background: rgba(255,255,255,0.04); border: 1px solid var(--rule-soft); border-radius: 100px; }
  .dsc-state { position: relative; z-index: 1; font-size: 19px; font-weight: 800; color: var(--white); letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 5px; }
  .dsc-qualifier { position: relative; z-index: 1; font-size: 11.5px; color: var(--white-2); line-height: 1.5; margin: 0 0 12px; }

  /* Platform list — surfaces the actual vendor names so the customer sees what we found */
  .dsc-platform-list { position: relative; z-index: 1; padding: 9px 0 9px; margin: 0 0 8px; border-top: 1px solid var(--rule-soft); border-bottom: 1px solid var(--rule-soft); font-size: 10.5px; line-height: 1.65; color: var(--white-2); }
  .dsc-platform-name { color: var(--white); font-weight: 600; letter-spacing: -0.005em; white-space: nowrap; }
  .dsc-platform-name.cname-only { color: var(--cyan); }
  .dsc-platform-marker { font-size: 7.5px; color: var(--cyan); margin-left: 1px; vertical-align: super; }
  .dsc-platform-sep { color: var(--white-4); margin: 0 1px; }
  .dsc-platform-footnote { position: relative; z-index: 1; font-size: 9.5px; color: var(--white-3); line-height: 1.5; margin: 0 0 10px; font-style: italic; }
  .dsc-platform-footnote .dsc-platform-marker { font-style: normal; }
  .dsc-actions { position: relative; z-index: 1; padding-top: 10px; border-top: 1px solid var(--rule-soft); margin-bottom: 10px; }
  .dsc-actions-label { font-size: 9px; font-weight: 800; letter-spacing: 0.14em; text-transform: uppercase; color: var(--white-4); margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }
  .dsc-actions-caption { font-weight: 500; letter-spacing: 0.02em; text-transform: none; font-size: 9px; color: var(--white-4); font-style: italic; }
  .dsc-actions-list { list-style: none; margin: 0; padding: 0; }
  .dsc-actions-list li { font-size: 11px; color: var(--white-2); line-height: 1.5; padding: 3px 0 3px 16px; position: relative; }
  .dsc-actions-list li::before { content: '→'; position: absolute; left: 0; color: var(--cyan); font-weight: 700; }
  .dsc-actions-list.compact li { padding: 1px 0 1px 14px; }
  .dsc-actions-list.compact li::before { content: '·'; color: var(--white-4); top: -2px; }
  .dsc-context { position: relative; z-index: 1; font-size: 10.5px; color: var(--white-3); line-height: 1.55; border-top: 1px dashed var(--rule-soft); padding-top: 8px; margin: 0; font-style: italic; }
  .dsc-context strong { color: var(--cyan); font-weight: 700; font-style: normal; }

  /* legacy dual-score-card props (v8.4 — unused on v8.5 cover but retained for safety) */
  .dsc-grade-row { position: relative; z-index: 1; display: flex; align-items: baseline; gap: 14px; margin-bottom: 6px; }
  .dsc-grade { font-size: 44px; font-weight: 900; line-height: 1; letter-spacing: -0.035em; color: var(--white); }
  .dsc-score { font-size: 14px; font-weight: 700; color: var(--white-3); font-variant-numeric: tabular-nums; letter-spacing: -0.005em; }
  .dsc-score .dsc-of { color: var(--white-4); font-weight: 600; }
  .dsc-headline { position: relative; z-index: 1; font-size: 12.5px; font-weight: 700; color: var(--white); letter-spacing: -0.005em; margin-bottom: 10px; }
  .dsc-bullets { position: relative; z-index: 1; list-style: none; margin: 0 0 10px; padding: 0; border-top: 1px solid var(--rule-soft); padding-top: 8px; }
  .dsc-bullets li { font-size: 11px; color: var(--white-2); line-height: 1.5; padding: 2px 0 2px 14px; position: relative; }
  .dsc-bullets li::before { content: '·'; position: absolute; left: 2px; color: var(--white-4); font-weight: 700; }

  .overall-grade-band { display: grid; grid-template-columns: 56px 1fr; gap: 18px; align-items: center; background: rgba(255,255,255,0.02); border: 1px solid var(--rule-dark); border-radius: 12px; padding: 14px 18px; margin-bottom: 22px; }
  .ogb-letter { width: 56px; height: 56px; border-radius: 12px; background: linear-gradient(135deg, var(--cyan) 0%, var(--cyan-deep) 100%); display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: 900; letter-spacing: -0.03em; color: var(--ink); box-shadow: 0 2px 10px rgba(0,194,255,0.25); }
  .ogb-body { line-height: 1.4; }
  .ogb-label { font-size: 9.5px; font-weight: 800; letter-spacing: 0.14em; text-transform: uppercase; color: var(--white-3); margin-bottom: 3px; }
  .ogb-headline { font-size: 15px; font-weight: 800; color: var(--white); letter-spacing: -0.015em; margin-bottom: 2px; }
  .ogb-detail { font-size: 11.5px; color: var(--white-2); line-height: 1.5; max-width: 540px; }

  /* Trust grade block (v8.3 — unused on v8.4 cover but retained for now) */
  .grade-block { display: grid; grid-template-columns: 168px 1fr; gap: 28px; align-items: center; background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.015) 100%); border: 1px solid var(--rule-dark); border-radius: 16px; padding: 26px 30px; margin-bottom: 28px; position: relative; overflow: hidden; }
  .grade-block::before { content: ''; position: absolute; top: -60px; right: -40px; width: 220px; height: 220px; background: radial-gradient(circle, var(--cyan-glow) 0%, transparent 60%); pointer-events: none; }
  .grade-dial { position: relative; width: 168px; height: 168px; }
  .grade-dial svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .grade-dial-letter { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .grade-letter { font-size: 76px; font-weight: 900; line-height: 1; letter-spacing: -0.04em; color: var(--white); margin-bottom: 4px; }
  .grade-caption { font-size: 9.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--white-3); }
  .grade-text { position: relative; z-index: 1; }
  .grade-headline { font-size: 22px; font-weight: 800; letter-spacing: -0.02em; color: var(--white); line-height: 1.2; margin-bottom: 6px; }
  .grade-sub { font-size: 13px; color: var(--white-2); line-height: 1.55; margin-bottom: 18px; max-width: 460px; }
  .grade-pills { display: flex; flex-wrap: wrap; gap: 8px; }
  .pill { display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px 7px 11px; background: rgba(255,255,255,0.04); border: 1px solid var(--rule-dark); border-radius: 100px; font-size: 11.5px; font-weight: 600; color: var(--white); letter-spacing: 0.005em; }
  .pill .pill-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--cyan); }
  .pill.warn .pill-dot { background: var(--warn); }
  .pill.bad .pill-dot { background: var(--bad); }
  .pill .pill-num { font-weight: 800; color: var(--cyan); margin-right: 2px; }
  .pill.warn .pill-num { color: var(--warn); }
  .pill.bad .pill-num { color: var(--bad); }
  /* Meta strip */
  .meta-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; padding: 18px 0 20px; border-top: 1px solid var(--rule-dark); border-bottom: 1px solid var(--rule-dark); margin-bottom: 24px; }
  .meta-cell { padding: 0 22px; border-right: 1px solid var(--rule-soft); }
  .meta-cell:first-child { padding-left: 0; }
  .meta-cell:last-child { padding-right: 0; border-right: none; }
  .meta-label { font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--cyan); margin-bottom: 7px; }
  .meta-value { font-size: 13.5px; font-weight: 600; color: var(--white); line-height: 1.35; }
  .meta-value .meta-sub { display: block; font-size: 10.5px; font-weight: 500; color: var(--white-3); margin-top: 3px; letter-spacing: 0.01em; }
  /* Corpus line */
  .corpus { display: flex; align-items: center; gap: 12px; margin-bottom: auto; padding-bottom: 20px; }
  .corpus-bar { flex: 1; height: 1px; background: linear-gradient(90deg, var(--rule-dark) 0%, rgba(0,194,255,0.18) 50%, var(--rule-dark) 100%); }
  .corpus-text { font-size: 10.5px; font-weight: 600; color: var(--white-3); letter-spacing: 0.06em; text-transform: uppercase; white-space: nowrap; }
  .corpus-text strong { color: var(--cyan); font-weight: 700; margin-right: 4px; }
  .corpus-pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--cyan); }
  /* Footer */
  .cover-footer { display: flex; justify-content: space-between; align-items: center; padding: 18px 56px 24px; border-top: 1px solid var(--rule-dark); font-size: 10px; font-weight: 600; color: var(--white-4); letter-spacing: 0.1em; text-transform: uppercase; }
  .cover-footer .right { color: var(--white-3); }
  /* Light interior pages */
  .page.light { background: var(--paper); color: var(--ink); }
  .page.light::before { background: radial-gradient(circle at 92% 4%, rgba(0,150,204,0.05) 0%, transparent 35%), radial-gradient(circle at 4% 96%, rgba(0,150,204,0.03) 0%, transparent 40%); }
  .page.light::after { background-image: linear-gradient(rgba(15,23,42,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(15,23,42,0.025) 1px, transparent 1px); background-size: 36px 36px; }
  .page.light .topbar { border-bottom-color: var(--rule-light); }
  .page.light .brand-wordmark { color: var(--ink); }
  .page.light .brand-product { color: var(--ink-3); }
  .page.light .brand-divider { background: var(--rule-light); }
  .page.light .topbar-id { color: var(--ink-3); }
  .page.light .topbar-id strong { color: var(--cyan-page); }
  .page.light .cover-footer { color: var(--ink-4); border-top-color: var(--rule-light); }
  .page.light .cover-footer .right { color: var(--ink-3); }
  .page.light .toc-spacer { flex: 1; }
  /* TOC */
  .toc-header { padding: 44px 56px 24px; }
  .toc-eyebrow { display: inline-flex; align-items: center; gap: 8px; font-size: 10.5px; font-weight: 700; color: var(--cyan-page); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 14px; }
  .toc-eyebrow::before { content: ''; width: 18px; height: 1.5px; background: var(--cyan-page); }
  .toc-title { font-size: 32px; font-weight: 800; letter-spacing: -0.025em; color: var(--ink); line-height: 1.15; margin-bottom: 12px; max-width: 600px; }
  .toc-lede { font-size: 13.5px; color: var(--ink-2); line-height: 1.6; max-width: 600px; }
  .toc-list { padding: 8px 56px 0; list-style: none; }
  .toc-item { display: grid; grid-template-columns: 56px 1fr auto; gap: 18px; align-items: start; padding: 14px 0; border-bottom: 1px solid var(--rule-lighter); }
  .toc-item:last-child { border-bottom: none; }
  .toc-num { font-size: 22px; font-weight: 800; color: var(--cyan-page); letter-spacing: -0.02em; line-height: 1; padding-top: 2px; font-variant-numeric: tabular-nums; }
  .toc-content { padding-right: 12px; }
  .toc-content h4 { font-size: 14.5px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; margin-bottom: 3px; line-height: 1.3; }
  .toc-content p { font-size: 12px; color: var(--ink-3); line-height: 1.5; margin: 0; }
  .toc-tag { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px 5px 9px; border-radius: 100px; font-size: 9.5px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; border: 1px solid; white-space: nowrap; margin-top: 2px; }
  .toc-tag .tag-dot { width: 5px; height: 5px; border-radius: 50%; }
  .toc-tag.context { color: var(--tag-context); border-color: rgba(100,116,139,0.3); background: rgba(100,116,139,0.06); }
  .toc-tag.context .tag-dot { background: var(--tag-context); }
  .toc-tag.findings { color: var(--tag-findings); border-color: rgba(0,150,204,0.32); background: rgba(0,150,204,0.06); }
  .toc-tag.findings .tag-dot { background: var(--tag-findings); }
  .toc-tag.action { color: var(--tag-action); border-color: rgba(194,65,12,0.32); background: rgba(194,65,12,0.06); }
  .toc-tag.action .tag-dot { background: var(--tag-action); }
  .toc-callout { margin: 16px 56px 0; background: linear-gradient(135deg, rgba(0,150,204,0.06) 0%, rgba(0,150,204,0.02) 100%); border: 1px solid rgba(0,150,204,0.22); border-radius: 12px; padding: 18px 22px; display: grid; grid-template-columns: auto 1fr; gap: 16px; align-items: start; }
  .toc-callout-icon { width: 36px; height: 36px; border-radius: 10px; background: var(--cyan-page); color: white; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 16px; }
  .toc-callout h5 { font-size: 12.5px; font-weight: 700; color: var(--ink); margin-bottom: 4px; letter-spacing: 0.02em; }
  .toc-callout p { font-size: 12px; color: var(--ink-2); line-height: 1.55; margin: 0; }
  .toc-callout p strong { color: var(--ink); font-weight: 600; }
  /* Section identifier */
  .section-id-bar { padding: 36px 56px 0; }
  .section-num-row { display: flex; align-items: baseline; gap: 12px; margin-bottom: 14px; }
  .section-num { font-size: 11px; font-weight: 700; letter-spacing: 0.18em; color: var(--cyan-page); text-transform: uppercase; }
  .section-rule { flex: 1; height: 1px; background: var(--rule-light); }
  .section-tag { font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; padding: 4px 10px; border-radius: 100px; background: rgba(100,116,139,0.08); border: 1px solid rgba(100,116,139,0.22); color: var(--ink-3); }
  .section-title-h1 { font-size: 30px; font-weight: 800; letter-spacing: -0.025em; color: var(--ink); line-height: 1.1; margin-bottom: 10px; }
  .section-headline { font-size: 14.5px; color: var(--ink-2); line-height: 1.6; max-width: 620px; margin-bottom: 24px; }
  .section-headline strong { color: var(--ink); font-weight: 600; }
  /* At-a-glance */
  .grade-band { margin: 0 56px 24px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 18px 22px; display: grid; grid-template-columns: 60px 1fr; gap: 22px; align-items: center; }
  .grade-band-letter { width: 60px; height: 60px; border-radius: 12px; background: linear-gradient(135deg, var(--ink) 0%, #1E293B 100%); color: var(--white); display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: 900; letter-spacing: -0.03em; box-shadow: 0 2px 10px rgba(15,23,42,0.18); }
  .grade-band-body { display: grid; grid-template-rows: auto auto; gap: 8px; }
  .grade-band-scale { position: relative; height: 24px; margin-top: 2px; }
  .grade-scale-track { position: absolute; top: 50%; left: 0; right: 0; height: 6px; transform: translateY(-50%); background: linear-gradient(90deg, #4ADE80 0%, #A3E635 22%, #FACC15 45%, #FB923C 65%, #EF4444 88%, #B91C1C 100%); border-radius: 3px; opacity: 0.85; }
  .grade-scale-marks { position: absolute; top: 50%; left: 0; right: 0; transform: translateY(-50%); display: flex; justify-content: space-between; pointer-events: none; }
  .grade-scale-mark { width: 2px; height: 14px; background: var(--paper); border-radius: 1px; }
  .grade-scale-pin { position: absolute; top: 50%; transform: translate(-50%, -50%); width: 22px; height: 22px; border-radius: 50%; background: var(--ink); border: 3px solid var(--paper); box-shadow: 0 2px 8px rgba(15,23,42,0.35); z-index: 2; }
  .grade-band-text { font-size: 12.5px; color: var(--ink-2); line-height: 1.55; }
  .grade-band-text strong { color: var(--ink); font-weight: 600; }
  .scorecards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin: 0 56px 22px; }
  .scorecard { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 18px 18px 16px; border-top: 3px solid var(--ink-4); }
  .scorecard.bad { border-top-color: #EF4444; }
  .scorecard.warn { border-top-color: #F59E0B; }
  .scorecard.neutral { border-top-color: var(--cyan-page); }
  .scorecard-label { font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--ink-3); margin-bottom: 10px; display: flex; align-items: center; gap: 6px; }
  .scorecard-label .scorecard-icon { width: 14px; height: 14px; border-radius: 4px; background: var(--ink-4); display: inline-flex; align-items: center; justify-content: center; color: white; font-size: 9px; font-weight: 800; }
  .scorecard.bad .scorecard-icon { background: #EF4444; }
  .scorecard.warn .scorecard-icon { background: #F59E0B; }
  .scorecard.neutral .scorecard-icon { background: var(--cyan-page); }
  .scorecard-state { font-size: 22px; font-weight: 800; letter-spacing: -0.02em; line-height: 1.1; margin-bottom: 10px; color: var(--ink); }
  .scorecard.bad .scorecard-state { color: #B91C1C; }
  .scorecard.warn .scorecard-state { color: #B45309; }
  .scorecard.neutral .scorecard-state { color: var(--cyan-deep); }
  .scorecard-text { font-size: 11.5px; color: var(--ink-2); line-height: 1.5; }
  .scorecard-text strong { color: var(--ink); font-weight: 600; }
  .assessment-strip { margin: 0 56px 22px; padding: 12px 18px; background: rgba(100,116,139,0.05); border: 1px solid rgba(100,116,139,0.15); border-radius: 10px; font-size: 11.5px; color: var(--ink-3); display: flex; align-items: center; gap: 10px; }
  .assessment-strip-icon { width: 20px; height: 20px; border-radius: 50%; background: var(--ink-3); color: white; display: inline-flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800; flex-shrink: 0; }
  .assessment-strip strong { color: var(--ink); font-weight: 600; }
  .priorities-header { margin: 0 56px 12px; display: flex; align-items: baseline; gap: 14px; }
  .priorities-header h3 { font-size: 16px; font-weight: 800; letter-spacing: -0.015em; color: var(--ink); }
  .priorities-header .sub { font-size: 11.5px; color: var(--ink-3); }
  .priority-list { margin: 0 56px; }
  .priority-card { display: grid; grid-template-columns: 40px 1fr 110px; gap: 16px; padding: 14px 18px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; margin-bottom: 8px; align-items: start; }
  .priority-card:last-child { margin-bottom: 0; }
  .priority-num { font-size: 26px; font-weight: 900; color: var(--ink-4); letter-spacing: -0.03em; line-height: 1; padding-top: 2px; font-variant-numeric: tabular-nums; }
  .priority-body { padding-right: 8px; }
  .priority-pills { display: flex; gap: 6px; margin-bottom: 5px; flex-wrap: wrap; }
  .pri-pill { font-size: 9px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; }
  .pri-pill.crit { background: #FEE2E2; color: #991B1B; }
  .pri-pill.high { background: #FEF3C7; color: #92400E; }
  .pri-pill.med { background: #DBEAFE; color: #1E40AF; }
  .pri-pill.vendor { background: rgba(239,68,68,0.08); color: #B91C1C; border: 1px solid rgba(239,68,68,0.25); }
  .pri-pill.brand { background: rgba(245,158,11,0.08); color: #B45309; border: 1px solid rgba(245,158,11,0.25); }
  .pri-pill.infra { background: rgba(0,150,204,0.08); color: var(--cyan-deep); border: 1px solid rgba(0,150,204,0.25); }
  .priority-title { font-size: 13.5px; font-weight: 700; color: var(--ink); letter-spacing: -0.005em; line-height: 1.3; margin-bottom: 3px; }
  .priority-action { font-size: 11.5px; color: var(--ink-2); line-height: 1.5; margin-bottom: 6px; }
  .priority-why { font-size: 10.5px; color: var(--ink-3); line-height: 1.5; font-style: italic; }
  .priority-why::before { content: 'Why · '; font-style: normal; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-4); font-size: 9.5px; }
  .priority-meta { font-size: 10px; color: var(--ink-3); line-height: 1.6; text-align: right; border-left: 1px solid var(--rule-light); padding-left: 14px; align-self: stretch; }
  .priority-meta-row { display: flex; justify-content: space-between; margin-bottom: 4px; }
  .priority-meta-key { font-weight: 700; color: var(--ink-4); letter-spacing: 0.06em; text-transform: uppercase; font-size: 8.5px; }
  .priority-meta-val { font-weight: 600; color: var(--ink); font-size: 10.5px; }
  /* Why this matters */
  .data-panel { margin: 0 56px 26px; background: linear-gradient(135deg, var(--ink) 0%, #1E293B 100%); border-radius: 14px; padding: 22px 26px; color: var(--white); position: relative; overflow: hidden; }
  .data-panel::before { content: ''; position: absolute; top: -40px; right: -40px; width: 220px; height: 220px; background: radial-gradient(circle, rgba(0,194,255,0.18) 0%, transparent 60%); pointer-events: none; }
  .data-panel-inner { position: relative; z-index: 1; }
  .data-panel-eyebrow { font-size: 9.5px; font-weight: 700; letter-spacing: 0.16em; text-transform: uppercase; color: var(--cyan); margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
  .data-panel-eyebrow::after { content: ''; flex: 1; height: 1px; background: rgba(0,194,255,0.25); }
  .data-panel-row { display: grid; grid-template-columns: auto 1fr; gap: 22px; align-items: center; margin-bottom: 14px; }
  .data-panel-pct { font-size: 56px; font-weight: 900; color: var(--cyan); line-height: 1; letter-spacing: -0.04em; }
  .data-panel-bar { height: 24px; border-radius: 6px; overflow: hidden; display: flex; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.08); }
  .data-panel-bar-fill { background: linear-gradient(90deg, var(--cyan-deep) 0%, var(--cyan) 100%); width: 87.5%; display: flex; align-items: center; justify-content: flex-start; padding-left: 12px; font-size: 10.5px; font-weight: 700; color: var(--ink); letter-spacing: 0.04em; text-transform: uppercase; }
  .data-panel-bar-rest { flex: 1; display: flex; align-items: center; justify-content: flex-end; padding-right: 10px; font-size: 10px; font-weight: 600; color: var(--white-3); letter-spacing: 0.04em; text-transform: uppercase; }
  .data-panel-claim { font-size: 13px; color: rgba(255,255,255,0.85); line-height: 1.6; max-width: 580px; margin-top: 14px; }
  .data-panel-claim strong { color: var(--white); font-weight: 600; }
  .surfaces-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin: 0 56px 24px; }
  .surface-panel { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 20px 22px; }
  .surface-panel.inbound { border-top: 3px solid #EF4444; }
  .surface-panel.outbound { border-top: 3px solid #F59E0B; }
  .surface-eyebrow { font-size: 9.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 4px; display: flex; align-items: center; gap: 7px; }
  .surface-panel.inbound .surface-eyebrow { color: #B91C1C; }
  .surface-panel.outbound .surface-eyebrow { color: #B45309; }
  .surface-eyebrow .surface-icon { width: 16px; height: 16px; border-radius: 4px; display: inline-flex; align-items: center; justify-content: center; color: white; font-size: 9px; font-weight: 800; }
  .surface-panel.inbound .surface-icon { background: #EF4444; }
  .surface-panel.outbound .surface-icon { background: #F59E0B; }
  .surface-title { font-size: 18px; font-weight: 800; color: var(--ink); letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 6px; }
  .surface-thesis { font-size: 12px; color: var(--ink-2); line-height: 1.55; margin-bottom: 14px; font-style: italic; }
  .surface-attrs { display: grid; gap: 8px; padding-top: 12px; border-top: 1px solid var(--rule-light); }
  .surface-attr { display: grid; grid-template-columns: 76px 1fr; gap: 12px; align-items: baseline; font-size: 11.5px; }
  .surface-attr-key { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-4); padding-top: 2px; }
  .surface-attr-val { color: var(--ink-2); line-height: 1.45; }
  .surface-attr-val strong { color: var(--ink); font-weight: 600; }
  .vol-badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 7px; border-radius: 4px; font-size: 10.5px; font-weight: 700; letter-spacing: 0.02em; }
  .surface-panel.inbound .vol-badge { background: #FEE2E2; color: #991B1B; }
  .surface-panel.outbound .vol-badge { background: #FEF3C7; color: #92400E; }
  .causal-section { margin: 0 56px 0; }
  .causal-header { display: flex; align-items: baseline; gap: 14px; margin-bottom: 14px; }
  .causal-header h3 { font-size: 15px; font-weight: 800; letter-spacing: -0.015em; color: var(--ink); }
  .causal-header .sub { font-size: 11.5px; color: var(--ink-3); line-height: 1.5; }
  .causal-example-eyebrow { display: inline-flex; align-items: center; gap: 8px; font-size: 9.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-3); margin-bottom: 10px; padding: 5px 12px; background: rgba(100,116,139,0.06); border: 1px dashed rgba(100,116,139,0.32); border-radius: 4px; }
  .causal-example-eyebrow::before { content: 'For example'; font-weight: 800; color: var(--ink); padding-right: 8px; margin-right: 4px; border-right: 1px solid rgba(100,116,139,0.3); }
  .causal-chain { display: grid; grid-template-columns: 1fr auto 1fr auto 1fr auto 1fr; gap: 0; align-items: stretch; }
  .causal-step { background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; padding: 12px 14px; display: flex; flex-direction: column; gap: 4px; min-height: 72px; }
  .causal-step.start { border-left: 3px solid #EF4444; }
  .causal-step.end { border-left: 3px solid #F59E0B; }
  .causal-step-num { font-size: 8.5px; font-weight: 800; color: var(--ink-4); letter-spacing: 0.14em; text-transform: uppercase; }
  .causal-step.start .causal-step-num { color: #B91C1C; }
  .causal-step.end .causal-step-num { color: #B45309; }
  .causal-step-title { font-size: 11.5px; font-weight: 700; color: var(--ink); line-height: 1.3; letter-spacing: -0.005em; }
  .causal-step-detail { font-size: 10px; color: var(--ink-3); line-height: 1.4; }
  .causal-arrow { display: flex; align-items: center; justify-content: center; color: var(--ink-4); padding: 0 4px; font-size: 18px; }
  .causal-tags { display: flex; justify-content: space-between; margin-top: 10px; padding: 0 4px; font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; }
  .causal-tags .tag-vendor { color: #B91C1C; }
  .causal-tags .tag-brand { color: #B45309; }
  /* Vendor footprint */
  .footprint-summary { margin: 0 56px 22px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; padding: 14px 0; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; }
  .footprint-stat { padding: 0 22px; border-right: 1px solid var(--rule-lighter); }
  .footprint-stat:last-child { border-right: none; }
  .footprint-stat-num { font-size: 24px; font-weight: 800; color: var(--ink); letter-spacing: -0.03em; line-height: 1; margin-bottom: 4px; font-variant-numeric: tabular-nums; }
  .footprint-stat-num.accent { color: var(--cyan-deep); }
  .footprint-stat-num.alert { color: #B91C1C; }
  .footprint-stat-label { font-size: 9.5px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-3); line-height: 1.3; }
  .top-vendors { margin: 0 56px 18px; display: grid; gap: 10px; }
  .vendor-card { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 16px 18px 14px; display: grid; grid-template-columns: 56px 1fr 130px; gap: 16px; align-items: start; }
  .vendor-card.high { border-left: 3px solid #EF4444; }
  .vendor-card.med-high { border-left: 3px solid #F59E0B; }
  .vendor-rank { display: flex; flex-direction: column; align-items: center; padding-top: 2px; }
  .vendor-rank-num { font-size: 30px; font-weight: 900; color: var(--ink); line-height: 1; letter-spacing: -0.04em; font-variant-numeric: tabular-nums; }
  .vendor-rank-label { font-size: 7.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-4); margin-top: 4px; }
  .vendor-body { padding-right: 4px; }
  .vendor-name { font-size: 16px; font-weight: 800; color: var(--ink); letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 2px; }
  .vendor-role { font-size: 11.5px; color: var(--ink-3); margin-bottom: 10px; font-weight: 500; }
  .vendor-evidence { display: flex; flex-wrap: wrap; gap: 5px 6px; margin-bottom: 10px; }
  .vendor-evi { font-family: 'JetBrains Mono', monospace; font-size: 9.5px; font-weight: 500; color: var(--ink-2); background: rgba(15,23,42,0.04); border: 1px solid rgba(15,23,42,0.08); padding: 3px 7px; border-radius: 4px; letter-spacing: -0.01em; }
  .vendor-evi-key { color: var(--cyan-deep); font-weight: 700; margin-right: 3px; }
  .vendor-quote { font-size: 11.5px; color: var(--ink-2); line-height: 1.5; font-style: italic; padding-left: 10px; border-left: 2px solid var(--rule-light); }
  .vendor-quote strong { color: var(--ink); font-weight: 600; font-style: normal; }
  .vendor-meta { display: flex; flex-direction: column; gap: 6px; align-items: flex-end; }
  .vendor-desirability { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; border-radius: 100px; font-size: 9.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; border: 1px solid; white-space: nowrap; }
  .vendor-desirability.high { color: #B91C1C; background: rgba(239,68,68,0.08); border-color: rgba(239,68,68,0.32); }
  .vendor-desirability.med-high { color: #B45309; background: rgba(245,158,11,0.08); border-color: rgba(245,158,11,0.32); }
  .vendor-desirability .des-dot { width: 6px; height: 6px; border-radius: 50%; }
  .vendor-desirability.high .des-dot { background: #EF4444; }
  .vendor-desirability.med-high .des-dot { background: #F59E0B; }
  .vendor-evidence-count { font-size: 9.5px; font-weight: 700; color: var(--ink-4); letter-spacing: 0.08em; text-transform: uppercase; }
  .vendor-evidence-count strong { color: var(--ink); font-size: 11.5px; font-weight: 800; margin-right: 3px; }
  .vendor-table-wrap { margin: 0 56px 18px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; overflow: hidden; }
  .vendor-table-header { padding: 10px 18px; background: rgba(15,23,42,0.02); border-bottom: 1px solid var(--rule-light); font-size: 11px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; }
  .vendor-table-header span { font-size: 9.5px; font-weight: 600; color: var(--ink-3); letter-spacing: 0.04em; text-transform: none; }
  .vendor-table { width: 100%; border-collapse: collapse; }
  .vendor-table thead th { text-align: left; padding: 8px 14px; font-size: 8.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--ink-4); border-bottom: 1px solid var(--rule-light); background: rgba(15,23,42,0.015); }
  .vendor-table tbody td { padding: 9px 14px; font-size: 11.5px; color: var(--ink-2); border-bottom: 1px solid var(--rule-lighter); vertical-align: middle; }
  .vendor-table tbody tr:last-child td { border-bottom: none; }
  .vendor-table .rank-cell { font-weight: 800; color: var(--ink-3); font-variant-numeric: tabular-nums; font-size: 13px; width: 36px; }
  .vendor-table .name-cell { font-weight: 700; color: var(--ink); font-size: 12px; white-space: nowrap; }
  .vendor-table .role-cell { color: var(--ink-3); }
  .vendor-table .evi-cell { font-family: 'JetBrains Mono', monospace; font-size: 9.5px; color: var(--ink-3); }
  .vendor-table .des-cell { text-align: right; width: 88px; }
  .des-mini { display: inline-flex; align-items: center; gap: 5px; padding: 3px 8px; border-radius: 100px; font-size: 8.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; border: 1px solid; }
  .des-mini.med { color: #92400E; background: rgba(245,158,11,0.06); border-color: rgba(245,158,11,0.28); }
  .des-mini.low { color: var(--ink-3); background: rgba(100,116,139,0.06); border-color: rgba(100,116,139,0.22); }
  .des-mini .des-dot { width: 5px; height: 5px; border-radius: 50%; }
  .des-mini.med .des-dot { background: #F59E0B; }
  .des-mini.low .des-dot { background: var(--ink-4); }
  .next-section-cta { margin: 0 56px 0; padding: 14px 18px; background: linear-gradient(135deg, rgba(0,150,204,0.05) 0%, rgba(0,150,204,0.015) 100%); border: 1px solid rgba(0,150,204,0.22); border-radius: 10px; display: grid; grid-template-columns: 1fr auto; gap: 14px; align-items: center; }
  .next-section-cta-text { font-size: 12px; color: var(--ink-2); line-height: 1.5; }
  .next-section-cta-text strong { color: var(--ink); font-weight: 700; }
  .next-section-cta-arrow { display: inline-flex; align-items: center; gap: 8px; font-size: 10.5px; font-weight: 800; color: var(--cyan-deep); letter-spacing: 0.1em; text-transform: uppercase; white-space: nowrap; }

  /* Mechanism steps — ported from the free report (freereport/renderer.py .mech*),
     restyled on this report's tokens. Numbered steps carry the explanation this
     section used to make in a 120-word paragraph. */
  .mech { border: 1px solid var(--rule-light); border-radius: 12px; overflow: hidden; margin: 0 56px 18px; background: var(--white); }
  .mech-h { background: var(--navy); color: var(--white); font-size: 12px; font-weight: 700; letter-spacing: 0.02em; padding: 11px 18px; }
  .mech-steps { padding: 15px 18px 5px; display: flex; flex-direction: column; gap: 11px; }
  .mstep { display: flex; gap: 13px; align-items: flex-start; }
  .mstep .mnum { flex: 0 0 auto; width: 25px; height: 25px; border-radius: 50%; background: var(--cyan-glow); color: var(--cyan-deep); font-weight: 800; font-size: 12px; display: flex; align-items: center; justify-content: center; border: 1.5px solid var(--cyan); }
  .mstep .mbody { font-size: 11.5px; line-height: 1.55; color: var(--ink-2); }
  .mstep .mbody b { color: var(--ink); font-weight: 600; }
  .mech-punch { margin: 6px 18px 15px; background: var(--rule-lighter); border-left: 3px solid var(--cyan); border-radius: 0 7px 7px 0; padding: 11px 15px; font-size: 12px; line-height: 1.55; color: var(--ink); font-weight: 500; }
  .mech-punch b { color: var(--cyan-deep); font-weight: 700; }
  /* Executive summary — the "so what", before any security vocabulary. */
  .exec-summary { margin: 0 56px 16px; background: var(--white); border: 1px solid var(--rule-light); border-left: 3px solid var(--cyan); border-radius: 0 12px 12px 0; padding: 16px 20px 14px; }
  .exec-verdict { font-size: 17px; font-weight: 800; letter-spacing: -0.015em; color: var(--ink); margin-bottom: 7px; }
  .exec-headline { font-size: 12.5px; line-height: 1.6; color: var(--ink-2); margin-bottom: 12px; }
  .exec-triage { display: flex; flex-direction: column; gap: 7px; }
  .et-row { display: grid; grid-template-columns: 108px 1fr; gap: 12px; align-items: baseline; }
  .et-key { font-size: 9.5px; font-weight: 800; letter-spacing: 0.09em; text-transform: uppercase; color: var(--cyan-deep); }
  .et-val { font-size: 11.5px; line-height: 1.55; color: var(--ink-2); }
  .et-val b { color: var(--ink); font-weight: 600; }
  .ogb-band, .gb-band { font-size: 26px; font-weight: 900; letter-spacing: -0.02em; line-height: 1; text-transform: uppercase; }
  .ogb-band { color: var(--white); }
  .gb-band { color: var(--ink); }
  .ogb-scoreline, .gb-scoreline { font-size: 10.5px; font-weight: 600; letter-spacing: 0.02em; margin-top: 6px; }
  .ogb-scoreline { color: var(--white-3); }
  .gb-scoreline { color: var(--ink-3); }
  .economy-note { margin: 0 56px 14px; background: var(--rule-lighter); border-left: 3px solid var(--cyan); border-radius: 0 9px 9px 0; padding: 12px 16px; }
  .economy-note-h { font-size: 10px; font-weight: 800; letter-spacing: 0.09em; text-transform: uppercase; color: var(--cyan-deep); margin-bottom: 5px; }
  .economy-note p { font-size: 11.5px; line-height: 1.6; color: var(--ink-2); }
  .exec-benchmark { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--rule-lighter); font-size: 11px; line-height: 1.55; color: var(--ink-3); }
  /* Attack-economy primer — ported with the mechanism from the free report. */
  .primer { margin: 0 56px 14px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 16px 20px 12px; }
  .primer-scale { display: flex; gap: 18px; align-items: center; }
  .ps-num { flex: 0 0 auto; font-size: 44px; font-weight: 800; letter-spacing: -0.03em; color: var(--cyan-deep); line-height: 1; }
  .ps-num .sup { font-size: 20px; vertical-align: super; }
  .ps-txt { font-size: 12.5px; line-height: 1.6; color: var(--ink-2); }
  .ps-txt b { color: var(--ink); font-weight: 700; }
  .primer-cite { margin-top: 10px; padding-top: 9px; border-top: 1px solid var(--rule-lighter); font-size: 10px; color: var(--ink-3); }
  .mech-escalate { display: flex; gap: 13px; align-items: flex-start; margin: 4px 18px 10px; background: rgba(244,184,96,0.10); border: 1px solid rgba(244,184,96,0.34); border-radius: 9px; padding: 12px 15px; }
  .mech-escalate .me-icon { flex: 0 0 auto; font-size: 15px; color: #B45309; line-height: 1.3; }
  .mech-escalate .me-body { font-size: 11.5px; line-height: 1.6; color: #5C3A0A; }
  .mech-escalate .me-body b { color: #4A2F08; font-weight: 700; }
  .economy-lead { margin: 0 56px 12px; font-size: 12.5px; line-height: 1.65; color: var(--ink-2); }
  .economy-lead b { color: var(--ink); font-weight: 600; }

  /* ============ Section 02 — External threat (impersonation tables) ============ */
  .monitoring-state-panel { margin: 0 56px 22px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 24px 26px; display: grid; grid-template-columns: 56px 1fr; gap: 22px; align-items: start; }
  .monitoring-state-icon { width: 56px; height: 56px; border-radius: 14px; background: linear-gradient(135deg, var(--cyan-page) 0%, #0078A0 100%); color: white; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 800; box-shadow: 0 2px 10px rgba(0,150,204,0.25); position: relative; }
  .monitoring-state-icon::after { content: ''; position: absolute; top: -3px; right: -3px; width: 14px; height: 14px; border-radius: 50%; background: var(--good); border: 2px solid var(--white); box-shadow: 0 0 0 0 rgba(74,222,128,0.5); animation: monitor-pulse 2s ease-out infinite; }
  @keyframes monitor-pulse { 0% { box-shadow: 0 0 0 0 rgba(74,222,128,0.5); } 70% { box-shadow: 0 0 0 12px rgba(74,222,128,0); } 100% { box-shadow: 0 0 0 0 rgba(74,222,128,0); } }
  .monitoring-state-body h3 { font-size: 17px; font-weight: 800; color: var(--ink); letter-spacing: -0.015em; margin-bottom: 6px; line-height: 1.25; }
  .monitoring-state-body p { font-size: 13px; color: var(--ink-2); line-height: 1.6; margin-bottom: 10px; }
  .monitoring-state-body p strong { color: var(--ink); font-weight: 600; }
  .monitoring-state-meta { display: flex; gap: 16px; margin-top: 12px; font-size: 11px; color: var(--ink-3); }
  .monitoring-state-meta strong { color: var(--ink); font-weight: 700; letter-spacing: 0.04em; }
  .monitoring-state-meta .sep { color: var(--ink-4); }

  /* What we monitor per platform (preview) */
  .platform-preview-header { margin: 14px 56px 10px; }
  .platform-preview-header h4 { font-size: 13px; font-weight: 800; color: var(--ink); letter-spacing: -0.01em; margin-bottom: 4px; }
  .platform-preview-header p { font-size: 11.5px; color: var(--ink-3); line-height: 1.5; }
  .platform-preview-grid { margin: 0 56px 18px; display: grid; gap: 8px; }
  .platform-preview-row { background: var(--white); border: 1px solid var(--rule-light); border-radius: 8px; padding: 11px 16px; display: grid; grid-template-columns: 1fr auto; gap: 16px; align-items: center; }
  .platform-preview-name { font-size: 12.5px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; }
  .platform-preview-name .sub { display: inline-block; font-size: 10.5px; font-weight: 500; color: var(--ink-3); margin-left: 8px; }
  .platform-preview-state { display: inline-flex; align-items: center; gap: 6px; font-size: 9.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; color: var(--good); padding: 4px 10px; border-radius: 100px; background: rgba(74,222,128,0.08); border: 1px solid rgba(74,222,128,0.28); }
  .platform-preview-state .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--good); }

  /* Methodology card */
  .methodology-card { margin: 0 56px 0; padding: 16px 20px; background: linear-gradient(135deg, rgba(15,23,42,0.03) 0%, rgba(15,23,42,0.01) 100%); border: 1px solid var(--rule-light); border-radius: 10px; }
  .methodology-card h5 { font-size: 11px; font-weight: 800; color: var(--ink); letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 8px; }
  .methodology-card p { font-size: 11.5px; color: var(--ink-2); line-height: 1.6; }

  /* ============ Section 02 — External threat (brand blocks) ============ */
  .brand-summary-grid { display: grid; grid-template-columns: 1.2fr 1fr 1fr; gap: 12px; margin: 0 56px 22px; }
  .brand-summary-card { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 16px 18px; }
  .brand-summary-card.primary { border-left: 3px solid #F59E0B; }
  .brand-summary-num { font-size: 32px; font-weight: 900; color: var(--ink); letter-spacing: -0.04em; line-height: 1; margin-bottom: 4px; font-variant-numeric: tabular-nums; }
  .brand-summary-num.warn { color: #B45309; }
  .brand-summary-num.good { color: #15803D; }
  .brand-summary-label { font-size: 11px; font-weight: 700; color: var(--ink-3); letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 6px; }
  .brand-summary-detail { font-size: 11.5px; color: var(--ink-2); line-height: 1.5; }
  .brand-summary-detail strong { color: var(--ink); font-weight: 600; }
  .brand-watchlist { margin: 0 56px 18px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; overflow: hidden; }
  .brand-watchlist-empty { padding: 28px 22px; text-align: center; color: var(--ink-3); font-size: 12px; }
  .brand-watchlist-empty strong { color: var(--ink); display: block; margin-bottom: 4px; font-size: 13px; }
  .brand-watchlist-row { padding: 12px 18px; display: grid; grid-template-columns: 1fr auto auto; gap: 14px; align-items: center; border-bottom: 1px solid var(--rule-lighter); }
  .brand-watchlist-row:last-child { border-bottom: none; }
  .brand-watchlist-domain { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--ink); font-weight: 600; }
  .brand-watchlist-meta { font-size: 10.5px; color: var(--ink-3); }

  /* ============ Section 03 — Outbound posture ============ */
  .posture-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 0 56px 14px; }
  .posture-card { background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; padding: 14px 16px; border-left: 3px solid var(--ink-4); }
  .posture-card.good { border-left-color: var(--good); }
  .posture-card.warn { border-left-color: #F59E0B; }
  .posture-card.bad  { border-left-color: #EF4444; }
  .posture-card.missing { border-left-color: var(--ink-4); opacity: 0.85; }
  .posture-label { font-size: 9.5px; font-weight: 800; letter-spacing: 0.12em; text-transform: uppercase; color: var(--ink-3); margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }
  .posture-state { font-size: 16px; font-weight: 800; color: var(--ink); letter-spacing: -0.015em; margin-bottom: 6px; line-height: 1.2; }
  .posture-card.good .posture-state { color: #15803D; }
  .posture-card.warn .posture-state { color: #B45309; }
  .posture-card.bad  .posture-state { color: #B91C1C; }
  .posture-card.missing .posture-state { color: var(--ink-3); }
  .posture-detail { font-size: 10.5px; color: var(--ink-2); line-height: 1.45; }
  .posture-detail code { font-family: 'JetBrains Mono', monospace; font-size: 10px; background: rgba(15,23,42,0.05); padding: 1px 4px; border-radius: 3px; }
  .posture-mini-pill { font-size: 8.5px; font-weight: 800; letter-spacing: 0.08em; padding: 2px 6px; border-radius: 3px; }
  .posture-card.good .posture-mini-pill { background: rgba(74,222,128,0.15); color: #15803D; }
  .posture-card.warn .posture-mini-pill { background: #FEF3C7; color: #92400E; }
  .posture-card.bad  .posture-mini-pill { background: #FEE2E2; color: #991B1B; }
  .posture-card.missing .posture-mini-pill { background: rgba(100,116,139,0.12); color: var(--ink-3); }
  .posture-explainer { margin: 8px 56px 18px; padding: 14px 18px; background: rgba(0,150,204,0.04); border: 1px solid rgba(0,150,204,0.18); border-radius: 8px; font-size: 11.5px; color: var(--ink-2); line-height: 1.55; }
  .posture-explainer strong { color: var(--ink); }

  /* ============ Section 03 — Defensive controls audit ============ */
  .controls-summary-strip { margin: 0 56px 16px; background: linear-gradient(135deg, var(--ink) 0%, #1E293B 100%); color: var(--white); border-radius: 12px; padding: 16px 22px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }
  .css-headline { font-size: 13px; font-weight: 500; color: rgba(255,255,255,0.85); letter-spacing: -0.005em; }
  .css-headline strong { color: var(--cyan); font-weight: 800; font-size: 16px; letter-spacing: -0.015em; margin-right: 2px; }
  .css-counts { display: flex; gap: 14px; }
  .css-count { display: inline-flex; align-items: center; gap: 6px; font-size: 10.5px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: rgba(255,255,255,0.85); }
  .css-count .css-dot { width: 7px; height: 7px; border-radius: 50%; }
  .css-count.good .css-dot { background: #4ADE80; }
  .css-count.warn .css-dot { background: #F59E0B; }
  .css-count.bad  .css-dot { background: #EF4444; }

  /* DMARC mandate callout — only renders when DMARC is below full enforcement */
  .mandate-callout { margin: 0 56px 14px; padding: 14px 18px; background: linear-gradient(135deg, rgba(194,65,12,0.06) 0%, rgba(194,65,12,0.02) 100%); border: 1px solid rgba(194,65,12,0.28); border-radius: 10px; display: grid; grid-template-columns: 30px 1fr; gap: 14px; align-items: start; }
  .mandate-callout-icon { width: 26px; height: 26px; border-radius: 50%; background: var(--tag-action); color: white; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 800; flex-shrink: 0; margin-top: 1px; }
  .mandate-callout-title { font-size: 12.5px; font-weight: 800; color: var(--ink); letter-spacing: -0.005em; margin-bottom: 5px; }
  .mandate-callout-text { font-size: 11px; color: var(--ink-2); line-height: 1.55; }
  .mandate-callout-text strong { color: var(--ink); font-weight: 700; }

  .controls-category { margin: 0 56px 12px; }
  .cc-header { display: flex; justify-content: space-between; align-items: baseline; padding: 0 2px 6px; border-bottom: 1px solid var(--rule-light); margin-bottom: 4px; }
  .cc-title { font-size: 10.5px; font-weight: 800; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink); }
  .cc-count { font-size: 9.5px; font-weight: 700; color: var(--ink-3); letter-spacing: 0.04em; }

  .control-row { display: grid; grid-template-columns: 165px 1fr; gap: 14px; padding: 8px 0; border-bottom: 1px dashed var(--rule-lighter); align-items: start; }
  .control-row:last-child { border-bottom: none; }
  .control-name { font-size: 11.5px; font-weight: 700; color: var(--ink); letter-spacing: -0.005em; padding-top: 2px; }
  .control-mid { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .control-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 100px; font-size: 9px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; white-space: nowrap; border: 1px solid; }
  .control-badge.deployed { color: #15803D; background: rgba(74,222,128,0.10); border-color: rgba(74,222,128,0.28); }
  .control-badge.partial  { color: #B45309; background: rgba(245,158,11,0.10); border-color: rgba(245,158,11,0.28); }
  .control-badge.missing  { color: #B91C1C; background: rgba(239,68,68,0.10);  border-color: rgba(239,68,68,0.30); }
  .control-badge.limited  { color: var(--ink-3); background: rgba(100,116,139,0.08); border-color: rgba(100,116,139,0.25); }
  .control-trust-marker { display: inline-block; color: #B45309; font-size: 12px; font-weight: 700; margin-left: 3px; vertical-align: -1px; }
  .control-evidence { font-size: 10.5px; color: var(--ink-2); line-height: 1.45; flex: 1; min-width: 0; }
  .control-action { font-size: 10.5px; color: var(--tag-action); line-height: 1.45; grid-column: 2; padding-top: 3px; font-style: italic; }

  /* ============ Section 04 — Hidden infrastructure ============ */

  /* Registration strip (top of §07) */
  .registration-strip { margin: 0 56px 14px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; overflow: hidden; }
  .registration-strip-header { padding: 9px 18px; background: rgba(15,23,42,0.025); border-bottom: 1px solid var(--rule-lighter); display: flex; justify-content: space-between; align-items: center; }
  .registration-strip-header h4 { font-size: 10.5px; font-weight: 800; color: var(--ink); letter-spacing: 0.08em; text-transform: uppercase; }
  .registration-strip-header .meta { font-size: 9.5px; font-weight: 600; color: var(--ink-3); letter-spacing: 0.04em; }
  .registration-cells { display: grid; grid-template-columns: repeat(4, 1fr); }
  .registration-cell { padding: 12px 16px; border-right: 1px solid var(--rule-lighter); }
  .registration-cell:last-child { border-right: none; }
  .reg-cell-label { font-size: 9px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-4); margin-bottom: 5px; }
  .reg-cell-value { font-size: 13.5px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; line-height: 1.2; }
  .reg-cell-value.email { font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 500; word-break: break-word; }
  .reg-cell-value.good { color: #15803D; }
  .reg-cell-value.warn { color: #B45309; }
  .reg-cell-value.bad  { color: #B91C1C; }
  .reg-cell-sub { font-size: 10px; font-weight: 500; color: var(--ink-3); margin-top: 3px; line-height: 1.35; }
  .reg-cell-sub .risk-chip { display: inline-flex; align-items: center; gap: 4px; padding: 1px 6px; border-radius: 3px; font-size: 9px; font-weight: 700; letter-spacing: 0.04em; }
  .reg-cell-sub .risk-chip.good { background: rgba(74,222,128,0.12); color: #15803D; }
  .reg-cell-sub .risk-chip.warn { background: rgba(245,158,11,0.12); color: #B45309; }
  .reg-cell-sub .risk-chip.med  { background: rgba(100,116,139,0.10); color: var(--ink-3); }
  .reg-cell-sub .risk-chip.bad  { background: rgba(239,68,68,0.12); color: #B91C1C; }
  .registration-address { padding: 9px 18px; border-top: 1px solid var(--rule-lighter); background: rgba(15,23,42,0.015); display: flex; gap: 10px; align-items: center; font-size: 11px; color: var(--ink-3); }
  .registration-address .addr-label { font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; color: var(--ink-4); font-size: 9px; white-space: nowrap; }
  .registration-address .addr-value { color: var(--ink-2); font-style: italic; }

  /* Estate overview */
  .estate-overview { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; margin: 0 56px 18px; padding: 14px 0; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; }
  .estate-stat { padding: 0 22px; border-right: 1px solid var(--rule-lighter); }
  .estate-stat:last-child { border-right: none; }
  .estate-stat-num { font-size: 26px; font-weight: 800; color: var(--ink); letter-spacing: -0.03em; line-height: 1; margin-bottom: 4px; font-variant-numeric: tabular-nums; }
  .estate-stat-num.alert { color: #B91C1C; }
  .estate-stat-num.warn  { color: #B45309; }
  .estate-stat-num.good  { color: #15803D; }
  .estate-stat-label { font-size: 9.5px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-3); line-height: 1.3; }
  .estate-callout { margin: 0 56px 14px; padding: 12px 18px; border-radius: 8px; font-size: 11.5px; line-height: 1.55; display: flex; gap: 12px; align-items: flex-start; }
  .estate-callout.warn { background: rgba(245,158,11,0.06); border: 1px solid rgba(245,158,11,0.25); color: var(--ink-2); }
  .estate-callout.good { background: rgba(74,222,128,0.06); border: 1px solid rgba(74,222,128,0.25); color: var(--ink-2); }
  .estate-callout strong { color: var(--ink); font-weight: 600; }
  .estate-callout .icon { width: 22px; height: 22px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800; color: white; }
  .estate-callout.warn .icon { background: #F59E0B; }
  .estate-callout.good .icon { background: var(--good); }
  .subdomain-sample-table-wrap { margin: 0 56px 18px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; overflow: hidden; }
  .subdomain-sample-header { padding: 10px 18px; background: rgba(15,23,42,0.02); border-bottom: 1px solid var(--rule-light); font-size: 11px; font-weight: 700; color: var(--ink); display: flex; justify-content: space-between; align-items: center; }
  .subdomain-sample-header .meta { font-size: 9.5px; font-weight: 600; color: var(--ink-3); letter-spacing: 0.04em; }
  .sample-table { width: 100%; border-collapse: collapse; }
  .sample-table thead th { text-align: left; padding: 7px 14px; font-size: 8.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--ink-4); border-bottom: 1px solid var(--rule-light); }
  .sample-table tbody td { padding: 8px 14px; font-size: 11px; border-bottom: 1px solid var(--rule-lighter); vertical-align: middle; color: var(--ink-2); }
  .sample-table tbody tr:last-child td { border-bottom: none; }
  .sample-table .host-cell { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: var(--ink); }
  .sample-table .risk-cell { width: 88px; }
  .risk-mini { display: inline-flex; align-items: center; gap: 5px; padding: 2px 7px; border-radius: 100px; font-size: 8.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; border: 1px solid; }
  .risk-mini .dot { width: 5px; height: 5px; border-radius: 50%; }
  .risk-mini.high     { color: #B91C1C; background: rgba(239,68,68,0.08);  border-color: rgba(239,68,68,0.32); }
  .risk-mini.high .dot     { background: #EF4444; }
  .risk-mini.med      { color: #92400E; background: rgba(245,158,11,0.06); border-color: rgba(245,158,11,0.28); }
  .risk-mini.med  .dot     { background: #F59E0B; }
  .risk-mini.low      { color: var(--ink-3); background: rgba(100,116,139,0.06); border-color: rgba(100,116,139,0.22); }
  .risk-mini.low  .dot     { background: var(--ink-4); }

  /* ============ Section 05 — Timeline ============ */
  .timeline-summary { margin: 0 56px 16px; padding: 14px 20px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; font-size: 12.5px; color: var(--ink-2); line-height: 1.6; }
  .timeline-summary strong { color: var(--ink); font-weight: 600; }
  .signal-grid { margin: 0 56px 18px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .signal-card { background: var(--white); border: 1px solid var(--rule-light); border-radius: 8px; padding: 11px 14px; display: flex; justify-content: space-between; align-items: center; gap: 12px; }
  .signal-card.active { border-color: rgba(245,158,11,0.4); background: rgba(245,158,11,0.04); }
  .signal-card.inactive { opacity: 0.7; }
  .signal-label { font-size: 11px; font-weight: 600; color: var(--ink); }
  .signal-state { font-size: 9.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; padding: 3px 8px; border-radius: 100px; }
  .signal-state.stable { color: var(--ink-3); background: rgba(100,116,139,0.08); }
  .signal-state.changed { color: #B45309; background: rgba(245,158,11,0.12); }
  .timeline-baseline { margin: 0 56px 0; padding: 14px 18px; background: rgba(0,150,204,0.04); border: 1px solid rgba(0,150,204,0.18); border-radius: 8px; font-size: 11.5px; color: var(--ink-2); line-height: 1.55; }
  .timeline-baseline strong { color: var(--ink); }

  /* ============ Section 06 — Roadmap ============ */
  .roadmap-grid { margin: 0 56px 16px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .roadmap-col { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 16px 18px; border-top: 3px solid var(--ink-4); }
  .roadmap-col.fortnight { border-top-color: #EF4444; }
  .roadmap-col.quarter   { border-top-color: #F59E0B; }
  .roadmap-col.year      { border-top-color: var(--cyan-page); }
  .roadmap-col-header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--rule-lighter); }
  .roadmap-col-title { font-size: 13px; font-weight: 800; color: var(--ink); letter-spacing: -0.01em; }
  .roadmap-col-count { font-size: 18px; font-weight: 900; color: var(--ink-4); letter-spacing: -0.02em; line-height: 1; font-variant-numeric: tabular-nums; }
  .roadmap-col.fortnight .roadmap-col-count { color: #B91C1C; }
  .roadmap-col.quarter   .roadmap-col-count { color: #B45309; }
  .roadmap-col.year      .roadmap-col-count { color: var(--cyan-deep); }
  .roadmap-item { padding: 8px 0; border-bottom: 1px dashed var(--rule-lighter); }
  .roadmap-item:last-child { border-bottom: none; }
  .roadmap-item-title { font-size: 11.5px; font-weight: 700; color: var(--ink); line-height: 1.35; margin-bottom: 2px; }
  .roadmap-item-meta  { font-size: 9.5px; font-weight: 600; color: var(--ink-3); letter-spacing: 0.04em; }
  .roadmap-empty { color: var(--ink-4); font-size: 11px; font-style: italic; padding: 6px 0; }
  .roadmap-narrative { margin: 0 56px 0; padding: 14px 18px; background: rgba(194,65,12,0.04); border: 1px solid rgba(194,65,12,0.18); border-radius: 8px; font-size: 11.5px; color: var(--ink-2); line-height: 1.6; }
  .roadmap-narrative strong { color: var(--ink); font-weight: 600; }

  /* ============ Section 10 — Glossary ============ */
  .glossary-grid { margin: 0 56px 14px; display: grid; grid-template-columns: 1fr 1fr; gap: 0 28px; }
  .glossary-item { padding: 10px 0; border-bottom: 1px solid var(--rule-lighter); }
  .glossary-term { font-size: 11.5px; font-weight: 800; color: var(--ink); letter-spacing: -0.005em; margin-bottom: 2px; }
  .glossary-term .acronym { font-family: 'JetBrains Mono', monospace; color: var(--cyan-deep); font-size: 11px; }
  .glossary-def { font-size: 10.5px; color: var(--ink-2); line-height: 1.5; }
  .methodology-block { margin: 0 56px 0; padding: 16px 20px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; }
  .methodology-block h4 { font-size: 12px; font-weight: 800; color: var(--ink); margin-bottom: 8px; letter-spacing: -0.005em; }
  .methodology-block p { font-size: 11px; color: var(--ink-2); line-height: 1.6; margin-bottom: 8px; }
  .methodology-block p:last-child { margin-bottom: 0; }
  .methodology-block strong { color: var(--ink); font-weight: 600; }
  /* Impersonation campaign table (page 6) */
  .trend-pill { display: inline-block; padding: 3px 9px; border-radius: 100px; font-size: 10px; font-weight: 700; letter-spacing: 0.03em; white-space: nowrap; }
  .trend-pill.up   { background: rgba(255,107,107,0.10); color: #C2410C; border: 1px solid rgba(255,107,107,0.35); }
  .trend-pill.down { background: rgba(74,222,128,0.10); color: #15803D; border: 1px solid rgba(74,222,128,0.35); }
  .trend-pill.flat { background: rgba(100,116,139,0.08); color: var(--ink-3); border: 1px solid var(--rule-light); }
  .lure-chip { display: inline-block; font-family: 'JetBrains Mono', monospace; font-size: 9.5px; background: rgba(15,23,42,0.05); color: var(--ink-2); padding: 2px 7px; border-radius: 4px; margin: 1px 3px 1px 0; border: 1px solid var(--rule-light); }
  .lure-chip.muted { background: transparent; color: var(--ink-3); border-style: dashed; }
  /* Lookalike-candidates section (lower confidence) */
  .lookalike-section { margin: 14px 56px 0; padding: 14px 18px; background: rgba(100,116,139,0.04); border: 1px dashed var(--rule-light); border-radius: 12px; }
  .lookalike-header { font-size: 12px; font-weight: 700; color: var(--ink-2); margin-bottom: 8px; display: flex; align-items: center; gap: 9px; }
  .lookalike-badge { font-size: 8.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-3); background: rgba(100,116,139,0.12); border: 1px solid var(--rule-light); border-radius: 100px; padding: 2px 8px; }
  .lookalike-intro { font-size: 11px; color: var(--ink-3); line-height: 1.55; margin: 0 0 10px; }
  .platform-preview-state.active { color: #C2410C; font-weight: 700; }
  .platform-preview-state.active .dot { background: #C2410C; }
  /* Brand watchlist (page 7, populated state) */
  .brand-watchlist-header { font-size: 12px; font-weight: 700; color: var(--ink); margin-bottom: 10px; }
  .brand-watchlist-header span { font-weight: 500; color: var(--ink-3); }
  .brand-watchlist-items { margin-bottom: 10px; }
  .brand-watchlist-items .lure-chip { font-size: 11px; padding: 4px 10px; margin: 2px 6px 2px 0; }
  .brand-watchlist-note { font-size: 11px; color: var(--ink-3); line-height: 1.55; margin: 0; }
  /* IT remediation tear-off */
  .remediation-list { margin: 0 56px; }
  .remediation-item { display: grid; grid-template-columns: 34px 1fr 22px; gap: 12px; align-items: start; background: var(--white); border: 1px solid var(--rule-light); border-left: 3px solid var(--ink-4); border-radius: 8px; padding: 12px 14px; margin-bottom: 8px; break-inside: avoid; }
  .remediation-item.critical { border-left-color: #B91C1C; }
  .remediation-item.high { border-left-color: #EF4444; }
  .remediation-item.medium { border-left-color: var(--warn); }
  .remediation-item.low { border-left-color: var(--ink-4); }
  .rem-sev.low { background: rgba(100,116,139,0.10); color: var(--ink-3); }
  .control-impact { font-size: 9px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; padding: 2px 7px; border-radius: 100px; margin-left: 7px; }
  .control-impact.high { background: rgba(255,107,107,0.12); color: #B91C1C; }
  .control-impact.medium { background: rgba(244,184,96,0.16); color: #B45309; }
  .control-impact.low { background: rgba(100,116,139,0.10); color: var(--ink-3); }
  .rem-rank { font-size: 14px; font-weight: 900; color: var(--ink-4); font-variant-numeric: tabular-nums; }
  .rem-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .rem-sev { font-size: 8.5px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; padding: 1px 7px; border-radius: 100px; }
  .rem-sev.critical { background: rgba(185,28,28,0.12); color: #B91C1C; }
  .rem-sev.high { background: rgba(239,68,68,0.12); color: #DC2626; }
  .rem-sev.medium { background: rgba(244,184,96,0.16); color: #B45309; }
  .rem-area { font-size: 9.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--ink-4); }
  .rem-title { font-size: 12.5px; font-weight: 700; color: var(--ink); margin-bottom: 5px; }
  .rem-current, .rem-step { font-size: 11px; line-height: 1.5; color: var(--ink-2); margin-top: 2px; }
  .rem-label { font-weight: 700; color: var(--ink-3); }
  .rem-check { width: 18px; height: 18px; border: 1.5px solid var(--rule-light); border-radius: 4px; margin-top: 2px; }
  /* External-threat compact summary */
  .es-block { margin: 0 56px 16px; }
  .es-label { font-size: 11px; font-weight: 800; color: var(--ink); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
  .es-note { font-weight: 600; color: var(--ink-4); text-transform: none; letter-spacing: 0; font-size: 9.5px; margin-left: 6px; }
  .es-foot { font-size: 9.5px; color: var(--ink-3); line-height: 1.5; margin: 4px 0 0; }
  .es-line { font-size: 12px; color: var(--ink-2); line-height: 1.7; margin: 0; }
  .es-line.muted { color: var(--ink-3); font-size: 11px; }
  .es-empty { font-size: 11.5px; color: var(--ink-3); font-style: italic; margin: 0; }
  /* Full DNS records */
  .dns-group { margin: 0 56px 12px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; overflow: hidden; }
  .dns-group-head { display: flex; justify-content: space-between; align-items: center; padding: 8px 16px; background: rgba(15,23,42,0.02); border-bottom: 1px solid var(--rule-light); }
  .dns-type { font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; color: var(--ink); letter-spacing: 0.05em; }
  .dns-weak-count { font-size: 9.5px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; color: #B91C1C; background: rgba(255,107,107,0.10); border-radius: 100px; padding: 2px 9px; }
  .dns-table { width: 100%; border-collapse: collapse; }
  .dns-table td { font-size: 11px; padding: 6px 16px; border-bottom: 1px solid var(--rule-lighter); vertical-align: top; }
  .dns-table tr:last-child td { border-bottom: none; }
  .dns-table tr.weak td { background: rgba(255,107,107,0.04); }
  .dns-val { font-family: 'JetBrains Mono', monospace; color: var(--ink-2); word-break: break-all; width: 52%; }
  .dns-note { color: var(--ink-3); font-size: 10.5px; }
  .dns-table tr.weak .dns-note { color: #B45309; font-weight: 600; }
  .dns-flag { color: #B91C1C; font-weight: 800; }
  /* Infrastructure & routing intelligence */
  .infra-overview { display: grid; grid-template-columns: 1.4fr 1fr 0.8fr; gap: 0; margin: 0 56px 16px; padding: 14px 0; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; }
  .infra-cell { padding: 0 20px; border-right: 1px solid var(--rule-lighter); }
  .infra-cell:last-child { border-right: none; }
  .infra-cell-label { font-size: 9px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-3); margin-bottom: 5px; }
  .infra-cell-value { font-size: 15px; font-weight: 800; color: var(--ink); letter-spacing: -0.01em; }
  .infra-cell-value.mono { font-family: 'JetBrains Mono', monospace; font-size: 13px; }
  .infra-cell-sub { font-size: 10.5px; color: var(--ink-3); margin-top: 2px; }
  .infra-providers { display: grid; grid-template-columns: 1fr 1fr; gap: 0; margin: 0 56px 16px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; }
  .infra-prov { padding: 11px 18px; display: flex; flex-direction: column; gap: 2px; }
  .infra-prov + .infra-prov { border-left: 1px solid var(--rule-lighter); }
  .infra-prov-label { font-size: 9px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-3); }
  .infra-prov-val { font-size: 13px; font-weight: 700; color: var(--ink); }
  .infra-prov-cat { font-size: 10.5px; font-weight: 500; color: var(--ink-3); }
  .infra-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 0 56px 16px; }
  .infra-panel { background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; padding: 14px 18px; }
  .infra-panel-title { font-size: 11px; font-weight: 800; color: var(--ink); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: baseline; }
  .infra-scale { font-size: 8.5px; font-weight: 600; color: var(--ink-4); letter-spacing: 0; text-transform: none; }
  .infra-table { width: 100%; border-collapse: collapse; }
  .infra-table td { font-size: 11.5px; color: var(--ink-2); padding: 5px 0; border-bottom: 1px solid var(--rule-lighter); }
  .infra-table tr:last-child td { border-bottom: none; }
  .infra-table td.r { text-align: right; font-weight: 600; color: var(--ink); }
  .infra-pill { display: inline-block; padding: 2px 9px; border-radius: 100px; font-size: 10px; font-weight: 800; letter-spacing: 0.03em; }
  .infra-pill.good { background: rgba(74,222,128,0.12); color: #15803D; }
  .infra-pill.warn { background: rgba(244,184,96,0.15); color: #B45309; }
  .infra-pill.bad  { background: rgba(255,107,107,0.12); color: #B91C1C; }
  .infra-score { font-variant-numeric: tabular-nums; font-weight: 800; padding: 1px 7px; border-radius: 5px; }
  .infra-score.good { color: #15803D; } .infra-score.warn { color: #B45309; } .infra-score.bad { background: rgba(255,107,107,0.10); color: #B91C1C; }
  .infra-feeds, .infra-reasons { margin: 0 56px 14px; font-size: 11px; color: var(--ink-2); }
  .infra-feeds-label { font-weight: 700; color: var(--ink); margin-right: 6px; }
  .infra-feeds .infra-pill { margin: 0 4px 4px 0; }
  .infra-cotenancy { margin: 0 56px 14px; background: rgba(255,107,107,0.04); border: 1px solid rgba(255,107,107,0.20); border-radius: 10px; padding: 12px 16px; }
  .infra-cotenant { font-size: 11.5px; color: var(--ink-2); line-height: 1.6; }
  .infra-cotenant code { font-family: 'JetBrains Mono', monospace; font-size: 10px; background: rgba(15,23,42,0.05); padding: 1px 5px; border-radius: 4px; }
  /* Teaser CTA */
  .teaser-cta { display: grid; grid-template-columns: 40px 1fr; gap: 14px; align-items: center; background: rgba(0,150,204,0.05); border: 1px solid rgba(0,150,204,0.25); border-radius: 12px; padding: 16px 20px; margin-top: 18px; }
  .teaser-cta-icon { font-size: 22px; text-align: center; }
  .teaser-cta-body h4 { font-size: 13px; font-weight: 800; color: var(--ink); margin: 0 0 4px; }
  .teaser-cta-body p { font-size: 11.5px; color: var(--ink-2); line-height: 1.55; margin: 0; }
</style>
</head>
<body>
{% set ns = namespace(page=0) %}

{# ============ MACROS ============ #}
{% macro brand_block(light=False) -%}
  <div class="brand">
    <div class="brand-mark">
      <svg viewBox="0 0 24 24" fill="none">
        <path d="M4 7L12 3L20 7L12 11L4 7Z" fill="white" opacity="0.95"/>
        <path d="M4 12L12 16L20 12" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.7"/>
        <path d="M4 17L12 21L20 17" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.45"/>
      </svg>
    </div>
    <div class="brand-wordmark">DATAZAG</div>
    <div class="brand-divider"></div>
    <div class="brand-product">{{ product_label }}{% if is_teaser %} · Teaser{% endif %}</div>
  </div>
{%- endmacro %}

{# ============ PAGE 1 — COVER ============ #}
{% if "cover" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page">
  <div class="topbar">
    {{ brand_block() }}
    <div class="topbar-right">
      <div class="topbar-id">
        {{ quarter_label }} · Confidential
        <strong>{{ domain }}</strong>
      </div>
    </div>
  </div>

  <div class="cover">
    <span class="eyebrow">
      <span class="dot"></span>
      {{ quarter_label }} &middot; Attack surface assessment &middot; {{ domain }}
    </span>

    <h1 class="cover-title">
      {{ cover_hook.title|safe }}
    </h1>

    <p class="cover-deck">
      {{ cover_hook.deck|safe }}
    </p>

    <div class="dual-score">
      <div class="dual-score-card platform">
        <div class="dsc-label">
          <span class="dsc-icon">▲</span>
          The attacker problem &mdash; platform impersonation
          <span class="dsc-grade-ref">{{ platform_grade.band }} &middot; {{ platform_score }}/100 exposure</span>
        </div>
        {% if suppress_platform_counts %}
        <div class="dsc-state">{{ vendors | length }} platform{{ 's' if vendors | length != 1 else '' }} detected in your stack &mdash; each an impersonation lure</div>
        <p class="dsc-qualifier">Every platform your staff log into is a brand an attacker can imitate. <strong>Platform impersonation is usually how brand impersonation starts.</strong></p>
        {% elif impersonation_total_30d > 0 %}
        <div class="dsc-state" style="color:var(--bad);">{{ impersonation_total_30d }} lookalike domains &mdash; {{ active_campaign_count }} of your platform{{ 's' if active_campaign_count != 1 else '' }} impersonated (30d)</div>
        <p class="dsc-qualifier">Attackers are imitating the platforms your staff use daily. <strong>Platform impersonation is usually how brand impersonation starts</strong> &mdash; the same technique then targets your customers.</p>
        {% elif not impersonation_lookup_ok %}
        <div class="dsc-state">Impersonation check unavailable &mdash; {{ vendors | length }} trusted platforms in your stack</div>
        <p class="dsc-qualifier">Our certificate-log rollup was unreachable when this report ran, so platform impersonation was <strong>not checked</strong> &mdash; this is not an all-clear.</p>
        {% else %}
        <div class="dsc-state">{{ platform_state.descriptor }} &mdash; {{ vendors | length }} trusted platforms in your stack</div>
        <p class="dsc-qualifier">No active impersonation of your platforms in the last 30 days &mdash; but every platform here is a lure. <strong>Platform impersonation is usually how brand impersonation starts.</strong></p>
        {% endif %}
        {% if platform_list.platforms %}
        <div class="dsc-platform-list">
          {% for item in platform_list.platforms %}<span class="dsc-platform-name{% if item.cname_only %} cname-only{% endif %}">{{ item.name }}{% if item.cname_only %}<span class="dsc-platform-marker">◆</span>{% endif %}</span>{% if not loop.last %} <span class="dsc-platform-sep">·</span> {% endif %}{% endfor %}
        </div>
        {% if platform_list.has_cname_items %}
        <p class="dsc-platform-footnote"><span class="dsc-platform-marker">◆</span> <strong>{{ platform_list.cname_count }} surfaced from subdomain CNAMEs.</strong> If we found these from outside, so can an attacker &mdash; it is all public DNS.</p>
        {% endif %}
        {% endif %}
        <div class="dsc-actions">
          <div class="dsc-actions-label">Hardening checklist <span class="dsc-actions-caption">externally unverifiable</span></div>
          <ul class="dsc-actions-list">
            {% for action in platform_actions %}
            <li>{{ action }}</li>
            {% endfor %}
          </ul>
        </div>
        <p class="dsc-context">
          Datazag observes <strong>85&ndash;90%</strong> of certificate-based impersonation targeting platforms like these.
        </p>
      </div>

      <div class="dual-score-card infra">
        <div class="dsc-label">
          <span class="dsc-icon">◉</span>
          Your defence weaknesses &mdash; trust &amp; infrastructure
          <span class="dsc-grade-ref">{{ infra_grade.band }} &middot; {{ infra_score }}/100 exposure</span>
        </div>
        <div class="dsc-state">{{ infra_grade.headline }}</div>
        <p class="dsc-qualifier">The gaps in your public DNS &mdash; DMARC, SPF, DNSSEC, CAA, certificates, routing &mdash; that decide <strong>how easily your own domain can be spoofed, hijacked or mis-issued against</strong>. A separate surface from the platform lures above.</p>
        <div class="dsc-actions">
          <div class="dsc-actions-label">Open gaps</div>
          <ul class="dsc-actions-list compact">
            {% for bit in infra_summary_bits %}
            <li>{{ bit }}</li>
            {% endfor %}
          </ul>
        </div>
        <p class="dsc-context">
          Each gap is fixable through changes you control. The roadmap is in <strong>section {{ section_no.roadmap }}</strong>.
        </p>
      </div>
    </div>

    <div class="overall-grade-band">
      <div class="ogb-letter">{{ grade.letter }}</div>
      <div class="ogb-body">
        <div class="ogb-label">External exposure &middot; the attacker problem and your defences, combined</div>
        <div class="ogb-band">{{ grade.band }}</div>
        <div class="ogb-scoreline">Risk score {{ overall_score }}/100 &mdash; higher is more exposed &middot; grade {{ grade.letter }}</div>
        <div class="ogb-detail">
          {% if driving_surface == 'platform' %}
          The bigger driver is the attacker problem &mdash; active impersonation of the platforms your staff use. That is defended inside your tenants (MFA, Conditional Access), which this report cannot see; section 07 sequences what you can fix from the outside.
          {% elif driving_surface == 'infrastructure' %}
          The bigger driver is your defence weaknesses &mdash; short-effort DNS, certificate and email-auth gaps that let a campaign travel further than it should. Section {{ section_no.roadmap }} prioritises them.
          {% else %}
          Both warrant attention. Section {{ section_no.roadmap }} sequences the changes by impact.
          {% endif %}
        </div>
      </div>
    </div>

    <div class="meta-strip">
      <div class="meta-cell"><div class="meta-label">Prepared for</div><div class="meta-value">{{ org_name }}<span class="meta-sub">{{ org_locale }}</span></div></div>
      <div class="meta-cell"><div class="meta-label">Domain</div><div class="meta-value">{{ domain }}<span class="meta-sub">{{ subdomain_count }} subdomains observed</span></div></div>
      <div class="meta-cell"><div class="meta-label">Snapshot</div><div class="meta-value">{{ snapshot_date_pretty }}<span class="meta-sub">{{ quarter_label }}</span></div></div>
      <div class="meta-cell"><div class="meta-label">Corpus</div><div class="meta-value">320M domains<span class="meta-sub">Hourly refresh</span></div></div>
    </div>

    <div class="corpus">
      <div class="corpus-pulse"></div>
      <div class="corpus-text"><strong>Live</strong> — cross-referenced against 40+ threat feeds &middot; updated continuously</div>
      <div class="corpus-bar"></div>
    </div>
  </div>

  <div class="cover-footer">
    <span>Datazag Health Report · Confidential</span>
    <span class="right">Page {{ ns.page }} of {{ total_pages }}</span>
  </div>
</div>
{% endif %}

{# ============ FREE HEALTH REPORT — BRAND FUNNEL ============ #}
{% if "brand_funnel" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Brand impersonation<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">Could someone impersonate {{ org_name }}?</h1>
    {% if brand_funnel.monitored %}
    <p class="section-headline">Continuous brand monitoring is active for <code style="font-family:'JetBrains Mono',monospace;font-size:12px;background:rgba(15,23,42,0.05);padding:1px 5px;border-radius:3px;">{{ domain_root }}</code>. Below: the lookalike history, plus the candidate attack surface generated at report time.</p>
    {% else %}
    <p class="section-headline">Brand monitoring is <strong>not yet active</strong> for {{ domain_root }}, so there is no history to show. Instead we generated the candidate attack surface an attacker could register today.</p>
    {% endif %}
  </div>

  {# The active-scan funnel — generated → registered → resolving → attack-signature #}
  <div class="footprint-summary">
    {% for s in brand_funnel.stages %}
    <div class="footprint-stat"><div class="footprint-stat-num{% if s.key == 'dga' and s.count > 0 %} alert{% elif s.key == 'resolving' and s.count > 0 %} warn{% endif %}">{{ s.count }}</div><div class="footprint-stat-label">{{ s.label }}</div></div>
    {% endfor %}
  </div>
  {% if brand_funnel.checked and brand_funnel.checked < brand_funnel.generated %}
  <p class="es-foot">Top candidates checked by priority; the rest were generated but not resolved (cost-capped &mdash; the full set is checked under the paid Watch).</p>
  {% endif %}

  {% if brand_funnel.near_miss %}
  <div class="es-block">
    <div class="es-label">Highlighted near-miss</div>
    <p class="es-line"><span class="lure-chip">{{ brand_funnel.near_miss.domain }}</span> &mdash;
      {% if brand_funnel.near_miss.registered %}already registered{% else %}<strong>not registered today, but registrable right now</strong>{% endif %}.
      A convincing lookalike of <code style="font-family:'JetBrains Mono',monospace;font-size:11px;background:rgba(15,23,42,0.05);padding:1px 4px;border-radius:3px;">{{ domain_root }}</code> an attacker could stand up for credential-phishing or invoice redirection.</p>
  </div>
  {% endif %}

  {% if brand_funnel.samples %}
  <div class="es-block">
    <div class="es-label">Generated candidate surface <span class="es-note">checked against the corpus</span></div>
    <table class="vendor-table">
      <thead><tr><th>Candidate</th><th>State</th><th>Cert seen</th></tr></thead>
      <tbody>
        {% for c in brand_funnel.samples %}
        <tr>
          <td class="name-cell">{{ c.domain }}</td>
          <td><span class="infra-pill {{ 'bad' if c.status == 'resolving' else 'warn' if c.status == 'parked' else 'good' }}">{{ c.status }}</span></td>
          <td>{% if c.has_cert %}<span class="infra-pill warn">observed</span>{% else %}&mdash;{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if brand_funnel.monitored and brand_funnel.own_brand_30d > 0 %}
  <div class="es-block">
    <div class="es-label">Observed lookalikes <span class="es-note">monitored history · 30 days</span></div>
    <p class="es-line"><strong>{{ brand_funnel.own_brand_30d }}</strong> lookalike domain(s) targeting {{ domain_root }}:
      {% for d in brand_funnel.own_brand_samples %}<span class="lure-chip">{{ d }}</span>{% endfor %}</p>
  </div>
  {% endif %}

  {# §5 paid-tier pitch — capability description only, no per-domain data #}
  <div class="es-block">
    <div class="es-label">What Brand Impersonation Watch adds</div>
    <p class="es-line muted"><strong>Continuous detection</strong> &mdash; new lookalike certificates matched within seconds of issuance.</p>
    <p class="es-line muted"><strong>Weaponization verdict</strong> &mdash; whether each live lookalike serves a credential-capture form using your brand.</p>
    <p class="es-line muted"><strong>Takedown intelligence</strong> &mdash; how long takedown takes on that host, and whether it acts on abuse reports.</p>
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ PAGE 2 — TOC ============ #}
{% if "toc" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Inside this report<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="toc-header">
    <div class="toc-eyebrow">A guided tour</div>
    <h2 class="toc-title">Mapping your attack surface, in {{ toc_items | length }} sections.</h2>
    <p class="toc-lede">This report maps your attack surface and gives you a roadmap to reduce it. Every section is <strong>Context</strong>, <strong>Findings</strong> or <strong>Action</strong>. Read it in order, or take sections {{ section_no.glance }}, {{ section_no.external_summary }} and {{ section_no.roadmap }} as the essentials.</p>
  </div>
  <ol class="toc-list">
    {% for item in toc_items %}
    <li class="toc-item">
      <span class="toc-num">{{ "%02d"|format(loop.index) }}</span>
      <div class="toc-content">
        <h4>{{ item.title }}</h4>
        <p>{{ item.desc | safe }}</p>
      </div>
      <span class="toc-tag {{ item.kind }}"><span class="tag-dot"></span>{{ item.kind | capitalize }}</span>
    </li>
    {% endfor %}
  </ol>
  <div class="toc-callout">
    <div class="toc-callout-icon">★</div>
    <div>
      <h5>How to read this report</h5>
      <p><strong>Ten minutes:</strong> sections {{ section_no.glance }}, {{ section_no.external_summary }} and {{ section_no.roadmap }}. <strong>Thirty:</strong> add {{ section_no.controls }} &mdash; your defensive controls. Every section opens in plain English before the technical detail.</p>
    </div>
  </div>
  <div class="toc-spacer"></div>
  <div class="cover-footer">
    <span>Datazag Health Report · Confidential</span>
    <span class="right">Page {{ ns.page }} of {{ total_pages }}</span>
  </div>
</div>
{% endif %}

{# ============ PAGE 3 — AT A GLANCE ============ #}
{% if "glance" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.glance }} · At a glance<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.glance }}</span><span class="section-rule"></span><span class="section-tag">● Context</span></div>
    <h1 class="section-title-h1">At a glance.</h1>
    <p class="section-headline">Three separate questions, answered separately: <strong>what is targeting your people</strong>, <strong>what is targeting your company</strong>, and <strong>what an attacker can exploit</strong>.</p>
  </div>

  <div class="exec-summary">
    <div class="exec-verdict">Your external security posture {{ exec_summary.verdict }}.</div>
    <p class="exec-headline">{{ exec_summary.headline }}</p>
    <div class="exec-triage">
      {% if exec_summary.immediate %}
      <div class="et-row"><span class="et-key">Most important</span><span class="et-val"><b>{{ exec_summary.immediate }}.</b> {{ exec_summary.immediate_detail }}. This is infrastructure serving your domain, not a lookalike of it.</span></div>
      {% endif %}
      {% if exec_summary.fixable %}
      <div class="et-row"><span class="et-key">Most fixable</span><span class="et-val"><b>{{ exec_summary.fixable }}</b>{% if exec_summary.fixable_count > 1 %} and {{ exec_summary.fixable_count - 1 }} other control{{ 's' if exec_summary.fixable_count > 2 else '' }}{% endif %} &mdash; changes you make yourself, in DNS. Section {{ section_no.roadmap }} sequences them.</span></div>
      {% endif %}
      {% if exec_summary.monitor %}
      <div class="et-row"><span class="et-key">Ongoing</span><span class="et-val"><b>{{ exec_summary.monitor }}</b>. Not aimed at you specifically &mdash; aimed at everyone using those platforms, which includes you.</span></div>
      {% endif %}
    </div>
    {% if exec_summary.benchmark %}
    <p class="exec-benchmark">{{ exec_summary.benchmark }}</p>
    {% endif %}
  </div>
  <div class="grade-band">
    <div class="grade-band-letter">{{ grade.letter }}</div>
    <div class="grade-band-body">
      <div class="gb-band">{{ grade.band }} exposure</div>
      <div class="gb-scoreline">Risk score {{ overall_score }}/100 &mdash; higher is more exposed &middot; grade {{ grade.letter }} on the A&ndash;F scale below</div>
      <div class="grade-band-scale">
        <div class="grade-scale-track"></div>
        <div class="grade-scale-marks">
          {% for _ in range(6) %}<span class="grade-scale-mark"></span>{% endfor %}
        </div>
        <div class="grade-scale-pin" style="left: {{ (grade.scale_position * 100) | round(1) }}%;"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:9.5px;font-weight:700;color:var(--ink-4);letter-spacing:0.05em;padding:0 2px;">
        {% for L in ['A','B','C','D','E','F'] %}<span{% if L == grade.letter %} style="color:var(--ink);"{% endif %}>{{ L }}</span>{% endfor %}
      </div>
      <div class="grade-band-text" style="margin-top:4px;">Most organisations at this level move down a band within a quarter by completing section {{ section_no.roadmap }}. The score weighs platform exposure, brand exposure and outbound posture.</div>
    </div>
  </div>
  <div class="scorecards">
    <div class="scorecard {% if not suppress_platform_counts and active_campaign_count > 0 %}bad{% else %}neutral{% endif %}">
      <div class="scorecard-label"><span class="scorecard-icon">▲</span>Trusted platform impersonation</div>
      <div class="scorecard-state">{{ 'Detected' if suppress_platform_counts else platform_scorecard_state }}</div>
      <div class="scorecard-text">{% if suppress_platform_counts %}<strong>{{ vendors | length }} platform{{ 's' if vendors | length != 1 else '' }}</strong> in your stack &mdash; each a lure an attacker can imitate. <em>The on-ramp.</em>{% elif active_campaign_count > 0 %}<strong>{{ pill_platforms_at_risk }} of your platforms</strong> actively impersonated &mdash; {{ impersonation_total_30d }} lookalike domains in 30 days. <em>The active risk.</em>{% elif not impersonation_lookup_ok %}<strong>Not checked</strong> &mdash; the impersonation rollup was unreachable, so no conclusion either way. <em>The active risk.</em>{% else %}<strong>No active impersonation</strong> of your platforms in the last 30 days. <em>The active risk.</em>{% endif %}</div>
    </div>
    <div class="scorecard {% if pill_brand_exposures >= 10 %}bad{% elif pill_brand_exposures > 0 %}warn{% else %}neutral{% endif %}">
      <div class="scorecard-label"><span class="scorecard-icon">◆</span>Brand impersonation</div>
      <div class="scorecard-state">{{ brand_scorecard_state }}</div>
      <div class="scorecard-text">{% if pill_brand_exposures > 0 %}<strong>{{ pill_brand_exposures }} lookalike domain{% if pill_brand_exposures != 1 %}s{% endif %}</strong> targeting <code style="font-family:'JetBrains Mono',monospace;font-size:10px;background:rgba(15,23,42,0.05);padding:1px 4px;border-radius:3px;">{{ domain_root }}</code> observed in certificate logs (30 days). <em>The watchlist.</em>{% elif suppress_platform_counts and not brand_monitored %}<strong>Monitoring not yet active</strong> for <code style="font-family:'JetBrains Mono',monospace;font-size:10px;background:rgba(15,23,42,0.05);padding:1px 4px;border-radius:3px;">{{ domain_root }}</code> &mdash; see the active-scan brand funnel for the candidate attack surface. <em>The watchlist.</em>{% elif not impersonation_lookup_ok %}<strong>Not checked</strong> &mdash; the lookalike rollup was unreachable when this report ran, so no conclusion either way for <code style="font-family:'JetBrains Mono',monospace;font-size:10px;background:rgba(15,23,42,0.05);padding:1px 4px;border-radius:3px;">{{ domain_root }}</code>. <em>The watchlist.</em>{% else %}<strong>No lookalike domains</strong> targeting <code style="font-family:'JetBrains Mono',monospace;font-size:10px;background:rgba(15,23,42,0.05);padding:1px 4px;border-radius:3px;">{{ domain_root }}</code> observed in the current window. <em>The watchlist.</em>{% endif %}</div>
    </div>
    <div class="scorecard neutral">
      <div class="scorecard-label"><span class="scorecard-icon">◉</span>Outbound posture</div>
      <div class="scorecard-state">{{ outbound_state }}</div>
      <div class="scorecard-text"><strong>{{ outbound_summary | safe }}</strong>. <em>The fixable item.</em></div>
    </div>
  </div>
  <div class="assessment-strip">
    <span class="assessment-strip-icon">i</span>
    <span><strong>First assessment.</strong> No delta yet. From the next snapshot this strip shows what changed &mdash; new platforms, posture changes, new lookalike registrations.</span>
  </div>
  <div class="priorities-header">
    <h3>Three things to address first.</h3>
    <span class="sub">One per surface — platform, brand, infrastructure.</span>
  </div>
  <div class="priority-list">
    {% for p in priorities %}
    <div class="priority-card">
      <div class="priority-num">{{ "%02d"|format(loop.index) }}</div>
      <div class="priority-body">
        <div class="priority-pills">
          <span class="pri-pill {{ p.severity }}">{{ p.severity_label }}</span>
          <span class="pri-pill {{ p.surface }}">{{ p.surface_glyph }} {{ p.surface_label }}</span>
        </div>
        <div class="priority-title">{{ p.title }}</div>
        <div class="priority-action">{{ p.action | safe }}</div>
        <div class="priority-why">{{ p.why }}</div>
      </div>
      <div class="priority-meta">
        <div class="priority-meta-row"><span class="priority-meta-key">Owner</span><span class="priority-meta-val">{{ p.owner }}</span></div>
        <div class="priority-meta-row"><span class="priority-meta-key">Effort</span><span class="priority-meta-val">{{ p.effort }}</span></div>
        <div class="priority-meta-row"><span class="priority-meta-key">When</span><span class="priority-meta-val">{{ p.when }}</span></div>
      </div>
    </div>
    {% endfor %}
  </div>
  {% if is_teaser %}
  <div class="teaser-cta">
    <div class="teaser-cta-icon">🔒</div>
    <div class="teaser-cta-body">
      <h4>This is the teaser edition.</h4>
      <p>The full report names every lookalike domain and gives step-by-step remediation with effort estimates. <strong>{{ brand_cfg.contact_email }}</strong> &middot; {{ brand_cfg.contact_web }}</p>
    </div>
  </div>
  {% endif %}
  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ SECTION 02 — HOW THE CYBER ATTACK ECONOMY WORKS ============ #}
{# Ported from the free report (freereport/renderer.py page 2). It is the one piece
   of general context that earns a page: it explains why exposure has nothing to do
   with being singled out, which is the question every reader asks first. Industry
   figures are labelled as such — they are not Datazag measurements. #}
{% if "attack_economy" in sections %}
{% set ns.page = ns.page + 1 %}
{% set top_platform = vendors[0].name if vendors else "Microsoft 365" %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.attack_economy }} · How the attack economy works<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.attack_economy }}</span><span class="section-rule"></span><span class="section-tag">● Context</span></div>
    <h1 class="section-title-h1">How the cyber attack economy works.</h1>
    <p class="section-headline">Platform impersonation is an industry with business models. How it operates explains why every organisation on {{ top_platform }} sits in its path.</p>
  </div>

  <div class="primer">
    <div class="primer-scale">
      <div class="ps-num">3<span class="sup">rd</span></div>
      <div class="ps-txt"><b>If cybercrime were a country, it would be the world&rsquo;s third-largest economy</b> &mdash; behind only the United States and China. It is projected to cost the world <b>$10.5 trillion in 2025</b>, roughly <b>$29 billion every day</b>.</div>
    </div>
    <div class="primer-cite">Source: Cybersecurity Ventures, 2025 Official Cybercrime Report. Industry context, not a Datazag measurement.</div>
  </div>

  <p class="economy-lead">That economy runs on a few repeatable business models. The one that reaches your employees is <b>mass credential harvesting</b> &mdash; an estimated <b>80&ndash;90% of all platform-impersonation activity</b> (industry estimate). It is why your exposure has little to do with whether anyone singled you out.</p>

  <div class="mech">
    <div class="mech-h">How mass credential harvesting works &mdash; &ldquo;spray and pray&rdquo;</div>
    <div class="mech-steps">
      <div class="mstep"><div class="mnum">1</div><div class="mbody"><b>Harvest the list.</b> Corporate addresses bought from breach dumps or scraped from public directories &mdash; accumulated by the million, not chosen.</div></div>
      <div class="mstep"><div class="mnum">2</div><div class="mbody"><b>Blast identical fakes.</b> Automated frameworks send the same fake {{ top_platform }} alert &mdash; &ldquo;your password has expired&rdquo; &mdash; to every address, each pointing at a convincing fake login page.</div></div>
      <div class="mstep"><div class="mnum">3</div><div class="mbody"><b>Harvest credentials at volume.</b> If even 1% enter their password, the operator nets thousands of valid logins, then resells them to extortion and ransomware crews.</div></div>
    </div>
    <div class="mech-escalate">
      <div class="me-icon">⚠</div>
      <div class="me-body"><b>It often takes only one &mdash; and you may never know it happened.</b> A single working credential moves you off the anonymous spray-and-pray list onto a <b>curated target list</b>. Because a credential is data, the same access is often <b>resold to several buyers at once</b>. And <b>a captured login is usually silent</b>: no outage, no alert, and the gap between compromise and discovery is often weeks.</div>
    </div>
    <div class="mech-punch">Nobody decided to target {{ org_name }}. They decided to target <b>everyone who uses {{ top_platform }}</b> &mdash; and you do. That is the logic of your exposure.</div>
  </div>

  {% if vendors %}
  <p class="economy-lead"><b>The platforms that put you in the target set</b> &mdash; read from your mail and DNS configuration, not guessed. Section {{ section_no.external_summary }} shows who is currently imitating them.</p>
  <div class="es-block">
    <table class="vendor-table">
      <tbody>
        {% for v in vendors[:5] %}
        <tr><td class="name-cell">{{ v.name }}</td><td class="evi-cell">{{ v.why }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ EXTERNAL THREAT — one page, replacing the four-page arc ============ #}
{% if "external_summary" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.external_summary }} · External threat<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.external_summary }}</span><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">Who is impersonating {{ org_name }}.</h1>
    <p class="section-headline">Lookalikes observed in certificate-transparency logs over the last 7 and 30 days &mdash; against the platforms <code style="font-family:'JetBrains Mono',monospace;font-size:12px;background:rgba(15,23,42,0.05);padding:1px 5px;border-radius:3px;">{{ domain }}</code> uses, and the <code style="font-family:'JetBrains Mono',monospace;font-size:12px;background:rgba(15,23,42,0.05);padding:1px 5px;border-radius:3px;">{{ domain_root }}</code> brand itself.</p>
  </div>

  {# The full attack-economy page still runs on the FREE tier, where a lead magnet
     can afford to argue the general case. Here it is a paragraph: the paid report
     is strongest telling a reader about their own estate, and the tables below
     already show "you use this / we observed that". #}
  <div class="economy-note">
    <div class="economy-note-h">Why you are exposed even if nobody targeted you</div>
    <p>Credential phishing is industrialised. Attackers build Microsoft, Google and Okta lookalikes and distribute them at scale, to whoever they reach. If your organisation uses those platforms &mdash; and the stack below is read from your own DNS &mdash; your staff are in the target population. Nobody decided on you.</p>
  </div>

  <div class="footprint-summary">
    <div class="footprint-stat"><div class="footprint-stat-num{% if impersonation_total_30d > 0 %} alert{% endif %}">{{ impersonation_total_30d }}</div><div class="footprint-stat-label">Platform lookalikes · 30d</div></div>
    <div class="footprint-stat"><div class="footprint-stat-num">{{ impersonation_total_7d }}</div><div class="footprint-stat-label">· 7d</div></div>
    <div class="footprint-stat"><div class="footprint-stat-num">{{ active_campaign_count }}</div><div class="footprint-stat-label">Platforms targeted</div></div>
    <div class="footprint-stat"><div class="footprint-stat-num{% if own_brand.count_30d > 0 %} alert{% endif %}">{{ own_brand.count_30d }}</div><div class="footprint-stat-label">Own-brand · 30d</div></div>
  </div>

  <div class="es-block">
    <div class="es-label">Detected platform stack <span class="es-note">strongest signal first</span></div>
    <table class="vendor-table">
      <thead><tr><th>Platform</th><th>Signal</th><th>Confidence</th></tr></thead>
      <tbody>
        {% for v in vendors %}
        <tr>
          <td class="name-cell">{{ v.name }}</td>
          <td class="evi-cell">{{ v.evidence_short }}</td>
          <td><span class="infra-pill {{ 'good' if v.confidence == 'confirmed' else 'warn' }}">{{ v.confidence }}</span></td>
        </tr>
        {% endfor %}
        {% if not vendors %}<tr><td colspan="3" style="color:var(--ink-3)">No platforms detected from DNS.</td></tr>{% endif %}
      </tbody>
    </table>
    <p class="es-foot">Confidence: <strong>confirmed</strong> = live MX, CNAME or SPF; <strong>indicative</strong> = a verification token only (may be stale).</p>
  </div>

  <div class="es-block">
    <div class="es-label">Active platform impersonation <span class="es-note">last 7 / 30 days</span></div>
    {% if active_campaigns %}
    <table class="vendor-table">
      <thead><tr><th>Platform</th><th>7d</th><th>30d</th><th>Trend</th><th>Sample lookalikes</th></tr></thead>
      <tbody>
        {% for imp in active_campaigns %}
        <tr>
          <td class="name-cell">{{ imp.platform }}</td>
          <td class="rank-cell">{{ imp.count_7d }}</td>
          <td class="rank-cell">{{ imp.count_30d }}</td>
          <td><span class="trend-pill {{ imp.trend }}">{% if imp.trend == 'up' %}↑{% elif imp.trend == 'down' %}↓{% else %}→{% endif %}</span></td>
          <td class="evi-cell">{% for d in imp.sample_domains[:3] %}<span class="lure-chip">{{ d }}</span>{% endfor %}{% if not imp.sample_domains %}&mdash;{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% elif not impersonation_lookup_ok %}
    <p class="es-empty">Impersonation monitoring <strong>could not run</strong> &mdash; the certificate-log rollup was unreachable. Not an all-clear.</p>
    {% else %}
    <p class="es-empty">No active impersonation of your platforms observed in the last 30 days. Continuous watch in place.</p>
    {% endif %}
  </div>

  <div class="es-block">
    <div class="es-label">Brand lookalikes <span class="es-note">typosquats of {{ domain_root }}</span></div>
    {% if own_brand.count_30d > 0 or own_brand.sample_domains %}
    <p class="es-line"><strong>{{ own_brand.count_30d }}</strong> in 30 days ({{ own_brand.count_7d }} this week):
      {% for d in own_brand.sample_domains %}<span class="lure-chip">{{ d }}</span>{% endfor %}</p>
    {% else %}
    <p class="es-empty">No brand lookalikes observed in the current window.</p>
    {% endif %}
    {% if own_brand_lookalikes.count_30d > 0 %}
    <p class="es-line muted">Plus {{ own_brand_lookalikes.count_30d }} lower-confidence typosquat candidate(s):
      {% for d in own_brand_lookalikes.sample_domains[:4] %}<span class="lure-chip">{{ d }}</span>{% endfor %}</p>
    {% endif %}
  </div>

  {% if platform_lookalikes %}
  <div class="es-block">
    <div class="es-label">Lookalike candidates <span class="es-note">Lower confidence &mdash; fuzzy, not exact matches</span></div>
    <p class="es-line muted">{% for c in platform_lookalikes %}<span class="lure-chip">{{ c.platform }} &times;{{ c.count_30d }}</span>{% for d in c.sample_domains[:2] %}<span class="lure-chip">{{ d }}</span>{% endfor %}{% endfor %}</p>
    <p class="es-foot">Short or dictionary-word brand names can produce false positives &mdash; a watchlist, not confirmed activity.</p>
  </div>
  {% endif %}

  {# The four pages this replaces carried no action. These come from the same
     priorities the roadmap uses, so the page a reader lands on tells them what
     to do about what it just showed them. #}
  {% if external_actions %}
  <div class="es-block">
    <div class="es-label">What to do <span class="es-note">from these observations</span></div>
    {% for a in external_actions %}
    <p class="es-line"><strong>{{ a.title }}</strong> &mdash; {{ a.action }}</p>
    {% endfor %}
  </div>
  {% endif %}

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag External Threat Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ PAGE 8 — SECTION 06 / DEFENSIVE CONTROLS ============ #}
{% if "controls" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.controls }} · Defensive controls<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.controls }}</span><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">Defensive controls — what we can see externally.</h1>
    <p class="section-headline">Every control here is <strong>directly observable</strong> from DNS, SSL or RDAP &mdash; no tenant access required. <strong>Deployed</strong> is credit for work done; <strong>partial</strong> and <strong>missing</strong> each carry the exact fix underneath.</p>
  </div>

  <div class="controls-summary-strip">
    <div class="css-headline"><strong>{{ controls_summary.deployed }} of {{ controls_summary.total }}</strong> externally verifiable controls deployed{% if controls_summary.limited %} · {{ controls_summary.limited }} not externally testable{% endif %}</div>
    <div class="css-counts">
      <span class="css-count good"><span class="css-dot"></span>{{ controls_summary.deployed }} deployed</span>
      <span class="css-count warn"><span class="css-dot"></span>{{ controls_summary.partial }} partial</span>
      <span class="css-count bad"><span class="css-dot"></span>{{ controls_summary.missing }} missing</span>
    </div>
  </div>

  {% if dmarc_mandate_callout %}
  <div class="mandate-callout">
    <div class="mandate-callout-icon">!</div>
    <div class="mandate-callout-body">
      <div class="mandate-callout-title">DMARC has moved from best practice to operational requirement.</div>
      <div class="mandate-callout-text">
        Google and Yahoo have required DMARC for bulk senders since <strong>February 2024</strong>, Microsoft since <strong>May 2025</strong>. Non-compliant senders now face permanent rejections &mdash; deliverability problems arrive regardless of the impersonation-defence value.
      </div>
    </div>
  </div>
  {% endif %}

  {% for cat in controls_audit %}
  <div class="controls-category">
    <div class="cc-header">
      <span class="cc-title">{{ cat.name }}</span>
      <span class="cc-count">{{ cat.deployed }} of {{ cat.total }} deployed</span>
    </div>
    {# Only gaps are listed; the deployed/total ratio above carries the credit for
       work already done, without a row each. #}
    {% for c in cat.controls if c.state != 'deployed' %}
    <div class="control-row {{ c.state }}">
      <div class="control-name">{{ c.name }}{% if c.trust_signal %} <span class="control-trust-marker" title="Notable trust signal">✦</span>{% endif %}</div>
      <div class="control-mid">
        <span class="control-badge {{ c.state }}">
          {% if c.state == 'deployed' %}✓ Deployed{% elif c.state == 'partial' %}◐ Partial{% elif c.state == 'limited' %}◯ Limited visibility{% else %}✗ Missing{% endif %}
        </span>
        <span class="control-evidence">{{ c.evidence }}</span>
        {% if c.state != 'deployed' %}<span class="control-impact {{ c.impact }}">{{ c.impact }} impact</span>{% endif %}
      </div>
      {% if c.action %}
      <div class="control-action">→ {{ c.action }}</div>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% endfor %}

  <div class="methodology-card">
    <h5>Methodology notes</h5>
    <p><strong>SPF doesn&rsquo;t inherit to subdomains.</strong> Each sending subdomain needs its own record; the audit above covers the apex only. DMARC does inherit, unless overridden with <code style="font-family:'JetBrains Mono',monospace;font-size:10px;background:rgba(15,23,42,0.05);padding:1px 3px;border-radius:3px;">sp=</code>.</p>
    <p><strong>DKIM cannot be reliably tested externally.</strong> Selectors are arbitrary subdomains chosen by the sending platform, so we cannot enumerate them. We probe known selectors for platforms we recognise &mdash; absence there does not confirm DKIM is missing.</p>
    <p><strong>What we cannot see externally.</strong> MFA, Conditional Access, anti-phishing rules, SIEM and staff training sit inside your tenants. They appear as checklist items on the cover card, not as audited controls.</p>
  </div>

  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ SECTION / FULL DNS RECORDS ============ #}
{% if "dns_records" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Full DNS records<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">Every record an attacker can read.</h1>
    <p class="section-headline">The complete DNS footprint for <code style="font-family:'JetBrains Mono',monospace;font-size:13px;background:rgba(15,23,42,0.05);padding:1px 5px;border-radius:3px;">{{ domain }}</code> &mdash; the records any attacker enumerates first. {{ dns_records_view.total }} captured; <strong>{{ dns_records_view.weak }}</strong> flagged as weaknesses.</p>
  </div>

  {% for g in dns_records_view.groups %}
  <div class="dns-group">
    <div class="dns-group-head"><span class="dns-type">{{ g.type }}</span>{% if g.weak %}<span class="dns-weak-count">{{ g.weak }} weakness{{ 'es' if g.weak != 1 else '' }}</span>{% endif %}</div>
    <table class="dns-table">
      {% for r in g.rows %}
      <tr class="{{ 'weak' if r.weak else '' }}">
        <td class="dns-val">{{ r.value }}</td>
        <td class="dns-note">{% if r.note %}{% if r.weak %}<span class="dns-flag">⚠</span> {% endif %}{{ r.note }}{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endfor %}

  <div class="methodology-card">
    <h5>Why the full record set matters</h5>
    <p>Public DNS is the first thing an attacker reads: A/AAAA show where you host, MX and TXT show how you send mail and whether you can be spoofed, NS shows your provider, and missing CAA/DNSSEC shows the soft spots.</p>
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ SECTION / INFRASTRUCTURE & ROUTING INTELLIGENCE ============ #}
{% if "infra_routing" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Infrastructure &amp; routing intelligence<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">The infrastructure your domain is hosted on.</h1>
    <p class="section-headline">Your domain inherits the reputation of the IP, prefix and ASN hosting it &mdash; routing integrity, threat-feed listings, and whether you share space with known-malicious domains.</p>
  </div>

  <div class="infra-overview">
    <div class="infra-cell"><div class="infra-cell-label">Hosting network (ASN)</div><div class="infra-cell-value">{{ infra_routing.asn }}</div><div class="infra-cell-sub">{{ infra_routing.isp }}</div></div>
    <div class="infra-cell"><div class="infra-cell-label">Country</div><div class="infra-cell-value">{{ infra_routing.country }}</div><div class="infra-cell-sub">ASN risk: <span class="infra-pill {{ infra_routing.asn_risk_class }}">{{ infra_routing.asn_risk }}</span></div></div>
    <div class="infra-cell"><div class="infra-cell-label">Announced prefix</div><div class="infra-cell-value mono">{{ infra_routing.prefix }}</div><div class="infra-cell-sub">RPKI <span class="infra-pill {{ infra_routing.rpki_class }}">{{ infra_routing.rpki_state }}</span></div></div>
  </div>

  <div class="infra-providers">
    <div class="infra-prov"><span class="infra-prov-label">Mailbox provider</span><span class="infra-prov-val">{{ infra_routing.mx_provider }}{% if infra_routing.mx_category %} <span class="infra-prov-cat">({{ infra_routing.mx_category }})</span>{% endif %}</span></div>
    <div class="infra-prov"><span class="infra-prov-label">Nameserver provider</span><span class="infra-prov-val">{{ infra_routing.ns_provider }}</span></div>
    {% if infra_routing.hosting_provider %}<div class="infra-prov"><span class="infra-prov-label">Hosting provider</span><span class="infra-prov-val">{{ infra_routing.hosting_provider }}</span></div>{% endif %}
    {% if infra_routing.tld_risk %}<div class="infra-prov"><span class="infra-prov-label">TLD risk</span><span class="infra-prov-val"><span class="infra-pill {{ infra_routing.tld_risk_class }}">{{ infra_routing.tld_risk }}</span></span></div>{% endif %}
    {% if infra_routing.trust_label %}<div class="infra-prov"><span class="infra-prov-label">Infrastructure trust</span><span class="infra-prov-val">{{ infra_routing.trust_label }}</span></div>{% endif %}
  </div>

  <div class="infra-grid">
    <div class="infra-panel">
      <div class="infra-panel-title">BGP routing posture</div>
      <table class="infra-table">
        <tr><td>MOAS detection</td><td class="r">{% if infra_routing.moas %}<span class="infra-pill bad">DETECTED</span>{% else %}<span class="infra-pill good">None</span>{% endif %}</td></tr>
        <tr><td>Prefix churn</td><td class="r">{{ infra_routing.churn }}</td></tr>
        <tr><td>MANRS member</td><td class="r">{{ 'Yes' if infra_routing.manrs_member else 'No' }}{% if infra_routing.manrs_status and infra_routing.manrs_status != 'Unknown' %} · {{ infra_routing.manrs_status }}{% endif %}</td></tr>
        <tr><td>MANRS culprit</td><td class="r">{% if infra_routing.manrs_culprit %}<span class="infra-pill bad">Yes</span>{% else %}No{% endif %}</td></tr>
      </table>
    </div>
    <div class="infra-panel">
      <div class="infra-panel-title">IP &amp; ASN reputation <span class="infra-scale">0.00 low → 1.00 high</span></div>
      <table class="infra-table">
        {% for r in infra_routing.reputation %}
        <tr><td>{{ r.label }}</td><td class="r"><span class="infra-score {{ r.cls }}">{{ r.val }}</span></td></tr>
        {% endfor %}
      </table>
    </div>
  </div>


  {% if infra_routing.cotenancy %}
  <div class="infra-cotenancy">
    <div class="infra-panel-title">Malicious co-tenancy</div>
    {% for c in infra_routing.cotenancy %}
    <div class="infra-cotenant"><strong>{{ c.count }}</strong> malicious domains share this {{ c.dimension }} (<code>{{ c.value }}</code>){% if c.examples %} — e.g. {{ c.examples }}{% endif %}</div>
    {% endfor %}
  </div>
  {% endif %}

  {% if infra_routing.reason_codes %}
  <div class="infra-reasons">
    <span class="infra-feeds-label">Datazag corpus reason codes:</span>
    {% for rc in infra_routing.reason_codes %}<span class="lure-chip">{{ rc }}</span>{% endfor %}
  </div>
  {% endif %}

  <div class="methodology-card">
    <h5>How this is assessed</h5>
    <p>We score every ASN and prefix against threat feeds, RPKI validity, MANRS participation, routing anomalies, and the density of malicious neighbours. Your domain inherits that reputation &mdash; clean hosting limits an attacker&rsquo;s options.</p>
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ PAGE 9 — SECTION 07 / HIDDEN INFRASTRUCTURE ============ #}
{% if "hidden_infra" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.hidden_infra }} · Hidden infrastructure<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.hidden_infra }}</span><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">The assets attackers find that you may not know exist.</h1>
    <p class="section-headline">Domain registration, subdomains, dormant services, and certificate hygiene. The foundational facts about your estate — discovered through DNS enumeration, SSL transparency logs, and RDAP. <strong>{{ subdomain_count }} live subdomains observed</strong> for {{ domain }}.</p>
  </div>

  {% if registration %}
  <div class="registration-strip">
    <div class="registration-strip-header">
      <h4>Domain registration</h4>
      <span class="meta">{% if registration.dnssec_enabled %}DNSSEC enabled · {% else %}DNSSEC not enabled · {% endif %}RDAP source: rdap.org</span>
    </div>
    <div class="registration-cells">

      <div class="registration-cell">
        <div class="reg-cell-label">Domain age</div>
        <div class="reg-cell-value">{{ registration.age_value }}</div>
        <div class="reg-cell-sub">{{ registration.age_sub | safe }}</div>
      </div>

      <div class="registration-cell">
        <div class="reg-cell-label">Last updated</div>
        <div class="reg-cell-value">{{ registration.updated_value }}</div>
        <div class="reg-cell-sub">{{ registration.updated_sub | safe }}</div>
      </div>

      <div class="registration-cell">
        <div class="reg-cell-label">Registrar</div>
        <div class="reg-cell-value">{{ registration.registrar_value }}</div>
        <div class="reg-cell-sub">{% if registration.registrar_chip_class %}<span class="risk-chip {{ registration.registrar_chip_class }}">{{ registration.registrar_chip_label }}</span>{% else %}&nbsp;{% endif %}</div>
      </div>

      <div class="registration-cell">
        <div class="reg-cell-label">Abuse contact</div>
        <div class="reg-cell-value email">{{ registration.abuse_value }}</div>
        <div class="reg-cell-sub">{{ registration.security_sub | safe }}</div>
      </div>

    </div>
    {% if registration.address %}
    <div class="registration-address">
      <span class="addr-label">Registrar address</span>
      <span class="addr-value">{{ registration.address }}</span>
    </div>
    {% endif %}
  </div>
  {% endif %}

  <div class="estate-overview">
    <div class="estate-stat"><div class="estate-stat-num">{{ subdomain_count }}</div><div class="estate-stat-label">Total subdomains</div></div>
    <div class="estate-stat"><div class="estate-stat-num{% if estate_high > 0 %} alert{% endif %}">{{ estate_high }}</div><div class="estate-stat-label">High-risk</div></div>
    <div class="estate-stat"><div class="estate-stat-num{% if estate_missed_renewal > 0 %} warn{% endif %}">{{ estate_missed_renewal }}</div><div class="estate-stat-label">Missed cert renewals</div></div>
    <div class="estate-stat"><div class="estate-stat-num{% if estate_cross_san > 5 %} warn{% endif %}">{{ estate_cross_san }}</div><div class="estate-stat-label">Cross-domain SANs</div></div>
  </div>

  {% if estate_callout %}
  <div class="estate-callout {{ estate_callout.kind }}">
    <span class="icon">{{ estate_callout.icon }}</span>
    <span>{{ estate_callout.text | safe }}</span>
  </div>
  {% endif %}

  {% if subdomain_sample %}
  <div class="subdomain-sample-table-wrap">
    <div class="subdomain-sample-header">
      Subdomain corpus — sample
      <span class="meta">{{ subdomain_sample | length }} of {{ subdomain_count }} shown · ordered by risk</span>
    </div>
    <table class="sample-table">
      <thead><tr><th>Subdomain</th><th>Cert</th><th>Notes</th><th class="risk-cell">Risk</th></tr></thead>
      <tbody>
        {% for s in subdomain_sample %}
        <tr>
          <td class="host-cell">{{ s.host }}</td>
          <td>{{ s.age }}</td>
          <td>{{ s.notes }}</td>
          <td class="risk-cell"><span class="risk-mini {{ s.risk_class }}"><span class="dot"></span>{{ s.risk_label }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <div class="methodology-card">
    <h5>What we look for</h5>
    <p>Subdomains found via DNS enumeration and certificate transparency, each checked for dangling CNAMEs, takeover-vulnerable platforms, shared cross-domain SAN certificates, and missed auto-renewals.</p>
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ PAGE 10 — SECTION 08 / TIMELINE ============ #}
{% if "timeline" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.timeline }} · Twelve-month timeline<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.timeline }}</span><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">Infrastructure changes worth knowing.</h1>
    <p class="section-headline">Every change Datazag has observed in your DNS and infrastructure over the past twelve months — flagged where it deviates from the baseline pattern for an estate of your shape.</p>
  </div>

  <div class="timeline-summary">{{ timeline_summary | safe }}</div>

  <div class="signal-grid">
    {% for sig in change_signals %}
    <div class="signal-card {{ 'active' if sig.changed else 'inactive' }}">
      <span class="signal-label">{{ sig.label }}</span>
      <span class="signal-state {{ 'changed' if sig.changed else 'stable' }}">{{ sig.state }}</span>
    </div>
    {% endfor %}
  </div>

  <div class="timeline-baseline">
    <strong>First assessment.</strong> This snapshot is your baseline. From the next one, this section shows what changed &mdash; new subdomains, provider rotations, anything off your pattern.
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ PAGE 11 — SECTION 09 / ROADMAP ============ #}
{% if "roadmap" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.roadmap }} · Implementation-changes roadmap<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.roadmap }}</span><span class="section-rule"></span><span class="section-tag" style="color:var(--tag-action);border-color:rgba(194,65,12,0.32);background:rgba(194,65,12,0.06);">● Action</span></div>
    <h1 class="section-title-h1">The implementation changes that close the gaps.</h1>
    <p class="section-headline">The weaknesses you can fix from the outside, sequenced by impact &mdash; the DNS, certificate and email-auth controls that govern whether your own domain can be spoofed, hijacked or mis-issued against. Platform phishing is defended inside your tenants, which this report cannot see.</p>
  </div>

  <div class="roadmap-grid">
    <div class="roadmap-col fortnight">
      <div class="roadmap-col-header"><span class="roadmap-col-title">This fortnight</span><span class="roadmap-col-count">{{ roadmap_fortnight | length }}</span></div>
      {% for item in roadmap_fortnight %}
      <div class="roadmap-item"><div class="roadmap-item-title">{{ item.title }}</div><div class="roadmap-item-meta">{{ item.surface }} · {{ item.effort }}</div></div>
      {% else %}
      <div class="roadmap-empty">No immediate actions required.</div>
      {% endfor %}
    </div>
    <div class="roadmap-col quarter">
      <div class="roadmap-col-header"><span class="roadmap-col-title">This quarter</span><span class="roadmap-col-count">{{ roadmap_quarter | length }}</span></div>
      {% for item in roadmap_quarter %}
      <div class="roadmap-item"><div class="roadmap-item-title">{{ item.title }}</div><div class="roadmap-item-meta">{{ item.surface }} · {{ item.effort }}</div></div>
      {% else %}
      <div class="roadmap-empty">No quarter-horizon items.</div>
      {% endfor %}
    </div>
    <div class="roadmap-col year">
      <div class="roadmap-col-header"><span class="roadmap-col-title">This year</span><span class="roadmap-col-count">{{ roadmap_year | length }}</span></div>
      {% for item in roadmap_year %}
      <div class="roadmap-item"><div class="roadmap-item-title">{{ item.title }}</div><div class="roadmap-item-meta">{{ item.surface }} · {{ item.effort }}</div></div>
      {% else %}
      <div class="roadmap-empty">No structural changes recommended.</div>
      {% endfor %}
    </div>
  </div>

  <div class="roadmap-narrative">
    <strong>How this prioritises:</strong> trusted-platform exposure and sensitive subdomains land in <strong>this fortnight</strong>; outbound posture and brand wiring in <strong>this quarter</strong>; estate-wide hygiene in <strong>this year</strong>.
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ SECTION / IT REMEDIATION TEAR-OFF ============ #}
{% if "remediation_plan" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">IT remediation plan<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-rule"></span><span class="section-tag pill-action" style="color:var(--tag-action);border-color:rgba(194,65,12,0.32);background:rgba(194,65,12,0.06);">● Action</span></div>
    <h1 class="section-title-h1">Remediation plan — hand this to your team.</h1>
    <p class="section-headline">Every actionable fix, consolidated and prioritised. Each row is self-contained: what is wrong now, and the exact change to make. Detach this page and hand it to whoever owns DNS, email, and infrastructure.</p>
  </div>

  {% if remediation_actions %}
  <div class="remediation-list">
    {% for a in remediation_actions %}
    <div class="remediation-item {{ a.severity }}">
      <div class="rem-rank">{{ "%02d"|format(loop.index) }}</div>
      <div class="rem-body">
        <div class="rem-head"><span class="rem-sev {{ a.severity }}">{{ a.severity|upper }}</span><span class="rem-area">{{ a.area }}</span></div>
        <div class="rem-title">{{ a.title }}</div>
        <div class="rem-step"><span class="rem-label">Fix:</span> {{ a.step }}</div>
      </div>
      <div class="rem-check"></div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="monitoring-state-panel">
    <div class="monitoring-state-icon">✓</div>
    <div class="monitoring-state-body">
      <h3>No outstanding remediation items.</h3>
      <p>No partial or missing controls and no actionable findings in this assessment. Maintain posture and re-assess next snapshot.</p>
    </div>
  </div>
  {% endif %}

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

{# ============ PAGE 12 — SECTION 10 / GLOSSARY ============ #}
{% if "glossary" in sections %}
{% set ns.page = ns.page + 1 %}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section {{ section_no.glossary }} · Glossary &amp; methodology<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section {{ section_no.glossary }}</span><span class="section-rule"></span><span class="section-tag">● Context</span></div>
    <h1 class="section-title-h1">Plain-English definitions.</h1>
    <p class="section-headline">Every technical term used in this report, in one line each. Methodology below.</p>
  </div>

  <div class="glossary-grid">
    {% for g in glossary %}
    <div class="glossary-item">
      <div class="glossary-term">{{ g.term | safe }}</div>
      <div class="glossary-def">{{ g.def | safe }}</div>
    </div>
    {% endfor %}
  </div>

  <div class="methodology-block">
    <h4>Methodology</h4>
    <p><strong>Data sources.</strong> Live DNS at snapshot time; certificate transparency logs; Datazag&rsquo;s certificate-issuance pipeline; RDAP registration data; ASN and BGP observations across 320 million domains, refreshed hourly.</p>
    <p><strong>Trusted-platform corpus.</strong> The identity platforms most often impersonated in certificate-issuance data &mdash; Microsoft 365, Google Workspace, Apple, PayPal, DocuSign, Mailchimp, Cloudflare, and the SaaS long tail.</p>
    <p><strong>The 85&ndash;90% figure.</strong> Of suspicious certificate registrations Datazag observed in April 2026, 85&ndash;90% imitated a trusted platform. Refreshed monthly; the range absorbs variance.</p>
    <p><strong>Trust Grade.</strong> A 0&ndash;100 composite (higher = more exposed) mapped to A&ndash;F. Driven by platform exposure, brand exposure, outbound posture and infrastructure findings.</p>
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page {{ ns.page }} of {{ total_pages }}</span></div>
</div>
{% endif %}

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Contract -> renderer-binding adapters
# ---------------------------------------------------------------------------
# The renderer's section methods read self.ea / self.dns (the old compiled-output
# sub-dict shape). Source those from the data CONTRACT (vm.hygiene / vm.dns_records)
# so the renderer no longer depends on a side-channel `legacy` raw rec. A real
# compiled-output `legacy` dict (the --input_json path) still wins when present.


def _ea_from_hygiene(hygiene) -> dict:
    """Adapt the contract's DnsHygiene -> the `email_auth` dict the email-auth
    controls read (self.ea.get(...)). Sources email-auth from the data package,
    not a side-channel rec, while leaving the existing call sites untouched."""
    if hygiene is None:
        return {}
    spf = getattr(hygiene, "spf_record", None) or ""
    policy = getattr(hygiene, "dmarc_policy", None)
    return {
        "spf": spf or None,
        "spf_strictness": ("strict" if getattr(hygiene, "spf_strict", False)
                           else "soft" if "~all" in spf else ("neutral" if spf else None)),
        "dmarc_raw": getattr(hygiene, "dmarc_record", None),
        "dmarc_policy": policy,
        "is_spoofable": policy in (None, "", "none"),
        "mta_sts_mode": getattr(hygiene, "mta_sts_mode", None),
        "tlsrpt_present": bool(getattr(hygiene, "tlsrpt_present", False)),
        "bimi_present": bool(getattr(hygiene, "bimi_present", False)),
        "caa_present": bool(getattr(hygiene, "caa_present", False)),
        "dnssec": bool(getattr(hygiene, "dnssec", False)),
    }


def _dns_from_contract(dns_records) -> dict:
    """Adapt the contract's DnsRecordSet -> the `dns_records` dict _build_dns_records
    reads (a/aaaa/mx/ns/caa/txt). mx entries are display strings ('pref host')."""
    if dns_records is None:
        return {}

    def g(n):
        return list(getattr(dns_records, n, None) or [])

    return {"a": g("a"), "aaaa": g("aaaa"), "mx": g("mx"),
            "ns": g("ns"), "caa": g("caa"), "txt": g("txt")}


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

class HealthReportRenderer:
    """
    Flagship Trust + Threat Surface report (v8 design, medallion-driven).

    Primary input is the typed `ReportViewModel` built from riskscore's
    medallion contract (intelligence_contract.build_view_models). An optional
    `legacy` output dict (the pre-split compiled shape, present in --live mode)
    enriches the sections that need live-scan data — vendor evidence, raw
    email-auth strings, subdomains, RDAP. When `legacy` is absent those
    sections degrade gracefully; nothing hard-requires it.

    `audience` selects the report variant (see healthreport/audiences.py);
    `tier` selects teaser vs full. Teaser redaction is applied to the
    view-model BEFORE any template rendering, so redacted specifics never
    reach the teaser HTML/PDF source.
    """

    def __init__(
        self,
        vm: ReportViewModel,
        audience: str = "flagship",
        tier: str = "full",
        legacy: dict | None = None,
        observatory: "Observatory | None" = None,
    ):
        if tier not in TIERS:
            raise ValueError(f"Unknown tier {tier!r}; expected one of {TIERS}")
        self.audience: AudienceConfig = get_audience(audience)
        self.tier = tier
        # Daily corpus measurements, for the "where you sit" line. Loading is
        # best-effort and cached per render; unreachable simply means no benchmark.
        self._observatory = observatory if observatory is not None else _load_observatory()

        legacy = legacy or {}
        self.o = legacy
        # Renderer bindings. email-auth + raw DNS records now come from the data
        # CONTRACT (vm.hygiene / vm.dns_records) when the caller didn't pass an
        # explicit compiled-output dict; everything else stays legacy-optional.
        self.ea            = legacy.get("email_auth") or _ea_from_hygiene(vm.hygiene)
        self.tech          = legacy.get("technographics") or {}
        self.txt_intel     = legacy.get("txt_intelligence") or {}
        self.dns           = legacy.get("dns_records") or _dns_from_contract(getattr(vm, "dns_records", None))
        self.subdomains    = legacy.get("subdomains") or list(getattr(vm, "subdomains", None) or [])
        self.cert_analysis = legacy.get("cert_analysis") or {}
        self.rdap          = legacy.get("rdap") or {}
        self.flags         = legacy.get("threat_flags") or {}
        self.changes       = legacy.get("change_signals") or {}
        self.infra         = legacy.get("infrastructure") or {}
        self.certs         = legacy.get("certificates") or {}
        self.narrative     = legacy.get("narrative") or {}
        # Annotation lake (DuckLake v_annotated row) — authoritative for
        # providers/labels. Prefer the view-model's annotation (populated by
        # lake_enrich in the in-process pipeline); fall back to a legacy
        # `output["annotation"]` block, then empty.
        vm_ann = getattr(vm, "annotation", None)
        if vm_ann is not None and vm_ann.present:
            self.annotation = vm_ann
        else:
            self.annotation = Annotation.model_validate(legacy.get("annotation") or {})

        # Merge findings: medallion-derived (already on the vm) first, then any
        # legacy live-scan findings, de-duplicated by finding key.
        merged: list[dict] = []
        seen: set[str] = set()
        for f in list(vm.findings) + list(legacy.get("findings") or []):
            key = str(f.get("finding") or f.get("title") or f)
            if key not in seen:
                seen.add(key)
                merged.append(f)
        vm = vm.model_copy(deep=True)
        vm.findings = merged
        if tier == "teaser":
            vm = redact_for_teaser(vm)
        self.vm = vm
        self.findings = vm.findings

        self.domain = vm.domain or legacy.get("domain", "")
        self.generated_at = vm.generated_at or legacy.get("generated_at", "")
        # Infrastructure composite: the medallion composite is authoritative;
        # fall back to the legacy display_score when no intelligence exists.
        if vm.has_intelligence:
            self.display_score = vm.composite_score
        else:
            self.display_score = int(legacy.get("display_score") or 0)

    # ----- Public API ------------------------------------------------------

    def render(self, fmt: str = "html", brand: BrandConfig | None = None) -> str:
        if fmt == "html":     return self.to_html(brand=brand)
        if fmt == "json":     return json.dumps(self.to_dict(), indent=2, default=str)
        if fmt == "markdown": return self.to_markdown(brand=brand)
        raise ValueError(f"Unknown format: {fmt}")

    def to_dict(self) -> dict:
        """Structured representation of what's rendered into the HTML.
        Useful for debugging and for downstream JSON consumers."""
        ext = self.vm.external_threat
        return {
            "report_type":   "trust_threat_surface_report",
            "version":       "v9.0",
            "audience":      self.audience.key,
            "tier":          self.tier,
            "domain":        self.domain,
            "generated_at":  self.generated_at,
            "has_intelligence": self.vm.has_intelligence,
            "trust_grade":   {
                "letter":      self._grade.letter,
                "headline":    self._grade.headline,
                "description": self._grade.description,
                "score":       self.display_score,
            },
            "pillars": {
                "trust":  {"score": self.vm.trust.score,  "grade": self.vm.trust.grade.letter},
                "threat": {"score": self.vm.threat.score, "grade": self.vm.threat.grade.letter},
            },
            "platform_footprint": self._build_vendor_list(),
            "external_threat": {
                "detected_platforms":      ext.detected_platforms,
                "impersonations_7d":       ext.total_7d,
                "impersonations_30d":      ext.total_30d,
                "own_brand_30d":           ext.own_brand.count_30d,
                "lookalike_candidates_30d": ext.lookalike_total_30d,
                "own_brand_lookalikes_30d": ext.own_brand_lookalikes.count_30d,
            },
            "brand_funnel":   self._build_brand_funnel(),
            "surface_counts": {
                "platforms_at_risk": self._pill_platforms_at_risk(),
                "brand_exposures":   self._pill_brand_exposures(),
                "defence_gaps":      self._pill_defence_gaps(),
            },
            "priorities":     self._build_priorities(),
            "findings":       self.findings,
            "narrative":      self.narrative,
        }

    def to_html(self, brand: BrandConfig | None = None) -> str:
        brand = brand or BrandConfig.default()
        ctx = self._build_context(brand)
        template = _jinja_env.from_string(HEALTH_REPORT_TEMPLATE)
        return template.render(**ctx)

    def to_markdown(self, brand: BrandConfig | None = None) -> str:
        """Full markdown rendition of the report — section-for-section parity
        with the HTML/PDF (for text workflows, diffing, and email). Respects
        the audience section set and the tier (the view-model is already
        teaser-redacted before it reaches here)."""
        vm = self.vm
        ext = vm.external_threat
        t, th = vm.trust, vm.threat
        secs = self.audience.sections
        L: list[str] = []
        A = L.append

        A(f"# Datazag {self.audience.title} — {self.domain}")
        A("")
        A(f"*{self.tier.title()} edition · snapshot {(self.generated_at or '')[:10]}*")
        A("")
        A(f"**Overall Trust Grade: {self._grade.letter} — {self._grade.headline}** "
          f"({self.display_score}/100)")
        if not vm.has_intelligence:
            A("")
            A("> Not yet assessed — no Datazag corpus intelligence for this domain yet.")
        A("")

        # ── Act 1: the attacker problem ──────────────────────────────────
        A("## The attacker problem — platform impersonation")
        A("")
        A(f"Grade {self._platform_grade.letter} ({self._platform_score}/100). "
          "Platform impersonation is usually how brand impersonation starts.")
        A("")
        actives = self._active_impersonations()
        if actives:
            A(f"**{ext.total_30d} lookalike domains across {len(actives)} of your "
              "platforms (last 30 days):**")
            for imp in actives:
                ex = ", ".join(imp.sample_domains[:3]) if imp.sample_domains else "—"
                A(f"- **{imp.platform}** — {imp.count_7d} in 7d / {imp.count_30d} in 30d "
                  f"({imp.trend}) · {ex}")
        elif not ext.lookup_ok:
            A("- Platform impersonation **not checked** — the certificate-log rollup "
              "was unreachable when this report ran. Not an all-clear.")
        else:
            A("- No active impersonation of your platforms in the last 30 days "
              "(continuous watch in place).")
        if ext.own_brand.count_30d:
            ob = ext.own_brand
            ex = f" · {', '.join(ob.sample_domains[:3])}" if ob.sample_domains else ""
            A(f"- Own-brand lookalikes — {ob.count_7d} in 7d / {ob.count_30d} in 30d{ex}")
        if ext.lookalike_candidates or ext.own_brand_lookalikes.count_30d:
            A("")
            A("_Lookalike candidates (lower confidence — fuzzy typosquats, treat as a watchlist):_")
            for imp in ext.lookalike_candidates:
                ex = ", ".join(imp.sample_domains[:3]) if imp.sample_domains else "—"
                A(f"- {imp.platform}: {imp.count_30d} in 30d · {ex}")
            if ext.own_brand_lookalikes.count_30d:
                A(f"- Own brand: {ext.own_brand_lookalikes.count_30d} in 30d")
        A("")

        # ── Act 2: defence weaknesses ────────────────────────────────────
        A("## Your defence weaknesses — trust & infrastructure")
        A("")
        A(f"Trust posture {t.score}/100 · infrastructure/threat {th.score}/100.")
        A("")
        A(f"- DMARC: {'**at risk** — not enforced' if t.dmarc_risk else 'enforced'}")
        A(f"- SPF: {'**not strict**' if t.spf_risk else 'strict'}; "
          f"modern email controls {'incomplete' if not t.modern_security_present else 'present'}")
        A(f"- Routing: RPKI {t.rpki_state}; MOAS {'**detected**' if t.moas_detected else 'none'}; "
          f"MANRS member {'yes' if t.is_manrs_member else 'no'}")
        if th.is_dangling_cname:
            A(f"- **Dangling CNAME** → {th.cname_target or 'unknown'} (subdomain-takeover exposure)")
        A("")

        # ── Brand funnel (free health report) ────────────────────────────
        if "brand_funnel" in secs:
            bf = self._build_brand_funnel()
            A("## Brand impersonation — active scan")
            A("")
            if bf["monitored"]:
                A(f"Continuous brand monitoring is active for {self.domain.split('.')[0]}.")
            else:
                A("Brand monitoring is **not yet active** for this domain — no retrospective "
                  "history. The candidate attack surface below was generated and checked "
                  "against the corpus at report time.")
            A("")
            A(f"- Patterns generated: **{bf['generated']}**"
              + (f" (top {bf['checked']} checked)" if bf['checked'] and bf['checked'] < bf['generated'] else ""))
            A(f"- Registered: **{bf['registered']}** · Resolving: **{bf['resolving']}** · "
              f"Attack signature (DGA): **{bf['dga_flagged']}**")
            if bf["near_miss"]:
                nm = bf["near_miss"]
                state = "already registered" if nm["registered"] else "registrable now (not registered today)"
                A(f"- Highlighted near-miss: `{nm['domain']}` — {state}")
            if bf["monitored"] and bf["own_brand_30d"] > 0:
                ex = f" · {', '.join(bf['own_brand_samples'][:3])}" if bf['own_brand_samples'] else ""
                A(f"- Observed lookalikes (30d): **{bf['own_brand_30d']}**{ex}")
            A("")
            A("_Brand Impersonation Watch adds continuous detection, per-lookalike "
              "weaponization verdicts, and takedown intelligence._")
            A("")

        # ── Platform footprint (now part of the one external page) ───────
        if "external_summary" in secs:
            vendors = self._build_vendor_list()
            if vendors:
                A("## Platform footprint (by attacker desirability)")
                A("")
                for i, v in enumerate(vendors, 1):
                    A(f"{i}. **{v['name']}** — {v['role']} ({v['tier_label']} desirability)")
                A("")

        # ── Defensive controls ───────────────────────────────────────────
        if "controls" in secs:
            cats = self._controls_categories()
            if cats:
                A("## Defensive controls")
                A("")
                for cat in cats:
                    A(f"### {cat['name']} — {cat['deployed']}/{cat['total']} deployed")
                    for c in cat["controls"]:
                        line = f"- **{c.get('name','')}** — {str(c.get('state','')).upper()}"
                        if c.get("evidence"):
                            line += f" · {c['evidence']}"
                        A(line)
                        if c.get("action"):
                            A(f"    - Fix: {c['action']}")
                    A("")

        # ── Full DNS records ─────────────────────────────────────────────
        if "dns_records" in secs:
            dv = self._build_dns_records()
            A(f"## Full DNS records ({dv['total']} records · {dv['weak']} weaknesses flagged)")
            A("")
            for g in dv["groups"]:
                A(f"**{g['type']}**")
                for r in g["rows"]:
                    flag = " ⚠" if r["weak"] else ""
                    note = f" — {r['note']}" if r["note"] else ""
                    A(f"- `{r['value']}`{flag}{note}")
                A("")

        # ── Infrastructure & routing intelligence ────────────────────────
        if "infra_routing" in secs:
            ir = self._build_infra_routing()
            A("## Infrastructure & routing intelligence")
            A("")
            A(f"- Hosting network **{ir['asn']}** ({ir['isp']}) · {ir['country']} · "
              f"ASN risk **{ir['asn_risk']}** · prefix `{ir['prefix']}` · RPKI **{ir['rpki_state']}**")
            A(f"- Mailbox provider: {ir['mx_provider']}"
              + (f" ({ir['mx_category']})" if ir['mx_category'] else "")
              + f" · Nameserver provider: {ir['ns_provider']}"
              + (f" · Hosting provider: {ir['hosting_provider']}" if ir['hosting_provider'] else ""))
            if ir['tld_risk'] or ir['trust_label']:
                A(f"- "
                  + " · ".join(filter(None, [
                      f"TLD risk **{ir['tld_risk']}**" if ir['tld_risk'] else "",
                      f"Infrastructure trust: {ir['trust_label']}" if ir['trust_label'] else "",
                  ])))
            A(f"- MOAS: {'**DETECTED**' if ir['moas'] else 'none'} · prefix churn {ir['churn']} · "
              f"MANRS member {'yes' if ir['manrs_member'] else 'no'}"
              + ("· **MANRS culprit**" if ir['manrs_culprit'] else ""))
            for r in ir["reputation"]:
                A(f"- {r['label']}: {r['val']}")
            for c in ir["cotenancy"]:
                A(f"- **{c['count']}** malicious domains share this {c['dimension']} ({c['value']})"
                  + (f" — e.g. {c['examples']}" if c['examples'] else ""))
            if ir["reason_codes"]:
                A(f"- Corpus reason codes: {', '.join(ir['reason_codes'])}")
            A("")

        # ── Hidden infrastructure ────────────────────────────────────────
        if "hidden_infra" in secs:
            A("## Hidden infrastructure")
            A("")
            rdap = self.rdap or {}
            if rdap.get("domain_age_days") not in (None, -1):
                A(f"- Domain age: {rdap.get('domain_age_days')} days · registrar: "
                  f"{rdap.get('registrar_name') or '—'}")
            A(f"- {len(self.subdomains)} subdomains observed"
              + (f" · {self._estate_count('high')} high-risk" if self.subdomains else ""))
            subs = self._build_subdomain_sample(limit=25)
            if subs:
                A("")
                A("| Subdomain | Cert | Notes | Risk |")
                A("|---|---|---|---|")
                for s in subs:
                    A(f"| `{s['host']}` | {s['age']} | {s['notes']} | {s['risk_label']} |")
            A("")

        # ── Priorities ───────────────────────────────────────────────────
        pris = self._build_priorities()
        if pris:
            A("## Three things to address first")
            A("")
            for i, p in enumerate(pris, 1):
                A(f"{i}. **{p['title']}** ({p['severity_label']} · {p['surface_label']})")
                A(f"   {p['action']}")
                A("")

        # ── Roadmap ──────────────────────────────────────────────────────
        if "roadmap" in secs:
            A("## Implementation-changes roadmap")
            A("")
            for bucket, label in (("fortnight", "This fortnight"),
                                  ("quarter", "This quarter"), ("year", "This year")):
                A(f"**{label}**")
                items = self._build_roadmap_bucket(bucket)
                if items:
                    for it in items:
                        A(f"- {it['title']} ({it['surface']} · {it['effort']})")
                else:
                    A("- —")
                A("")

        # ── IT remediation tear-off ──────────────────────────────────────
        if "remediation_plan" in secs:
            acts = self._build_remediation_actions()
            A("## IT remediation plan")
            A("")
            if acts:
                for i, a in enumerate(acts, 1):
                    A(f"{i}. **[{a['severity'].upper()}] {a['title']}** ({a['area']})")
                    if a["current"]:
                        A(f"   - Now: {a['current']}")
                    A(f"   - Fix: {a['step']}")
                    A("")
            else:
                A("- No outstanding remediation items.")
                A("")

        # ── Full findings ────────────────────────────────────────────────
        if vm.findings:
            A("## All findings")
            A("")
            _order = {"critical": 0, "high": 1, "elevated": 2, "medium": 3, "low": 4, "info": 5}
            for f in sorted(vm.findings, key=lambda x: _order.get(x.get("severity", "info"), 5)):
                A(f"- **[{str(f.get('severity', 'info')).upper()}] {f.get('title', '')}**")
                if f.get("detail"):
                    A(f"    - {f['detail']}")
                if f.get("remediation"):
                    A(f"    - Fix: {f['remediation']}")
            A("")

        return "\n".join(L)

    # ----- Impersonation lookups -------------------------------------------

    @staticmethod
    def _norm_platform_key(name: str) -> str:
        """Normalise a platform name for matching the impersonation rollup
        against vendor detection: 'Microsoft 365' / 'microsoft365' → 'microsoft365'."""
        return (name or "").strip().lower().replace(" ", "").replace("-", "").replace("_", "")

    @property
    def _impersonations_by_key(self) -> dict[str, PlatformImpersonation]:
        if not hasattr(self, "_imp_by_key_cache"):
            self._imp_by_key_cache = {
                self._norm_platform_key(i.platform): i
                for i in self.vm.external_threat.impersonations
            }
        return self._imp_by_key_cache

    def _impersonation_for(self, name_key: str) -> PlatformImpersonation | None:
        return self._impersonations_by_key.get(self._norm_platform_key(name_key))

    def _active_impersonations(self) -> list[PlatformImpersonation]:
        """Platforms with observed impersonation activity in the 30-day window,
        highest volume first."""
        return sorted(
            (i for i in self.vm.external_threat.impersonations if i.count_30d > 0),
            key=lambda i: -i.count_30d,
        )

    # ----- Cached lazy properties ------------------------------------------

    @property
    def _platform_score(self) -> int:
        """Platform exposure score 0-100. Reflects the size of the attack
        surface the customer faces — more high-desirability platforms in the
        stack means more lures attackers can deploy — plus OBSERVED campaign
        volume against those platforms from the impersonation rollup.

        Calibration (v1):
            base = 15  (everyone has some baseline platform exposure)
            +8 per high-desirability platform     (Microsoft 365, Google Workspace, ...)
            +5 per med-high-desirability platform (Mailchimp, ...)
            +3 per med-desirability platform      (Zoho, Citrix, ...)
            +1 per low-desirability platform      (Mailgun, Email Signatures, ...)
            +4 per platform with active impersonation in the last 30 days,
            +8 instead when that platform saw >= 20 lookalikes (capped +24 total)
            capped at 100
        """
        if not hasattr(self, "_platform_score_cache"):
            vendors = self._build_vendor_list()
            weights = {"high": 8, "med-high": 5, "med": 3, "low": 1}
            score = 15 + sum(weights.get(v["tier"], 3) for v in vendors)
            campaign_uplift = sum(
                8 if imp.count_30d >= 20 else 4
                for imp in self._active_impersonations()
            )
            score += min(24, campaign_uplift)
            self._platform_score_cache = min(100, score)
        return self._platform_score_cache

    @property
    def _infrastructure_score(self) -> int:
        """Internal infrastructure score 0-100. Uses the existing pipeline
        composite_score — DMARC/SPF/BIMI/CAA posture, infrastructure trust,
        DNS hygiene, subdomain risk.
        """
        return int(self.display_score or 0)

    @property
    def _overall_score(self) -> int:
        """Overall = the worse of the two surfaces. Higher = more exposure."""
        return max(self._platform_score, self._infrastructure_score)

    @property
    def _assessed(self) -> bool:
        """True when we have ANY basis for a grade — medallion intelligence or
        a legacy live-scan dict. Without either, grades must read 'not yet
        assessed' rather than defaulting to a misleading A."""
        return self.vm.has_intelligence or bool(self.o)

    @property
    def _platform_grade(self) -> TrustGrade:
        if not hasattr(self, "_platform_grade_cache"):
            self._platform_grade_cache = score_to_grade(
                self._platform_score if self._assessed else None)
        return self._platform_grade_cache

    @property
    def _infrastructure_grade(self) -> TrustGrade:
        if not hasattr(self, "_infra_grade_cache"):
            self._infra_grade_cache = score_to_grade(
                self._infrastructure_score if self._assessed else None)
        return self._infra_grade_cache

    @property
    def _grade(self) -> TrustGrade:
        """Overall Trust Grade — derived from the worse of the two sub-scores."""
        if not hasattr(self, "_grade_cache"):
            self._grade_cache = score_to_grade(
                self._overall_score if self._assessed else None)
        return self._grade_cache

    @property
    def _driving_surface(self) -> str:
        """Which sub-score is driving the overall grade?
        Returns 'platform', 'infrastructure', or 'both' (within 5 points)."""
        diff = self._platform_score - self._infrastructure_score
        if abs(diff) <= 5:
            return "both"
        return "platform" if diff > 0 else "infrastructure"

    @property
    def _platform_state(self) -> dict[str, str]:
        """Descriptive state for the platform attack surface, based on size and
        composition. Avoids the punitive 'exposure' framing — the platform side
        is about surface SIZE, not defensive failure. The qualifier reassures
        the reader that having common platforms isn't itself a problem.
        """
        n = len(self._build_vendor_list())
        if n == 0:
            return {"descriptor": "Minimal",
                    "qualifier":  "No SaaS platforms detected in DNS signals."}
        if n <= 3:
            return {"descriptor": "Lean",
                    "qualifier":  "Small SaaS footprint — fewer lures attackers can deploy against your staff."}
        if n <= 7:
            return {"descriptor": "Standard",
                    "qualifier":  f"{n} trusted platforms — typical for a business of your shape."}
        if n <= 12:
            return {"descriptor": "Wide",
                    "qualifier":  f"{n} trusted platforms — heavily SaaS-dependent, normal for an established estate."}
        return {"descriptor": "Very wide",
                "qualifier":  f"{n} trusted platforms — consider SSO consolidation to reduce lure count."}

    def _platform_actions(self) -> list[str]:
        """Generate platform-specific defensive actions based on detected
        platforms. The actions are customer-owned (they don't require Datazag
        services) and tailored to the actual stack.

        NOTE: every action here is Tier-3 — externally unverifiable. We can't
        see whether MFA is enforced, Conditional Access is configured, or API
        keys have been rotated. So actions are framed as checklist items
        ("If not already in place: ...") rather than diagnoses. The cover
        caption ('externally unverifiable') makes this explicit.
        """
        vendors = self._build_vendor_list()
        detected_keys = {v["name_key"] for v in vendors}
        actions: list[str] = []

        if "microsoft 365" in detected_keys:
            actions.append("If not already enforced: phishing-resistant MFA on Microsoft 365 "
                           "admin accounts, block legacy auth in Conditional Access.")

        if "google workspace" in detected_keys:
            actions.append("If not already enabled: Google Advanced Protection for high-value "
                           "accounts, Context-Aware Access policies.")

        if "mailchimp" in detected_keys:
            actions.append("If not already in place: Mailchimp 2FA on all users, rotated API "
                           "keys, IP allowlisting on the account.")

        # ConnectWise / Autotask are PSA platforms with high lateral-impact risk —
        # warrant their own action when detected
        if "connectwise" in detected_keys or "autotask" in detected_keys:
            actions.append("If not already enforced: MFA on PSA accounts (ConnectWise/Autotask) "
                           "with admin-tier accounts on phishing-resistant credentials. "
                           "These hold your client list.")

        # Salesforce gets its own item — high-value target, distinct controls
        if "salesforce" in detected_keys:
            actions.append("If not already enforced: Salesforce MFA org-wide; restrict API "
                           "access to allowlisted IPs.")

        # If we have detected platforms but no named-platform actions yet, fall back to generic
        if not actions and vendors:
            top = vendors[0]
            actions.append(f"If not already enforced: strong MFA on {top['name']} accounts, "
                           "especially anyone with admin rights or broad data access.")

        # Universal closer — recurring activity, doesn't require verification
        if vendors:
            top_names = ", ".join(v["name"] for v in vendors[:3])
            actions.append(f"Brief staff on impersonation lure patterns for {top_names} — "
                           "what real login pages look like vs. fake ones. Recurring activity.")

        return actions[:3]

    def _platform_list_for_cover(self) -> dict[str, Any]:
        """Build the platform-name list shown on the cover, with a marker
        flagging platforms surfaced from subdomain CNAMEs (the higher-signal,
        less-obvious-to-the-customer detection path).

        Returns a dict:
            platforms:       list of {name, cname_only} pairs
            cname_count:     int — how many were CNAME-only detections
            has_cname_items: bool — whether to show the footnote

        Note: the key is 'platforms' not 'items' — Jinja2 resolves `.items`
        to dict.items() rather than the value of an 'items' key.
        """
        vendors = self._build_vendor_list()
        platforms = []
        cname_count = 0
        for v in vendors:
            evidence_keys = {e["key"] for e in v["evidence"]}
            # "CNAME-only" means the only evidence is CNAME — i.e. surfaced
            # purely from subdomain data, not from TXT records or SPF includes.
            # These are the "surprising" detections the customer may not realise
            # are externally visible.
            cname_only = evidence_keys == {"CNAME"}
            if cname_only:
                cname_count += 1
            platforms.append({"name": v["name"], "cname_only": cname_only})
        return {
            "platforms":       platforms,
            "cname_count":     cname_count,
            "has_cname_items": cname_count > 0,
        }

    # ----- Context assembly ------------------------------------------------

    def _build_context(self, brand: BrandConfig) -> dict[str, Any]:
        gen_iso = self.generated_at or ""
        snapshot_date = gen_iso[:10] if gen_iso else ""
        snapshot_pretty = self._pretty_date(snapshot_date)
        quarter = self._quarter_label(snapshot_date)

        vendors = self._build_vendor_list()
        vendors_top = vendors[:3]
        vendors_rest = vendors[3:]

        ext = self.vm.external_threat
        actives = self._active_impersonations()
        own = ext.own_brand
        sections = self.audience.sections
        toc_items = [t for t in self._toc_items() if t["section"] in sections]

        return {
            # Variant / tier
            "sections":          sections,
            "product_label":     self.audience.title,
            "tier":              self.tier,
            "is_teaser":         self.tier == "teaser",
            "has_intelligence":  self.vm.has_intelligence,
            "brand_cfg":         brand,
            # Identity
            "domain":            self.domain,
            "domain_root":       self.domain.split(".")[0],
            "org_name":          self._org_display_name(),
            "org_locale":        self._org_locale(),  # TODO(rdap-locale)
            # Snapshot meta
            "snapshot_date_pretty": snapshot_pretty,
            "quarter_label":     quarter,
            "research_month":    "April 2026",  # TODO(research-publishing): pull from config when published
            "subdomain_count":   len(self.subdomains),
            "total_pages":       len(sections),
            # External threat / platform impersonation
            "active_campaigns":        actives,
            "active_campaign_count":   len(actives),
            "impersonation_total_7d":  ext.total_7d,
            "impersonation_total_30d": ext.total_30d,
            # False = the rollup could not be reached, so the zeros above mean NOT
            # CHECKED. Every all-clear in the templates below gates on this.
            "impersonation_lookup_ok": ext.lookup_ok,
            # The external page's action block — the platform/brand priorities only,
            # so it never repeats the infrastructure items the roadmap owns.
            "section_no":        self._section_numbers(),
            "cover_hook":        self._cover_hook(),
            "exec_summary":      self._executive_summary(),
            "external_actions":  [p for p in self._build_priorities()
                                  if p.get("surface") in ("vendor", "brand")],
            "own_brand":               own,
            # Free health report: suppress platform-GLOBAL impersonation counts
            # (not customer-specific — the "157") and avoid implying we ran a brand
            # check when the domain isn't monitored. See brand_page_data_contract.md.
            "suppress_platform_counts": self.audience.key == "health",
            "brand_monitored":          ext.brand_funnel.monitored,
            # Lower-confidence typosquat candidates (separate section)
            "platform_lookalikes":     [c for c in ext.lookalike_candidates if c.count_30d > 0],
            "own_brand_lookalikes":    ext.own_brand_lookalikes,
            "has_lookalikes":          ext.has_lookalikes,
            "platform_scorecard_state": ("Elevated" if actives
                                         else "Monitoring" if ext.lookup_ok
                                         else "Unavailable"),
            "brand_scorecard_state":    ("Elevated" if own.count_30d >= 10
                                         else "Moderate" if own.count_30d > 0
                                         else "Clear" if ext.lookup_ok
                                         else "Unavailable"),
            # Trust / threat pillars (medallion)
            "trust_pillar":      self.vm.trust,
            "threat_pillar":     self.vm.threat,
            # Trust grade
            "grade":             self._grade,
            # The overall 0-100 (higher = more exposed). The scorelines print it
            # beside the band; an undefined name here renders as empty in Jinja and
            # ships "Risk score /100", so it is passed explicitly.
            "overall_score":     self.display_score,
            "platform_grade":    self._platform_grade,
            "infra_grade":       self._infrastructure_grade,
            "platform_score":    self._platform_score,
            "infra_score":       self._infrastructure_score,
            "driving_surface":   self._driving_surface,
            "platform_state":    self._platform_state,
            "platform_actions":  self._platform_actions(),
            "platform_list":     self._platform_list_for_cover(),
            "infra_summary_bits": self._infra_summary_bits(),
            # Surface pill counts
            "pill_platforms_at_risk": self._pill_platforms_at_risk(),
            "pill_brand_exposures":   self._pill_brand_exposures(),
            "pill_defence_gaps":      self._pill_defence_gaps(),
            # At-a-glance scorecards
            "outbound_state":    self._outbound_state(),
            "outbound_summary":  self._outbound_summary(),
            # Priorities
            "priorities":        self._build_priorities(),
            # Vendor footprint
            "vendors":              vendors,
            "vendors_top":          vendors_top,
            "vendors_rest":         vendors_rest,
            "vendors_high_count":   sum(1 for v in vendors if v["tier"] == "high"),
            "total_evidence_signals": sum(len(v["evidence"]) for v in vendors),
            # TOC (filtered to enabled sections)
            "toc_items":         toc_items,
            # Section 06 — Outbound posture
            "posture_layers":    self._build_posture_layers(),
            "controls_audit":    self._controls_categories(),
            "controls_summary":  self._controls_summary(),
            "dmarc_mandate_callout": (self.ea.get("dmarc_policy") or "") != "reject",
            # Infrastructure & routing intelligence (IP / prefix / ASN quality)
            "infra_routing":     self._build_infra_routing(),
            # Full DNS records + weakness commentary
            "dns_records_view":  self._build_dns_records(),
            # IT remediation tear-off (back of report)
            "remediation_actions": self._build_remediation_actions(),
            # Section 07 — Hidden infrastructure
            "registration":           self._build_registration(),
            "estate_high":            self._estate_count("high"),
            "estate_missed_renewal":  self._estate_missed_renewals_count(),
            "estate_cross_san":       self._estate_cross_san_count(),
            "estate_callout":         self._estate_callout(),
            "subdomain_sample":       self._build_subdomain_sample(limit=8),
            # Section 08 — Timeline
            "timeline_summary":  self._build_timeline_summary(),
            "change_signals":    self._build_change_signal_list(),
            # Section 09 — Roadmap
            "roadmap_fortnight": self._build_roadmap_bucket("fortnight"),
            "roadmap_quarter":   self._build_roadmap_bucket("quarter"),
            "roadmap_year":      self._build_roadmap_bucket("year"),
            # FREE health report — active-scan brand funnel
            "brand_funnel":      self._build_brand_funnel(),
            # Section 10 — Glossary
            "glossary":          self._glossary_items(),
        }

    # ----- Display helpers -------------------------------------------------

    def _org_display_name(self) -> str:
        """The 'Prepared for' line on the cover.

        Default: the domain itself — clean, accurate, no fabricated company name.
        Override: an explicit `prepared_for` string can be passed via the output
        dict (set by upstream run() or CLI) when the report is being prepared
        for a named buyer (MSSP for a client, Datazag-direct for a customer).

        Note: we do NOT use rdap.registrar_name — that's the registration
        provider (e.g. "Easyspace Limited"), not the customer. We do NOT use
        rdap.registrant_name either — the upstream RDAP module does not emit it
        because most TLDs redact registrant data behind WHOIS privacy by default.
        """
        override = (self.o.get("prepared_for") or "").strip()
        if override:
            return override
        return self.domain

    def _org_locale(self) -> str:
        """Sub-line under the 'Prepared for' cell.

        We don't reliably know the customer's locale (RDAP registrant data is
        typically redacted). What we do know is where their infrastructure is
        hosted, which is a legitimate and accurate signal — and not misleading
        because it's labelled 'hosted in' in the template.
        """
        country = (self.tech or {}).get("isp_country") or ""
        if country:
            return f"hosted in {country}"
        return ""

    @staticmethod
    def _pretty_date(iso_date: str) -> str:
        try:
            from datetime import datetime
            dt = datetime.strptime(iso_date, "%Y-%m-%d")
            return dt.strftime("%d %b %Y")
        except (ValueError, TypeError):
            return iso_date or "—"

    @staticmethod
    def _quarter_label(iso_date: str) -> str:
        try:
            from datetime import datetime
            dt = datetime.strptime(iso_date, "%Y-%m-%d")
            q = (dt.month - 1) // 3 + 1
            return f"Q{q} {dt.year}"
        except (ValueError, TypeError):
            return "—"

    # ----- Surface counts ---------------------------------------------------

    def _pill_platforms_at_risk(self) -> int:
        """Detected platforms with active impersonation observed in the last
        30 days — from the riskscore platform-impersonation rollup."""
        return len(self._active_impersonations())

    @property
    def _suppress_platform_counts(self) -> bool:
        """Free health report: never cite platform-GLOBAL impersonation counts
        (not customer-specific — the "157") anywhere, including priorities."""
        return self.audience.key == "health"

    def _pill_brand_exposures(self) -> int:
        """Lookalike domains targeting the customer's OWN brand observed in
        the last 30 days — from the riskscore brand_hits rollup."""
        return self.vm.external_threat.own_brand.count_30d

    def _build_brand_funnel(self) -> dict[str, Any]:
        """FREE health report brand page (brand_page_data_contract.md §3/§6).

        Renders the active-scan funnel — candidates generated → registered →
        resolving → DGA-flagged — plus the single highlighted near-miss and the
        empty-state framing when the brand isn't monitored. Brand-scoped by
        construction: it reads ONLY brand sources (the funnel + own_brand) and
        NEVER the platform-global impersonation counts (the "157" conflation).
        """
        ext = self.vm.external_threat
        bf = ext.brand_funnel

        # §7 guard — fail loud if a platform-global count ever reaches a brand
        # claim on this page. own_brand/funnel are brand-scoped; the platform
        # totals must not equal a brand number we surface here unless that brand
        # number genuinely came from brand data (it has samples) or is zero.
        self._assert_brand_not_platform()

        stages = [
            {"key": "generated",  "label": "Patterns generated",     "count": bf.candidates_generated},
            {"key": "registered", "label": "Registered",            "count": bf.registered},
            {"key": "resolving",  "label": "Resolving (live infra)", "count": bf.resolving},
            {"key": "dga",        "label": "Attack signature (DGA)", "count": bf.dga_flagged},
        ]
        near = bf.near_miss
        return {
            "monitored":   bf.monitored,
            "present":     bf.present,
            "checked":     bf.checked,
            "generated":   bf.candidates_generated,
            "registered":  bf.registered,
            "resolving":   bf.resolving,
            "dga_flagged": bf.dga_flagged,
            "stages":      stages,
            "samples":     [
                {"domain": c.domain, "status": c.status, "age_days": c.domain_age_days,
                 "has_cert": c.has_cert, "dga_risk": c.dga_risk}
                for c in bf.samples[:8]
            ],
            "near_miss":   ({"domain": near.domain, "status": near.status,
                             "registered": near.registered} if near else None),
            # Retrospective monitored history (own-brand), shown only when the
            # brand IS monitored. Never borrowed from platform data.
            "own_brand_30d": ext.own_brand.count_30d,
            "own_brand_samples": ext.own_brand.sample_domains[:6],
        }

    def _assert_brand_not_platform(self) -> None:
        """§7 hard guard: platform-global impersonation data must never populate a
        brand-level claim. We surface own_brand.count_30d as the brand figure; if
        it is non-zero it MUST be backed by brand-scoped evidence (sample domains
        or an active funnel), never silently equal to a platform-global total."""
        ext = self.vm.external_threat
        brand_count = ext.own_brand.count_30d
        if brand_count <= 0:
            return  # zero brand claim — nothing to conflate
        platform_totals = {i.count_30d for i in ext.impersonations} | {ext.total_30d}
        brand_backed = bool(ext.own_brand.sample_domains) or ext.brand_funnel.present
        if brand_count in platform_totals and not brand_backed:
            raise ValueError(
                f"Brand exposure count ({brand_count}) matches a platform-global "
                "impersonation total with no brand-scoped evidence — platform data "
                "may not populate a brand claim (see brand_page_data_contract.md §1/§7)."
            )

    def _pill_defence_gaps(self) -> int:
        """Defence gaps = critical+high posture findings. Real value, no placeholder."""
        return sum(1 for f in self.findings if f.get("severity") in ("critical", "high"))

    def _outbound_state(self) -> str:
        if self.ea:
            if self.ea.get("is_spoofable"):
                sev = self.ea.get("spoofing_severity", "high")
                return {"high": "Weak", "medium": "Mixed"}.get(sev, "Mixed")
            return "Configured"
        # Medallion fallback (no live scan attached)
        t = self.vm.trust
        if t.dmarc_risk:
            return "Weak"
        if t.spf_risk or not t.modern_security_present:
            return "Mixed"
        return "Configured"

    def _outbound_summary(self) -> str:
        if self.ea:
            ea = self.ea
            bits = []
            dmarc = ea.get("dmarc_policy") or "missing"
            bits.append(f"DMARC at p={dmarc}")
            if not self.flags.get("has_caa"):
                bits.append("no CAA")
            if "BIMI" in (ea.get("missing_layers") or []):
                bits.append("no BIMI")
            return ", ".join(bits) + (". Your domain remains spoofable" if ea.get("is_spoofable") else "")
        # Medallion fallback
        t = self.vm.trust
        bits = []
        bits.append("DMARC not enforced" if t.dmarc_risk else "DMARC enforced")
        if t.spf_risk:
            bits.append("SPF not strict")
        if not t.modern_security_present:
            bits.append("modern email controls incomplete")
        return ", ".join(bits) + (". Your domain remains spoofable" if t.dmarc_risk else "")

    def _infra_summary_bits(self) -> list[str]:
        """Three short bullets describing the customer's infrastructure posture,
        for the cover sub-score card. Each bullet is ≤ 6 words.

        Prefers live-scan (legacy) detail when attached; otherwise derives the
        bullets from the medallion trust/threat pillars."""
        if not self.ea and self.vm.has_intelligence:
            t, th = self.vm.trust, self.vm.threat
            bits = []
            bits.append("DMARC not enforced" if t.dmarc_risk else "DMARC enforced")
            if t.rpki_state == "invalid":
                bits.append("RPKI invalid — hijack exposure")
            elif t.rpki_state == "unknown":
                bits.append("RPKI not deployed")
            if th.is_dangling_cname:
                bits.append("dangling CNAME — takeover risk")
            elif t.moas_detected:
                bits.append("MOAS routing anomaly")
            elif t.spf_risk:
                bits.append("SPF not strict")
            return bits[:3]

        ea = self.ea or {}
        rdap = self.rdap or {}
        flags = self.flags or {}
        bits = []

        # DMARC state — top of the order; it's the most consequential outbound control
        dmarc = ea.get("dmarc_policy") or ""
        if dmarc == "reject":
            bits.append("DMARC enforcing")
        elif dmarc == "quarantine":
            bits.append("DMARC partial (quarantine)")
        elif dmarc == "none":
            bits.append("DMARC monitor only")
        else:
            bits.append("DMARC missing")

        # CAA / BIMI / DNSSEC — pick the most consequential missing layer next
        missing_layers = ea.get("missing_layers") or []
        if not flags.get("has_caa"):
            bits.append("CAA not deployed")
        elif "BIMI" in missing_layers:
            bits.append("BIMI not deployed")
        elif not rdap.get("dnssec_enabled"):
            bits.append("DNSSEC not enabled")

        # If we still have room, mention high-risk subdomains or cert hygiene
        if len(bits) < 3:
            high_count = sum(1 for s in self.subdomains if s.get("risk_level") == "high")
            missed = len((self.cert_analysis or {}).get("missed_renewals") or [])
            if high_count > 0:
                bits.append(f"{high_count} high-risk subdomain{'s' if high_count != 1 else ''}")
            elif missed > 0:
                bits.append(f"{missed} missed cert renewal{'s' if missed != 1 else ''}")
            elif not rdap.get("dnssec_enabled"):
                bits.append("DNSSEC not enabled")

        return bits[:3]

    # ----- Section: Full DNS records (completeness + weakness commentary) --

    @staticmethod
    def _annotate_txt(t: str) -> tuple[str, bool]:
        """Return (note, is_weakness) for a TXT record."""
        low = (t or "").lower()
        if low.startswith("v=spf1"):
            if "-all" in low:
                return ("SPF — strict (-all): unauthorised senders are hard-failed", False)
            if "~all" in low:
                return ("SPF — soft-fail (~all): spoofers are marked, not blocked", True)
            if "?all" in low or "+all" in low:
                return ("SPF — no enforcement: effectively allows anyone to send as you", True)
            return ("SPF record with no explicit -all/~all mechanism", True)
        if low.startswith("v=dmarc1"):
            if "p=reject" in low:
                return ("DMARC — p=reject (full enforcement)", False)
            if "p=quarantine" in low:
                return ("DMARC — p=quarantine (partial enforcement)", False)
            if "p=none" in low:
                return ("DMARC — p=none: monitoring only, does not block spoofing", True)
            return ("DMARC record", False)
        if low.startswith("v=dkim1") or "._domainkey" in low:
            return ("DKIM public key", False)
        if low.startswith(("google-site-verification", "ms=", "apple-domain-verification",
                           "facebook-domain-verification", "atlassian-domain-verification",
                           "stripe-verification", "docusign=")) or "verification" in low:
            return ("Domain-verification token — reveals a SaaS platform in use", False)
        if low.startswith("v=mta-sts"):
            return ("MTA-STS policy marker", False)
        return ("", False)

    def _build_dns_records(self) -> dict[str, Any]:
        """Every captured DNS record, grouped by type, with inline weakness
        commentary on the records that are defensive gaps. Demonstrates a full
        DNS-level grasp of the attack surface."""
        dns = self.dns or {}
        ea = self.ea or {}
        groups: list[dict[str, Any]] = []

        def grp(rtype: str, rows: list[dict]) -> None:
            if rows:
                groups.append({"type": rtype, "rows": rows,
                               "weak": sum(1 for r in rows if r["weak"])})

        def plain(vals) -> list[dict]:
            return [{"value": str(v), "note": "", "weak": False} for v in (vals or [])]

        grp("A", plain(dns.get("a")))
        grp("AAAA", plain(dns.get("aaaa")))

        mx = dns.get("mx") or []
        mx_rows = [{"value": (f"{m.get('priority')} {m.get('host')}" if isinstance(m, dict) else str(m)),
                    "note": "", "weak": False} for m in mx]
        if not mx_rows:
            mx_rows = [{"value": "(none)", "weak": True,
                        "note": "No MX records — the domain is not configured to receive mail"}]
        grp("MX", mx_rows)

        ns = dns.get("ns") or []
        ns_rows = plain(ns)
        if len(ns_rows) == 1:
            ns_rows[0].update(note="Single nameserver — no DNS redundancy", weak=True)
        grp("NS", ns_rows)

        caa = dns.get("caa") or []
        grp("CAA", plain(caa) if caa else
            [{"value": "(none)", "weak": True,
              "note": "No CAA record — any certificate authority can issue certificates for this domain"}])

        txt_rows = []
        for t in dns.get("txt") or []:
            note, weak = self._annotate_txt(t)
            txt_rows.append({"value": str(t), "note": note, "weak": weak})
        grp("TXT", txt_rows)

        dnssec_on = bool(ea.get("dnssec")) or bool((self.rdap or {}).get("dnssec_enabled"))
        grp("DNSSEC", [{"value": "enabled" if dnssec_on else "not enabled",
                        "weak": not dnssec_on,
                        "note": "" if dnssec_on else
                                "DNS responses are not cryptographically signed — exposure to DNS spoofing/cache poisoning"}])

        total = sum(len(g["rows"]) for g in groups)
        weak = sum(g["weak"] for g in groups)
        return {"groups": groups, "total": total, "weak": weak}

    # ----- Section: Infrastructure & routing intelligence ------------------

    @staticmethod
    def _risk_class01(v: float | None) -> str:
        """Severity class for a 0–1 risk score, or `neutral` when it was never measured.

        None must NOT fall through to "good": that is the same absent-reads-as-safe defect as
        rendering 0.00, just expressed as a colour instead of a number. `.neutral` already
        exists in this stylesheet for exactly this state.
        """
        if v is None:
            return "neutral"
        return "bad" if v > 0.5 else "warn" if v > 0.25 else "good"

    def _build_infra_routing(self) -> dict[str, Any]:
        """IP / prefix / ASN quality from the medallion view-model (routing
        integrity + reputation + threat-feed listings + malicious co-tenancy).
        ASN org name comes from the live-scan technographics when present."""
        t, th = self.vm.trust, self.vm.threat
        tech = self.tech or {}
        ann = self.annotation
        # Provider/label precedence: annotation lake (authoritative labelling) →
        # medallion (riskscore single source of truth) → live-scan technographics.
        isp = ann.hosting_provider or ann.cloud_provider \
            or t.isp or tech.get("isp_name") or ann.asn_name or "—"
        country = t.isp_country or tech.get("isp_country") or ann.isp_country or "—"
        asn_risk = (ann.asn_risk_level
                    or (t.asn_risk_level if t.asn_risk_level and t.asn_risk_level != "unknown" else None)
                    or tech.get("asn_risk_level") or "unknown")
        asn_num = t.asn or tech.get("asn") or ann.asn or 0
        # mailbox provider: annotation lake first (resolves MX-over-TXT at source),
        # then live-scan technographics, then the medallion mx_type.
        mx_type = t.mx_type if t.mx_type and t.mx_type != "unknown" else None
        mx_provider = ann.mailbox_provider or tech.get("mx_provider_name") \
            or (mx_type.title() if mx_type else None) or "—"
        mx_category = ann.mailbox_category or tech.get("mx_mbp_category") or ""
        ns_provider = ann.ns_provider or tech.get("ns_provider_name") or "—"
        # Annotation-only labels (no medallion/technographics equivalent yet).
        hosting_provider = ann.hosting_provider or ann.cloud_provider or ""
        tld_risk = (ann.tld_risk_level or "").strip()
        trust_label = (ann.trust_label or "").strip()

        cotenancy = []
        for pf in th.pivot_findings:
            if pf.malicious_count > 0:
                cotenancy.append({
                    "dimension": pf.dimension or "asn",
                    "value": pf.value or "—",
                    "count": pf.malicious_count,
                    "examples": ", ".join(pf.examples[:3]) if pf.examples else "",
                })

        def f2(x: float | None) -> str:
            """Format a sub-score, or this file's em-dash missing-marker when it was never
            measured. RiskAssessment/ThreatSurface sub-scores are `float | None`, where None
            means NOT MEASURED — it must not render as 0.00, which reads as measured-and-clean.
            See the note on RiskAssessment in intelligence_contract."""
            return "—" if x is None else f"{x:.2f}"

        return {
            "asn":            f"AS{asn_num}" if asn_num else "—",
            "prefix":         t.prefix or ann.prefix or "—",
            "isp":            isp,
            "country":        country,
            "asn_risk":       asn_risk,
            "asn_risk_class": "bad" if asn_risk in ("high", "critical") else "warn" if asn_risk in ("medium", "elevated") else "good",
            "mx_provider":    mx_provider,
            "mx_category":    mx_category,
            "ns_provider":    ns_provider,
            "hosting_provider": hosting_provider,
            "tld_risk":       tld_risk,
            "tld_risk_class": "bad" if tld_risk in ("high", "critical") else "warn" if tld_risk in ("medium", "elevated") else "good",
            "trust_label":    trust_label,
            "is_parked":      ann.is_parked,
            "rpki_state":     t.rpki_state.upper(),
            "rpki_class":     "good" if t.rpki_state == "valid" else "bad" if t.rpki_state == "invalid" else "warn",
            "moas":           t.moas_detected,
            "churn":          t.prefixes_churn_total,
            "manrs_member":   t.is_manrs_member,
            "manrs_status":   t.manrs_status,
            "manrs_culprit":  t.is_manrs_culprit,
            "reputation": [
                {"label": "ASN infrastructure risk", "val": f2(th.infra_score),            "cls": self._risk_class01(th.infra_score)},
                {"label": "IP direct threat score",  "val": f2(th.ip_direct_threat_score),  "cls": self._risk_class01(th.ip_direct_threat_score)},
                {"label": "Fast-flux risk",          "val": f2(th.fast_flux_risk),          "cls": self._risk_class01(th.fast_flux_risk)},
                {"label": "DGA risk",                "val": f2(th.dga_risk),                "cls": self._risk_class01(th.dga_risk)},
                {"label": "Concentration risk",      "val": f2(th.concentration_risk),      "cls": self._risk_class01(th.concentration_risk)},
                {"label": "CertStream hits",         "val": str(th.certstream_hits),        "cls": "bad" if th.certstream_hits > 0 else "good"},
            ],
            "reason_codes":   th.reason_codes,
            "cotenancy":      cotenancy,
        }

    # ----- Section: IT remediation tear-off (back of report) ---------------

    def _executive_summary(self) -> dict[str, Any]:
        """The answer to "so what?", before any security vocabulary.

        Three questions, kept apart because they have different answers and
        different owners: what needs investigating, what can be fixed, what has to
        be watched. The old opening ("riskyexample.com's exposure is at critical
        exposure") named a grade band and told a reader nothing they could act on.

        The benchmark line is the part only Datazag can write: where this domain
        sits against the daily corpus measurement. It carries its denominator,
        because `dmarc_enforced` is 49.6% of DMARC-publishing domains and 11.5% of
        all resolving ones, and a share without its population is a wrong number.
        """
        findings = self.findings or []
        ext = self.vm.external_threat
        crit = [f for f in findings if f.get("severity") == "critical"]
        actions = self._build_remediation_actions()
        fixable = [a for a in actions if a.get("impact") in ("high", "medium")]

        counts_ok = ext.lookup_ok and not self._suppress_platform_counts
        monitor = None
        if counts_ok and ext.total_30d:
            names = [self._display_name(self._normalise_vendor_name(i.platform))
                     for i in sorted(ext.impersonations, key=lambda i: -i.count_30d)[:3]]
            monitor = (f"{ext.total_30d} lookalike domains imitating "
                       + ", ".join(names) if names else f"{ext.total_30d} lookalike domains")
        elif not ext.lookup_ok:
            monitor = "impersonation monitoring could not run for this report"
        elif ext.own_brand.count_30d:
            monitor = f"{ext.own_brand.count_30d} lookalike domains targeting your brand"

        # Verdict in plain words, driven by what was actually found.
        if crit:
            verdict = "needs immediate attention"
        elif fixable:
            verdict = "needs attention"
        else:
            verdict = "is broadly sound on what we can see"

        parts = []
        if crit:
            parts.append(f"{len(crit)} issue{'s' if len(crit) != 1 else ''} requiring "
                         "immediate investigation")
        if fixable:
            parts.append(f"{len(fixable)} weakness{'es' if len(fixable) != 1 else ''} that make"
                         f"{'' if len(fixable) != 1 else 's'} your domain easier to abuse")
        if counts_ok and ext.total_30d:
            parts.append("active impersonation of the platforms your staff rely on")
        headline = ("We found " + _join_clauses(parts) + ".") if parts else (
            "We found nothing requiring investigation on the surfaces we can see from outside.")

        return {
            "verdict": verdict,
            "headline": headline,
            "immediate": crit[0]["title"] if crit else None,
            "immediate_detail": (crit[0].get("detail") or "").split(". ")[0] if crit else None,
            "fixable": fixable[0]["title"] if fixable else None,
            "fixable_count": len(fixable),
            "monitor": monitor,
            "benchmark": self._benchmark_line(),
        }

    def _benchmark_line(self) -> Optional[str]:
        """Where this domain sits against the daily corpus measurement. Returns None
        when the observatory is unreachable — the report never guesses a corpus
        figure, and no line is better than an invented one."""
        obs = self._observatory
        if not obs.available:
            return None
        publishes_dmarc = not self.vm.trust.dmarc_risk
        stat = obs.get("dmarc_present")
        if stat is None:
            return None
        if publishes_dmarc:
            return (f"You publish DMARC. So does {stat.sentence()} "
                    f"(Datazag corpus, {stat.as_of}).")
        without = obs.share_without("dmarc_present")
        return (f"You do not publish DMARC, and neither does {without}% of the "
                f"{stat.denominator_label or 'corpus'} Datazag tracks ({stat.as_of}) "
                "\u2014 which is why mail claiming to be from you is so rarely challenged.")

    # Sections that carry a printed number, in page order. Anything not listed
    # renders unnumbered (DNS records, infra/routing, the remediation tear-off).
    NUMBERED_SECTIONS = ("glance", "attack_economy", "external_summary", "controls",
                         "hidden_infra", "timeline", "roadmap", "glossary")

    def _section_numbers(self) -> dict[str, str]:
        """Number the sections THIS audience actually renders.

        The numbers used to be hardcoded in the template, which broke every time a
        page moved: the report has jumped 01 to 06, renumbered twice more since,
        and the free tier — which renders a subset — had gaps all along that nobody
        was checking. Deriving them from the enabled set makes those bugs
        unrepresentable rather than merely fixed.
        """
        enabled = set(self.audience.sections)
        out, n = {}, 0
        for key in self.NUMBERED_SECTIONS:
            if key in enabled:
                n += 1
                out[key] = f"{n:02d}"
        return out

    def _cover_hook(self) -> dict[str, str]:
        """The cover headline, built from THIS domain's numbers.

        A cover that says "the attacker problem facing example.com" could sit on any
        report. A count could not: it is the one line that proves the report is about
        the reader before they have read anything.

        The branches are the same honesty rule the rest of the report follows — a
        failed impersonation lookup gets a headline that claims nothing either way,
        never the quiet all-clear that a zero would otherwise imply.
        """
        ext = self.vm.external_threat
        vendors = self._build_vendor_list()
        n_platforms = len(vendors)
        # The free tier must never bind a platform-GLOBAL count to this domain (the
        # "157" conflation — brand_page_data_contract.md). Its headline is built from
        # the stack size and brand-scoped counts only.
        platform_counts_ok = ext.lookup_ok and not self._suppress_platform_counts
        gaps = sum(max(0, c["total"] - c["deployed"]) for c in self._controls_categories())
        gap_clause = (f"the <strong>{gaps}</strong> fixable gap{'s' if gaps != 1 else ''} in your "
                      "defences that govern whether your own domain can be spoofed or "
                      "hijacked" if gaps else
                      "the controls that govern whether your own domain can be spoofed")

        # Most-targeted platform, for the deck.
        top = max(ext.impersonations, key=lambda i: i.count_30d, default=None)

        # ── The lead is whatever is most serious, not whatever is most marketable.
        # A domain whose infrastructure sits on an active command-and-control feed
        # has a bigger problem than lookalike domains, and leading with the
        # impersonation count there would bury it. Platform impersonation leads only
        # when nothing outranks it.
        critical = [f for f in (self.findings or []) if f.get("severity") == "critical"]
        if critical:
            lead = critical[0]
            others = []
            if platform_counts_ok and ext.total_30d:
                others.append(f"{ext.total_30d} lookalike domains imitating your platforms")
            if ext.own_brand.count_30d:
                others.append(f"{ext.own_brand.count_30d} targeting your brand")
            if gaps:
                others.append(f"{gaps} fixable gaps in your own controls")
            also = ("Also on this report: " + ", ".join(others) + "." ) if others else ""
            head = lead["title"].rstrip(".")
            # Don't lowercase an acronym: "RPKI state INVALID" must not become "rPKI".
            if not (len(head) > 1 and head[1].isupper()):
                head = head[0].lower() + head[1:]
            # `detail` is written for a reader; `evidence` is a log line.
            why = (lead.get("detail") or "").split(". ")[0].rstrip(".")
            return {
                "title": f"<strong>Immediate investigation:</strong> {head}.",
                "deck":  (f"{why}. " if why else "")
                         + "Act on this first &mdash; it concerns the infrastructure "
                           "serving your domain, not a lookalike of it. " + also,
            }

        if platform_counts_ok and ext.total_30d > 0:
            return {
                "title": f"<strong>{ext.total_30d} lookalike domains</strong> are imitating "
                         "the platforms your staff log into.",
                "deck":  (f"{self._display_name(self._normalise_vendor_name(top.platform))} is the "
                          f"most-targeted, with {top.count_30d} in the last 30 days. "
                          if top and top.count_30d else "")
                         + f"This report shows who is imitating you, and {gap_clause}.",
            }
        if ext.lookup_ok and ext.own_brand.count_30d > 0:   # brand-scoped: safe on every tier
            return {
                "title": f"<strong>{ext.own_brand.count_30d} lookalike domain"
                         f"{'s' if ext.own_brand.count_30d != 1 else ''}</strong> "
                         f"{'are' if ext.own_brand.count_30d != 1 else 'is'} targeting "
                         f"<span class=\"cover-domain\">{self.domain}</span>.",
                "deck":  f"Your customers are the target. This report shows the campaigns aimed "
                         f"at your brand, and {gap_clause}.",
            }
        if n_platforms:
            head = (f"Your staff log into <strong>{n_platforms} platform"
                    f"{'s' if n_platforms != 1 else ''}</strong> an attacker can imitate.")
            if not ext.lookup_ok:
                # Nothing was checked: say so on the cover rather than imply calm.
                return {"title": head,
                        "deck": "Impersonation monitoring could not run for this report, so "
                                f"nothing is claimed either way. What follows is {gap_clause}."}
            if platform_counts_ok:
                return {"title": head,
                        "deck": "None are being imitated today &mdash; but campaigns are "
                                f"intermittent, and this report shows {gap_clause} "
                                "when that changes."}
            # Free tier: state the surface, claim nothing about current activity.
            return {"title": head,
                    "deck": f"Each one is a lure an attacker can deploy against your staff. "
                            f"This report shows {gap_clause}."}
        return {
            "title": f"What an attacker sees when they look up "
                     f"<span class=\"cover-domain\">{self.domain}</span>.",
            "deck":  f"Everything here is read from public DNS, certificates and routing &mdash; "
                     f"the same data an attacker reads first. It shows {gap_clause}.",
        }

    def _build_remediation_actions(self) -> list[dict[str, Any]]:
        """Consolidated, de-duplicated, severity-sorted list of concrete fixes
        for the IT/infrastructure team — drawn from the defensive-controls audit
        (partial/missing controls and their exact action) and the findings
        (their remediation). This is the tear-off appendix at the back."""
        actions: list[dict[str, Any]] = []
        seen: set[str] = set()

        # 1) Control gaps with a concrete action.
        for cat in self._controls_categories():
            for c in cat["controls"]:
                if c.get("state") in ("partial", "missing") and c.get("action"):
                    key = c["name"].lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    # Severity follows the IMPACT of the gap, not the fact of it.
                    impact = control_impact(c["name"])
                    severity = {"high": "high", "medium": "medium", "low": "low"}[impact]
                    if c["state"] == "partial" and severity == "high":
                        severity = "medium"        # half-deployed beats absent
                    actions.append({
                        "title": c["name"],
                        "severity": severity,
                        "impact": impact,
                        "area": cat["name"],
                        "current": c.get("evidence", ""),
                        "step": c["action"],
                    })

        # 2) Findings with a remediation (critical/high/medium), not already covered.
        for f in self.findings:
            sev = f.get("severity")
            if sev not in ("critical", "high", "medium"):
                continue
            step = f.get("remediation")
            if not step or step == "Included in the full report.":   # teaser-redacted
                continue
            title = f.get("title") or f.get("finding") or "Finding"
            key = title.lower()
            if key in seen:
                continue
            seen.add(key)
            actions.append({
                "title": title,
                "severity": sev,
                "area": (f.get("category", "") or "finding").replace("_", " ").title(),
                "current": (f.get("evidence") or "")[:180],
                "step": step,
            })

        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        actions.sort(key=lambda a: rank.get(a["severity"], 4))
        # The tear-off is a work list, not an inventory: the ten most severe fit on
        # the page and get done. The rest stay on the contract for the next snapshot.
        return actions[:REMEDIATION_PLAN_MAX]

    # ----- Priorities ------------------------------------------------------

    def _build_priorities(self) -> list[dict[str, Any]]:
        """Three priorities spanning the three surfaces — platform, brand,
        infrastructure. The platform priority references OBSERVED impersonation
        activity from the rollup when present; otherwise it is synthesised from
        the highest-desirability detected vendor."""
        priorities = []
        used_findings: set[str] = set()

        # 1. Platform priority — observed campaign first, synthesis fallback
        vendors = self._build_vendor_list()
        actives = self._active_impersonations()
        if self._suppress_platform_counts and vendors:
            # Free health report: frame as readiness on the top target, citing no
            # platform-global counts and making no claim about observed volume.
            top = vendors[0]
            priorities.append({
                "severity": "medium",
                "severity_label": "Preventative",
                "surface": "vendor",
                "surface_label": "Platform",
                "surface_glyph": "▲",
                "title": f"Harden {top['name']} against impersonation",
                "action": (f"{top['name']} is the highest-value platform in your stack. Brief staff "
                           "on its phishing patterns and enforce phishing-resistant MFA on the tenant."),
                "why": (f"Every platform your staff log into is a brand an attacker can imitate to "
                        f"phish them; {top['name']} is the most valuable lure in your detected stack."),
                "owner": "IT ops / security",
                "effort": "< 1 day",
                "when": "Quarter",
            })
        elif actives:
            top_imp = actives[0]
            name = self._display_name(self._normalise_vendor_name(top_imp.platform))
            trend_note = {
                "up":   "Volume is rising week-on-week.",
                "down": "Volume is easing but infrastructure remains live.",
                "flat": "Volume is steady.",
            }[top_imp.trend]
            priorities.append({
                "severity": "crit",
                "severity_label": "Critical",
                "surface": "vendor",
                "surface_label": "Platform",
                "surface_glyph": "▲",
                "title": f"{top_imp.count_30d} lookalikes of {name} active in the last 30 days",
                "action": (f"Brief staff who use {name} on the active impersonation wave "
                           f"({top_imp.count_7d} new lookalike domains this week); verify "
                           "phishing-resistant MFA on the tenant."),
                "why": (f"Your organisation uses {name}; attackers have stood up "
                        f"{top_imp.count_30d} lookalike domains imitating it in the last "
                        f"30 days. {trend_note}"),
                "owner": "IT ops / security",
                "effort": "< 1 day",
                "when": "Fortnight",
            })
        elif vendors:
            # No impersonation observed in the window — do NOT claim an active
            # campaign (that contradicts the "Monitoring / no matches" state shown
            # elsewhere). Frame it as preventative readiness on the top target.
            # `checked` separates "we looked and saw none" from "the rollup was
            # unreachable": only the first may say there is no campaign.
            checked = self.vm.external_threat.lookup_ok
            top = vendors[0]
            priorities.append({
                "severity": "medium",
                "severity_label": "Preventative",
                "surface": "vendor",
                "surface_label": "Platform",
                "surface_glyph": "▲",
                "title": (f"Stay ready for {top['name']} impersonation — no active campaign right now"
                          if checked else
                          f"Stay ready for {top['name']} impersonation — not checked this run"),
                "action": ((f"No live impersonation of {top['name']} in the last 30 days. As your "
                            if checked else
                            f"Impersonation of {top['name']} could not be checked for this report. As your ")
                           + "highest-value platform target, keep staff briefed on its phishing "
                             "patterns and ensure phishing-resistant MFA is enforced."),
                "why": (f"{top['name']} is among the most-impersonated platforms in our "
                        "certificate-issuance data; campaigns are intermittent, so quiet today "
                        "doesn't mean quiet next month — readiness is the control."),
                "owner": "IT ops / security",
                "effort": "< 1 day",
                "when": "Quarter",
            })

        # 2. Brand priority — own-brand lookalikes first, then DMARC
        own = self.vm.external_threat.own_brand
        dmarc_finding_key = "dmarc_p_none"
        legacy_spoofable = self.ea.get("is_spoofable") and self.ea.get("dmarc_policy") in (None, "none", "")
        medallion_dmarc_risk = not self.ea and self.vm.trust.dmarc_risk
        if own.count_30d > 0:
            priorities.append({
                "severity": "high",
                "severity_label": "High",
                "surface": "brand",
                "surface_label": "Brand",
                "surface_glyph": "◆",
                "title": f"{own.count_30d} lookalike domain{'s' if own.count_30d != 1 else ''} "
                         f"targeting your brand (30 days)",
                "action": ("Review the lookalike watchlist above; "
                           "initiate takedown for any serving content or mail."),
                "why": ("Lookalikes of your own domain are the launchpad for customer-facing "
                        "fraud — invoice redirection, credential phishing in your name."),
                "owner": "Brand / legal",
                "effort": "varies",
                "when": "Fortnight",
            })
        elif legacy_spoofable or medallion_dmarc_risk:
            priorities.append({
                "severity": "high",
                "severity_label": "High",
                "surface": "brand",
                "surface_label": "Brand",
                "surface_glyph": "◆",
                "title": "Move DMARC to an enforcing policy",
                "action": ("Escalate the DMARC policy to p=quarantine after a 30-day reporting "
                           "validation window confirming all legitimate senders are authenticated."),
                "why": (f"Your @{self.domain} is currently spoofable by anyone. Brand-impersonation campaigns "
                        "against your customers can be sent from real-looking addresses with no infrastructure cost."),
                "owner": "DNS / email",
                "effort": "30 min",
                "when": "Quarter",
            })
            used_findings.add(dmarc_finding_key)
            used_findings.add("no_dmarc_enforcement")

        # 3. Infra priority — top critical/high finding that isn't already in priorities
        for f in self.findings:
            if f.get("severity") not in ("critical", "high"):
                continue
            f_key = f.get("finding") or ""
            # Skip any finding whose key, title, or remediation matches an already-used priority
            if f_key in used_findings:
                continue
            f_title = (f.get("title") or "").lower()
            if "dmarc" in f_title and dmarc_finding_key in used_findings:
                continue
            title = f.get("title") or f.get("finding", "Critical posture finding")
            action = f.get("remediation") or f.get("fix") or "See full finding detail."
            priorities.append({
                "severity": "crit" if f.get("severity") == "critical" else "high",
                "severity_label": (f.get("severity") or "high").capitalize(),
                "surface": "infra",
                "surface_label": "Infra",
                "surface_glyph": "◉",
                "title": title[:80],
                "action": action[:200],
                "why": (f.get("detail") or f.get("description") or "")[:200],
                "owner": "Infrastructure",
                "effort": "varies",
                "when": "Fortnight",
            })
            used_findings.add(f_key)
            break  # only one infra priority

        return priorities[:3]

    # ----- Vendor footprint ------------------------------------------------

    def _build_vendor_list(self) -> list[dict[str, Any]]:
        """Detected platforms ranked by attacker desirability.

        Sources:
        - txt_intelligence['saas_platforms'/'identity_providers'/etc.] from the
          existing technographics module — gives us the vendor name
        - dns_records['txt'] — gives us the actual TXT record string, matched
          back to the vendor by substring
        - mx_provider, isp from infrastructure
        - SPF includes parsed from dns_records['txt']

        TODO(technographics-2.0): the technographics module needs updating to
        emit a per-vendor record with structured evidence (rather than just a
        list of names). When that lands, this method becomes a pass-through.

        When the annotation lake supplied a platform stack (`platform_signals`
        and/or a platform `mailbox_provider`) it is authoritative — the lake
        already classified the providers, so we build straight from it and skip
        the regex fingerprinting.
        """
        ann = self.annotation
        if ann.platform_signals or (ann.mailbox_provider and is_platform_name(ann.mailbox_provider)):
            return self._vendor_list_from_annotation()

        ti = self.txt_intel or {}
        evidence_map: dict[str, list[dict[str, str]]] = {}

        # Build a TXT-record corpus we can match vendor names back against
        txt_records: list[str] = [t for t in (self.dns.get("txt", []) or []) if isinstance(t, str)]

        def _match_txt_for_vendor(name_key: str) -> list[str]:
            """Return TXT records that mention this vendor (best-effort substring match)."""
            patterns = _VENDOR_TXT_PATTERNS.get(name_key, [])
            matches = []
            for txt in txt_records:
                txt_lower = txt.lower()
                if any(p in txt_lower for p in patterns):
                    matches.append(txt)
            return matches

        # Categorised platforms from txt_intelligence — emit evidence as the actual TXT record
        for category in ("saas_platforms", "identity_providers", "payment_processors",
                         "ai_infrastructure", "security_tooling", "email_marketing"):
            for svc in ti.get(category, []):
                if not is_platform_name(svc):
                    continue   # drop email-auth/DNS tokens (e.g. "SPF Policy")
                key = self._normalise_vendor_name(svc)
                txt_matches = _match_txt_for_vendor(key)
                if txt_matches:
                    # Add the most evidential TXT record (shortest non-SPF is usually the verification token)
                    non_spf = [t for t in txt_matches if not t.startswith("v=spf1")]
                    chosen = non_spf[0] if non_spf else txt_matches[0]
                    evidence_map.setdefault(key, []).append({
                        "key": "TXT",
                        "val": chosen[:80] + ("…" if len(chosen) > 80 else ""),
                    })
                else:
                    # Fallback: at least record that the category match was made
                    evidence_map.setdefault(key, []).append({
                        "key": "STACK",
                        "val": "technographic match",
                    })

        # MX provider — classify the actual MX hostnames (strong, live signal),
        # not the now-dead annotation's mx_provider field. The host that receives
        # the domain's mail outranks any TXT verification token.
        mx_records = self.dns.get("mx", []) or []
        for m in mx_records:
            mx_host = (m.get("host") if isinstance(m, dict) else str(m)) or ""
            mxl = mx_host.lower()
            for vendor_key, patterns in _VENDOR_MX_PATTERNS.items():
                if any(p in mxl for p in patterns):
                    evidence_map.setdefault(vendor_key, []).append({"key": "MX", "val": mx_host})
                    break
        # Annotation fallback (only if it ever repopulates)
        mx_provider = self.infra.get("mx_provider")
        if mx_provider and not any(e["key"] == "MX" for evs in evidence_map.values() for e in evs):
            key = self._normalise_vendor_name(mx_provider)
            evidence_map.setdefault(key, []).append({"key": "MX", "val": str(mx_provider)})

        # SPF includes — emit one evidence pill per detected include
        for txt in txt_records:
            if txt.startswith("v=spf1"):
                for token in txt.split():
                    if token.startswith("include:"):
                        host = token.split(":", 1)[1]
                        key = self._spf_to_vendor_key(host)
                        if key:
                            evidence_map.setdefault(key, []).append({"key": "SPF", "val": host})

        # Subdomain CNAME targets — Tier-1 evidence. Pulls vendor signals from
        # the subdomain estate (e.g. support.example.com → desk.zoho.com).
        # This is the strongest detection mechanism because CNAMEs prove current
        # active use, not just historical domain ownership.
        for host, target in self._subdomain_cname_targets():
            for vendor_key, patterns in _VENDOR_CNAME_PATTERNS.items():
                if any(p in target for p in patterns):
                    evidence_map.setdefault(vendor_key, []).append({
                        "key": "CNAME",
                        "val": f"{host} → {target}",
                    })
                    break  # one vendor per CNAME match

        # Corpus-detected platform stack (vm.external_threat.detected_platforms).
        # In --live mode these usually duplicate the DNS-evidence detections
        # above; in snapshot/fixture mode they are the only source.
        existing_norms = {self._norm_platform_key(k) for k in evidence_map}
        for platform in self.vm.external_threat.detected_platforms:
            if not is_platform_name(platform):
                continue
            key = self._normalise_vendor_name(platform)
            if self._norm_platform_key(key) not in existing_norms:
                existing_norms.add(self._norm_platform_key(key))
                evidence_map.setdefault(key, []).append({
                    "key": "CORPUS",
                    "val": "platform stack detection",
                })

        # De-duplicate evidence per vendor (same key+val collapsing)
        for key, items in evidence_map.items():
            seen: set[tuple[str, str]] = set()
            deduped: list[dict[str, str]] = []
            for item in items:
                sig = (item["key"], item["val"])
                if sig not in seen:
                    seen.add(sig)
                    deduped.append(item)
            evidence_map[key] = deduped

        # Build vendor records, applying desirability lookup + observed
        # impersonation activity from the rollup
        vendors = []
        for name_key, evidence in evidence_map.items():
            entry = self._lookup_platform(name_key)
            tier = entry["tier"]
            tier_label = {"high": "High", "med-high": "Med-high", "med": "Med", "low": "Low"}[tier]
            tier_short = {"high": "med", "med-high": "med", "med": "med", "low": "low"}[tier]
            imp = self._impersonation_for(name_key)
            strength = _evidence_strength(evidence)
            vendors.append({
                "name":             self._display_name(name_key),
                "name_key":         name_key,
                "role":             entry["role"],
                "why":              entry["why"],
                "tier":             tier,
                "tier_label":       tier_label,
                "tier_short":       tier_short,
                "weight":           entry["weight"],
                "evidence":         evidence,
                "evidence_short":   ", ".join(f"{e['key']}: {e['val']}" for e in evidence[:2]),
                "strength":         strength,
                # confidence: "confirmed" when there's live-routing/active-use
                # evidence (MX/CNAME/SPF); "indicative" for a verification token alone.
                "confidence":       "confirmed" if strength >= 3 else "indicative",
                "impersonation":    imp,
            })

        # Rank: confirmed (live-use) evidence first, then by attacker desirability.
        # So MX→Microsoft 365 outranks a Google Workspace TXT verification token.
        vendors.sort(key=lambda v: (0 if v["strength"] >= 3 else 1, -v["weight"]))
        return vendors

    # Lake signal_type → the report's evidence-pill vocabulary (+ strength via
    # _EVIDENCE_STRENGTH). The lake's platform_signals are SPF/TXT only; MX is
    # synthesised from the flat mailbox_provider field (see below).
    _ANNOTATION_SIGNAL_KIND = {
        "MX": "MX", "SPF_INCLUDE": "SPF", "SPF": "SPF", "TXT": "TXT", "CNAME": "CNAME",
    }

    def _vendor_list_from_annotation(self) -> list[dict[str, Any]]:
        """Build the detected-platform list from the annotation lake. The lake's
        `platform_signals` cover only the apex SPF/TXT axes — the MX-derived
        platform lives in the flat `mailbox_provider` field, so we fold it in as a
        high-confidence MX signal. That is what keeps MX-over-TXT resolved:
        Microsoft 365 via MX outranks a Google Workspace TXT verification token.
        A vendor is 'confirmed' when it has a live-use signal (MX/SPF strength) or
        the lake's own confidence is >= 0.7."""
        ann = self.annotation
        # (provider, pill-kind, confidence, evidence)
        raw: list[tuple[str, str, float, str]] = []
        if ann.mailbox_provider and is_platform_name(ann.mailbox_provider):
            raw.append((ann.mailbox_provider, "MX", 0.95, ann.mailbox_provider))
        for s in ann.platform_signals:
            kind = self._ANNOTATION_SIGNAL_KIND.get(
                (s.signal_type or "").upper(), (s.signal_type or "STACK").upper())
            raw.append((s.provider, kind, float(s.confidence or 0.0), s.evidence or s.provider or ""))

        agg: dict[str, dict] = {}
        for provider, kind, conf, evidence in raw:
            if not is_platform_name(provider):
                continue
            key = self._normalise_vendor_name(provider)
            val = (evidence or "").strip()
            rec = agg.setdefault(key, {"evidence": [], "conf": 0.0})
            rec["evidence"].append({
                "key": kind,
                "val": val[:80] + ("…" if len(val) > 80 else ""),
            })
            rec["conf"] = max(rec["conf"], conf)

        vendors: list[dict[str, Any]] = []
        for name_key, rec in agg.items():
            # de-duplicate evidence pills (same key+val)
            seen: set[tuple[str, str]] = set()
            evidence: list[dict[str, str]] = []
            for item in rec["evidence"]:
                sig = (item["key"], item["val"])
                if sig not in seen:
                    seen.add(sig)
                    evidence.append(item)
            entry = self._lookup_platform(name_key)
            tier = entry["tier"]
            tier_label = {"high": "High", "med-high": "Med-high", "med": "Med", "low": "Low"}[tier]
            tier_short = {"high": "med", "med-high": "med", "med": "med", "low": "low"}[tier]
            strength = _evidence_strength(evidence)
            confirmed = rec["conf"] >= 0.7 or strength >= 3
            vendors.append({
                "name":           self._display_name(name_key),
                "name_key":       name_key,
                "role":           entry["role"],
                "why":            entry["why"],
                "tier":           tier,
                "tier_label":     tier_label,
                "tier_short":     tier_short,
                "weight":         entry["weight"],
                "evidence":       evidence,
                "evidence_short": ", ".join(f"{e['key']}: {e['val']}" for e in evidence[:2]),
                "strength":       strength,
                "confidence":     "confirmed" if confirmed else "indicative",
                "impersonation":  self._impersonation_for(name_key),
            })

        vendors.sort(key=lambda v: (0 if v["confidence"] == "confirmed" else 1, -v["weight"]))
        return vendors

    def _subdomain_cname_targets(self) -> list[tuple[str, str]]:
        """Extract (host, cname_target) tuples from subdomain data.

        The upstream pipeline emits subdomain CNAME data, but the field name
        varies across pipeline versions. This helper tries a handful of common
        shapes so detection works without requiring a coordinated rename:
            subdomain.cname             (preferred — flat string)
            subdomain.cname_target      (alternative name)
            subdomain.target / .canonical
            subdomain.dns_records.cname (nested list/string)
            subdomain.records[*]        (some shapes flatten everything here)

        Targets are returned lowercased and stripped of trailing dots.
        Empty/missing CNAMEs are silently skipped.
        """
        out: list[tuple[str, str]] = []
        for s in self.subdomains:
            host = s.get("dns_name") or s.get("host") or ""
            cname_records = s.get("cname_records")
            target = (
                (cname_records[0] if isinstance(cname_records, list) and cname_records else "")
                or s.get("cname")
                or s.get("cname_target")
                or s.get("target")
                or s.get("canonical")
                or ""
            )
            # Try nested dns_records dict
            if not target and isinstance(s.get("dns_records"), dict):
                cn = s["dns_records"].get("cname")
                if isinstance(cn, list) and cn:
                    target = cn[0]
                elif isinstance(cn, str):
                    target = cn
            if isinstance(target, list):
                target = target[0] if target else ""
            target = str(target).strip().rstrip(".").lower()
            if host and target:
                out.append((host, target))
        return out

    @staticmethod
    def _normalise_vendor_name(raw: str) -> str:
        """Lowercase, strip, collapse common aliases."""
        s = (raw or "").strip().lower()
        # Microsoft family — including bare "microsoft" from MX provider classification
        if any(k in s for k in ("microsoft", "outlook", "office 365", "ms 365", "exchange online")):
            return "microsoft 365"
        if "google" in s and ("workspace" in s or "search console" in s):
            return "google workspace"
        if "google" in s:
            return "google workspace"
        if "mailchimp" in s:
            return "mailchimp"
        if "apple" in s:
            return "apple"
        if "zoho" in s:
            return "zoho"
        if "citrix" in s:
            return "citrix"
        if "mailgun" in s:
            return "mailgun"
        if "emailsignatures" in s.replace(" ", "") or "email signatures 365" in s:
            return "email signatures"
        return s

    @staticmethod
    def _spf_to_vendor_key(spf_host: str) -> str | None:
        h = spf_host.lower()
        if "outlook" in h or "protection.outlook" in h:
            return "microsoft 365"
        if "google.com" in h or "_spf.google" in h:
            return "google workspace"
        if "mcsv.net" in h or "mailchimp" in h:
            return "mailchimp"
        if "mailgun" in h:
            return "mailgun"
        if "zoho" in h:
            return "zoho"
        if "emailsignatures365" in h:
            return "email signatures"
        return None

    @staticmethod
    def _lookup_platform(name_key: str) -> dict[str, Any]:
        for k, v in PLATFORM_DESIRABILITY.items():
            if k in name_key or name_key in k:
                return v
        return DEFAULT_PLATFORM_ENTRY

    @staticmethod
    def _display_name(name_key: str) -> str:
        return {
            "microsoft 365":    "Microsoft 365",
            "google workspace": "Google Workspace",
            "okta":             "Okta",
            "docusign":         "DocuSign",
            "mailchimp":        "Mailchimp",
            "apple":            "Apple",
            "zoho":             "Zoho",
            "zoho desk":        "Zoho Desk",
            "zoho crm":         "Zoho CRM",
            "zoho mail":        "Zoho Mail",
            "zoho generic":     "Zoho (other)",
            "citrix":           "Citrix",
            "mailgun":          "Mailgun",
            "email signatures": "Email Signatures 365",
            "zendesk":          "Zendesk",
            "freshservice":     "Freshservice",
            "freshdesk":        "Freshdesk",
            "servicenow":       "ServiceNow",
            "atlassian":        "Atlassian (Jira/Confluence)",
            "help scout":       "Help Scout",
            "intercom":         "Intercom",
            "salesforce":       "Salesforce",
            "hubspot":          "HubSpot",
            "pipedrive":        "Pipedrive",
            "connectwise":      "ConnectWise",
            "autotask":         "Autotask",
            "cloudflare":       "Cloudflare",
            "aws":              "AWS",
            "azure":            "Microsoft Azure",
            "vercel":           "Vercel",
            "netlify":          "Netlify",
            "statuspage":       "Atlassian Statuspage",
            "betterstack":      "BetterStack",
            "notion":           "Notion",
            "gitbook":          "GitBook",
            "shopify":          "Shopify",
            "sendgrid":         "SendGrid",
            "wordpress engine": "WP Engine",
        }.get(name_key, name_key.title())

    # ----- Section 06: Outbound posture ------------------------------------

    # ----- Section 06: Defensive controls audit ----------------------------

    def _capture_field(self, name: str, *containers: dict) -> Any:
        """Resolve a DNS-capture-schema field across possible upstream shapes.

        Tries each provided container in order, then falls back to the top-level
        `output` dict. Returns the first non-None value found, or None.

        This lets the renderer be forward-compatible with whatever sub-dict
        structure the upstream pipeline ends up using — fields can land in
        email_auth, certificates, threat_flags, or stay at the top level.
        """
        for c in containers:
            if c is None:
                continue
            val = c.get(name)
            if val is not None:
                return val
        return self.o.get(name)

    @staticmethod
    def _parse_bimi_record(bimi: str | None) -> dict[str, Any]:
        """Parse a BIMI record string into its tags.

        Returns a dict with:
            has_record:  True if a valid-looking BIMI record was passed
            logo_url:    the l= tag value if present (logo URL)
            vmc_url:     the a= tag value if present (VMC URL — the trust signal)
            vmc_host:    hostname of the VMC URL if extractable
        """
        out: dict[str, Any] = {"has_record": False, "logo_url": None,
                               "vmc_url": None, "vmc_host": None}
        if not bimi or not isinstance(bimi, str):
            return out
        if "v=bimi1" not in bimi.lower():
            return out
        out["has_record"] = True
        for part in bimi.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "l":
                out["logo_url"] = v
            elif k == "a":
                out["vmc_url"] = v
                # Extract host for compact display
                try:
                    from urllib.parse import urlparse
                    out["vmc_host"] = urlparse(v).netloc or None
                except Exception:
                    pass
        return out

    def _defensive_controls_audit(self) -> dict[str, list[dict[str, Any]]]:
        """Audit externally-observable defensive controls.

        Returns a dict of category → list of control records. Each record is:
            {name, state, evidence, action}
        where state ∈ {'deployed', 'partial', 'missing'}.

        IMPORTANT: every control here is Tier-1 — directly observable in
        DNS, SSL, or RDAP. Tier-3 controls (MFA enforcement, Conditional
        Access policies, training programmes) are NOT included because we
        cannot externally verify them. Those live as 'checklist items' on
        the platform card.
        """
        reg = self.vm.registration
        ea = self.ea or {}
        rdap = self.rdap or {}
        flags = self.flags or {}
        findings = self.findings or []
        missing_layers = ea.get("missing_layers") or []

        controls: dict[str, list[dict[str, Any]]] = {
            "Email authentication": [],
            "Certificate & web":    [],
            "DNS security":         [],
            "Domain registration":  [],
        }

        # ─── Email authentication ─────────────────────────────────────────
        # DMARC has moved from best-practice to operational requirement: Google
        # and Yahoo have required it for bulk senders since Feb 2024; Microsoft
        # since May 2025; Apple and Comcast are aligned. The action text reflects
        # this — the deliverability angle matters even before the impersonation
        # defence side.
        dmarc_mandate_note = (" Increasingly required by Google, Yahoo, Microsoft, "
                              "Apple, and Comcast for bulk-sender deliverability.")
        dmarc = ea.get("dmarc_policy") or ""
        if dmarc == "reject":
            controls["Email authentication"].append({
                "name": "DMARC enforcement", "state": "deployed",
                "evidence": "p=reject (full enforcement)", "action": None,
            })
        elif dmarc == "quarantine":
            controls["Email authentication"].append({
                "name": "DMARC enforcement", "state": "partial",
                "evidence": "p=quarantine (mail quarantined, not rejected)",
                "action": "Move to p=reject for full enforcement once quarantine has been stable.",
            })
        elif dmarc == "none":
            controls["Email authentication"].append({
                "name": "DMARC enforcement", "state": "partial",
                "evidence": "p=none (monitoring only, no enforcement)",
                "action": "After 30-day reporting validation, move to p=quarantine, then p=reject."
                          + dmarc_mandate_note,
            })
        else:
            controls["Email authentication"].append({
                "name": "DMARC enforcement", "state": "missing",
                "evidence": "No DMARC TXT record published",
                "action": f"Publish DMARC record at _dmarc.{self.domain} starting with p=none for reporting."
                          + dmarc_mandate_note,
            })

        # SPF — check both apex AND mail subdomain. SPF doesn't inherit, so a
        # protected apex with an unprotected mail.* subdomain is partial coverage,
        # not full. The mail_spf column gives us the direct fact.
        spf = ea.get("spf") or self._capture_field("spf", ea) or ""
        mail_spf = self._capture_field("mail_spf", ea) or ""
        spf_strict = ea.get("spf_strictness") or ""
        apex_strict = "-all" in spf or spf_strict == "strict"
        apex_soft   = "~all" in spf or spf_strict == "soft"
        apex_present = bool(spf)
        mail_present = bool(mail_spf)
        mail_strict = "-all" in mail_spf

        if apex_strict and mail_strict:
            controls["Email authentication"].append({
                "name": "SPF strict mode", "state": "deployed",
                "evidence": "Apex SPF -all + mail subdomain has its own SPF (both protected)",
                "action": None,
            })
        elif apex_strict and not mail_present:
            controls["Email authentication"].append({
                "name": "SPF strict mode", "state": "partial",
                "evidence": "Apex SPF -all, but mail subdomain has no SPF record of its own "
                            "(SPF does not inherit — mail.* is unprotected)",
                "action": f"Publish SPF record at mail.{self.domain} matching the sending "
                          "infrastructure used from that subdomain.",
            })
        elif apex_strict and mail_present and not mail_strict:
            controls["Email authentication"].append({
                "name": "SPF strict mode", "state": "partial",
                "evidence": "Apex SPF -all, but mail subdomain SPF is permissive",
                "action": f"Tighten SPF at mail.{self.domain} to -all.",
            })
        elif apex_soft:
            controls["Email authentication"].append({
                "name": "SPF strict mode", "state": "partial",
                "evidence": "SPF ~all (soft-fail) at apex",
                "action": "Tighten apex SPF to -all once includes are stable.",
            })
        elif apex_present:
            controls["Email authentication"].append({
                "name": "SPF strict mode", "state": "partial",
                "evidence": "SPF published at apex but permissive",
                "action": "Tighten apex SPF to -all.",
            })
        else:
            controls["Email authentication"].append({
                "name": "SPF strict mode", "state": "missing",
                "evidence": "No SPF record",
                "action": "Publish SPF TXT record with -all and all legitimate senders included.",
            })

        # BIMI — parse the raw record string to detect VMC reference.
        # If 'a=' tag is present, the VMC is referenced directly; that's the
        # full trust signal. If only a logo URL ('l=') is present, the record
        # exists but no VMC has been completed yet (or they're relying on
        # Yahoo's VMC-optional policy).
        bimi_raw = ea.get("bimi") or self._capture_field("bimi", ea)
        bimi_parsed = self._parse_bimi_record(bimi_raw)
        bimi_missing_via_layer = "BIMI" in missing_layers

        if not bimi_parsed["has_record"] and bimi_missing_via_layer:
            controls["Email authentication"].append({
                "name": "BIMI", "state": "missing",
                "evidence": "No BIMI record at default._bimi",
                "action": "Publish BIMI record (requires DMARC at p=quarantine or stronger; "
                          "VMC ~$1,500/year from DigiCert or Entrust gives the verified logo).",
            })
        elif bimi_parsed["has_record"] and bimi_parsed["vmc_url"]:
            # Strongest case: BIMI deployed AND VMC referenced
            vmc_host_clause = (f" — VMC referenced at {bimi_parsed['vmc_host']}"
                               if bimi_parsed["vmc_host"] else "")
            controls["Email authentication"].append({
                "name": "BIMI", "state": "deployed",
                "evidence": f"BIMI record present with VMC{vmc_host_clause} "
                            f"(VMC ~$1,500/year requires registered trademark + identity verification)",
                "action": None,
                "trust_signal": True,
            })
        elif bimi_parsed["has_record"]:
            # BIMI record exists but no VMC — partial credit
            controls["Email authentication"].append({
                "name": "BIMI", "state": "partial",
                "evidence": "BIMI record present but no VMC referenced "
                            "(a= tag absent — logo display limited to providers that "
                            "accept BIMI without VMC, e.g. Yahoo)",
                "action": "Obtain a VMC (~$1,500/year from DigiCert or Entrust) "
                          "to unlock verified logo display in Gmail and Apple Mail.",
            })
        else:
            # Fallback when ea.missing_layers and ea.bimi disagree
            controls["Email authentication"].append({
                "name": "BIMI", "state": "missing",
                "evidence": "No BIMI record at default._bimi",
                "action": "Publish BIMI record (requires DMARC at p=quarantine or stronger).",
            })

        # DKIM — limited external visibility. Selectors are arbitrary subdomains
        # chosen by the sending platform, so we can't enumerate them without
        # knowing what they are. We can probe a handful of common selectors
        # (selector1, selector2 for M365; google for Workspace) but absence
        # there doesn't mean DKIM isn't configured.
        controls["Email authentication"].append({
            "name": "DKIM signing", "state": "limited",
            "evidence": "Limited external visibility — selectors are arbitrary, "
                        "not enumerable without internal knowledge",
            "action": "Verify internally: Microsoft 365 typically uses selector1 and "
                      "selector2; Google Workspace uses google. Each sending platform "
                      "has its own selectors; each should be rotated annually.",
        })

        # MTA-STS — check both the deployment AND the mode. 'enforce' is the
        # full trust signal; 'testing' means the policy file is published but
        # senders won't actually enforce it (no protection in practice yet).
        has_mta_sts = self._capture_field("has_mta_sts", ea, flags)
        mta_sts_mode = (self._capture_field("mta_sts_mode", ea, flags) or "").lower()
        # Fall back to subdomain detection if the upstream hasn't populated the columns
        mtasts_subs = [s for s in self.subdomains if "mta-sts" in (s.get("dns_name") or s.get("host") or "").lower()]
        mta_sts_deployed = bool(has_mta_sts) or bool(mtasts_subs)

        if mta_sts_deployed and mta_sts_mode == "enforce":
            controls["Email authentication"].append({
                "name": "MTA-STS", "state": "deployed",
                "evidence": "Policy published in enforce mode",
                "action": None,
                "trust_signal": True,
            })
        elif mta_sts_deployed and mta_sts_mode == "testing":
            controls["Email authentication"].append({
                "name": "MTA-STS", "state": "partial",
                "evidence": "Policy published in testing mode (senders observe but do not enforce)",
                "action": "Move MTA-STS policy from mode=testing to mode=enforce once "
                          "you've validated that legitimate mail isn't being blocked.",
            })
        elif mta_sts_deployed:
            # Detected but mode not visible
            controls["Email authentication"].append({
                "name": "MTA-STS", "state": "deployed",
                "evidence": "mta-sts subdomain published (policy mode not captured)",
                "action": None,
            })
        else:
            controls["Email authentication"].append({
                "name": "MTA-STS", "state": "missing",
                "evidence": "No MTA-STS policy detected",
                "action": "Publish MTA-STS DNS TXT and policy file in testing mode initially, "
                          "then move to enforce.",
            })

        # TLS-RPT — receiver-side reporting partner to MTA-STS. Tells senders
        # where to send TLS failure reports. Deployed means the org is paying
        # attention to delivery integrity, not just configuring it.
        tlsrpt = self._capture_field("tlsrpt_rua", ea)
        if tlsrpt:
            controls["Email authentication"].append({
                "name": "TLS-RPT", "state": "deployed",
                "evidence": f"TLS-RPT reporting configured ({tlsrpt[:60]}{'…' if len(str(tlsrpt)) > 60 else ''})",
                "action": None,
            })
        else:
            controls["Email authentication"].append({
                "name": "TLS-RPT", "state": "missing",
                "evidence": "No TLS-RPT record at _smtp._tls",
                "action": "Publish a TLS-RPT TXT record pointing to an inbox or aggregator "
                          "that can receive TLS failure reports.",
            })

        # ─── Certificate & web ────────────────────────────────────────────
        # Contract first (vm.hygiene), legacy only as a fallback for --input_json.
        if ea.get("caa_present") or flags.get("has_caa"):
            controls["Certificate & web"].append({
                "name": "CAA records", "state": "deployed",
                "evidence": "CAA records published — issuance restricted",
                "action": None,
            })
        else:
            controls["Certificate & web"].append({
                "name": "CAA records", "state": "missing",
                "evidence": "No CAA record — any CA can issue for this domain",
                "action": "Publish CAA records restricting issuance to the CAs you actually use",
            })

        hsts_findings = [f for f in findings
                         if "hsts" in (f.get("finding") or "").lower()
                         or "hsts" in (f.get("title") or "").lower()]
        if hsts_findings:
            most_severe = sorted(hsts_findings,
                                 key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                                     f.get("severity"), 4))[0]
            sev = most_severe.get("severity", "")
            state = "missing" if sev in ("critical", "high") else "partial"
            controls["Certificate & web"].append({
                "name": "HSTS deployment", "state": state,
                "evidence": most_severe.get("title") or "HSTS gaps detected",
                "action": most_severe.get("remediation")
                          or "Deploy HSTS header with includeSubDomains; consider preload",
            })
        else:
            controls["Certificate & web"].append({
                "name": "HSTS deployment", "state": "deployed",
                "evidence": "No HSTS gaps detected",
                "action": None,
            })

        # HTTPS certificate health — direct cert state from the SSL handshake.
        # 'Deployed' means a valid cert with reasonable runway. 'Partial' means
        # valid but expiring imminently. 'Missing' means handshake failed.
        certs = self.certs or {}
        https_ok = self._capture_field("https_cert_ok", certs)
        https_days = self._capture_field("https_cert_days_left", certs)
        https_issuer = self._capture_field("https_cert_issuer", certs)
        if https_ok is None and https_days is None:
            pass  # field not populated — skip the row entirely
        elif https_ok and isinstance(https_days, int) and https_days >= 14:
            issuer_clause = f", issued by {https_issuer}" if https_issuer else ""
            controls["Certificate & web"].append({
                "name": "HTTPS certificate health", "state": "deployed",
                "evidence": f"Certificate valid, {https_days} days remaining{issuer_clause}",
                "action": None,
            })
        elif https_ok and isinstance(https_days, int) and https_days >= 0:
            controls["Certificate & web"].append({
                "name": "HTTPS certificate health", "state": "partial",
                "evidence": f"Certificate valid but expiring in {https_days} days",
                "action": "Schedule certificate renewal — most ACME setups auto-renew "
                          "within 30 days of expiry.",
            })
        else:
            controls["Certificate & web"].append({
                "name": "HTTPS certificate health", "state": "missing",
                "evidence": "Certificate handshake failed or certificate invalid",
                "action": "Investigate HTTPS configuration — handshake or validity error.",
            })

        # security.txt — vulnerability disclosure process. Few SMBs publish one;
        # presence signals a mature security posture (someone has thought about
        # how external researchers will reach them when they find something).
        has_sec_txt = self._capture_field("has_security_txt", flags)
        sec_txt_url = self._capture_field("security_txt_url", flags)
        if has_sec_txt:
            url_clause = f" at {sec_txt_url}" if sec_txt_url else ""
            controls["Certificate & web"].append({
                "name": "security.txt", "state": "deployed",
                "evidence": f"Vulnerability disclosure file published{url_clause} — "
                            "signals a working security-contact process",
                "action": None,
                "trust_signal": True,
            })
        else:
            controls["Certificate & web"].append({
                "name": "security.txt", "state": "missing",
                "evidence": "No /.well-known/security.txt — researchers have no "
                            "documented channel to report vulnerabilities",
                "action": f"Publish a security.txt file at /.well-known/security.txt on "
                          f"{self.domain} with a contact, expires date, and preferred languages.",
            })

        # ─── DNS security ─────────────────────────────────────────────────
        if ea.get("dnssec") or reg.dnssec or rdap.get("dnssec_enabled"):
            controls["DNS security"].append({
                "name": "DNSSEC", "state": "deployed",
                "evidence": "Domain signed; delegation signing active",
                "action": None,
            })
        else:
            controls["DNS security"].append({
                "name": "DNSSEC", "state": "missing",
                "evidence": "DNSSEC not enabled",
                "action": "Enable DNSSEC at registrar; publish DS records",
            })

        # ─── Domain registration ──────────────────────────────────────────
        lock_count = rdap.get("lock_count", 0) or _locks_from_status(reg.status)
        if lock_count >= 4:
            controls["Domain registration"].append({
                "name": "Registrar locks", "state": "deployed",
                "evidence": f"{lock_count} client-side locks (transfer, delete, update, renew)",
                "action": None,
            })
        elif lock_count >= 1:
            controls["Domain registration"].append({
                "name": "Registrar locks", "state": "partial",
                "evidence": f"{lock_count} of 4 client-side locks",
                "action": "Enable all four client-side locks at the registrar",
            })
        else:
            controls["Domain registration"].append({
                "name": "Registrar locks", "state": "missing",
                "evidence": "No registrar locks",
                "action": "Enable client-side locks (transfer, delete, update, renew); "
                          "consider server-side locks for high-value domains",
            })

        abuse_email = (rdap.get("abuse_email") or self.vm.abuse.registrar_abuse_email
                       or self.vm.abuse.asn_abuse_email)
        if abuse_email:
            controls["Domain registration"].append({
                "name": "Abuse contact published", "state": "deployed",
                "evidence": f"Contact: {abuse_email}",
                "action": None,
            })
        else:
            controls["Domain registration"].append({
                "name": "Abuse contact published", "state": "missing",
                "evidence": "No abuse contact in RDAP",
                "action": "Verify the registrar has a current abuse contact on file",
            })

        return controls

    def _controls_summary(self) -> dict[str, int]:
        """Total/deployed/partial/missing/limited counts across all controls.

        'limited' is a fourth state for controls that exist in principle but
        can't be reliably verified externally — DKIM is the canonical example.
        Limited-state controls are excluded from deployed/partial/missing
        counts so the summary headline ('X of Y deployed') remains honest:
        Y is the count of verifiable controls only.
        """
        audit = self._defensive_controls_audit()
        deployed = partial = missing = limited = 0
        verifiable_total = 0
        for ctrls in audit.values():
            for c in ctrls:
                state = c.get("state", "")
                if state == "deployed":
                    deployed += 1
                    verifiable_total += 1
                elif state == "partial":
                    partial += 1
                    verifiable_total += 1
                elif state == "missing":
                    missing += 1
                    verifiable_total += 1
                elif state == "limited":
                    limited += 1
        return {
            "total":    verifiable_total,
            "deployed": deployed,
            "partial":  partial,
            "missing":  missing,
            "limited":  limited,
        }

    def _controls_categories(self) -> list[dict[str, Any]]:
        """Flatten the audit into a list with per-category counts, ready for
        the Jinja template. 'limited'-state controls (e.g. DKIM) are excluded
        from the deployed/total ratio so it remains an honest count of
        externally verifiable controls."""
        audit = self._defensive_controls_audit()
        out = []
        for category, ctrls in audit.items():
            for c in ctrls:
                c["impact"] = control_impact(c["name"])
            verifiable = [c for c in ctrls if c["state"] != "limited"]
            deployed = sum(1 for c in verifiable if c["state"] == "deployed")
            total = len(verifiable)
            out.append({
                "name":      category,
                "controls":  ctrls,
                "deployed":  deployed,
                "total":     total,
            })
        return out

    # ----- Section 06: Outbound posture (legacy v8.6 helper, retained) -----

    def _build_posture_layers(self) -> list[dict[str, Any]]:
        """Six-layer posture grid. Each entry covers one defence layer with its
        current state, severity, and a short technical detail line."""
        ea = self.ea or {}
        flags = self.flags or {}

        # DMARC
        dmarc_policy = ea.get("dmarc_policy") or ""
        if dmarc_policy in ("reject",):
            dmarc_state, dmarc_class, dmarc_mini = "Enforced", "good", "Reject"
        elif dmarc_policy == "quarantine":
            dmarc_state, dmarc_class, dmarc_mini = "Partial", "warn", "Quarantine"
        elif dmarc_policy == "none":
            dmarc_state, dmarc_class, dmarc_mini = "Monitor only", "bad", "p=none"
        else:
            dmarc_state, dmarc_class, dmarc_mini = "Missing", "missing", "Absent"
        dmarc_detail = (f"DMARC published with policy <code>p={dmarc_policy}</code>."
                        if dmarc_policy else "No DMARC record published — domain is fully spoofable.")
        if dmarc_policy == "none":
            dmarc_detail += " Receivers take no action on unauthenticated mail."

        # SPF
        spf = (ea.get("spf") or "")
        spf_strict = ea.get("spf_strictness") or ""
        if "-all" in spf or spf_strict == "strict":
            spf_state, spf_class, spf_mini = "Strict", "good", "-all"
            spf_detail = "SPF published with strict failure mode (-all)."
        elif "~all" in spf or spf_strict == "soft":
            spf_state, spf_class, spf_mini = "Soft", "warn", "~all"
            spf_detail = "SPF in soft-fail mode (~all) — unauthorised mail may still reach inboxes marked as suspicious."
        elif spf:
            spf_state, spf_class, spf_mini = "Permissive", "warn", "?all"
            spf_detail = "SPF published but permissive."
        else:
            spf_state, spf_class, spf_mini = "Missing", "missing", "None"
            spf_detail = "No SPF record published."

        # BIMI
        if "BIMI" in (ea.get("missing_layers") or []):
            bimi_state, bimi_class, bimi_mini = "Not deployed", "missing", "Absent"
            bimi_detail = "No BIMI record. Your logo doesn't appear in supporting inboxes."
        else:
            bimi_state, bimi_class, bimi_mini = "Configured", "good", "Live"
            bimi_detail = "BIMI record present; logo appears in supporting inboxes."

        # CAA
        if flags.get("has_caa"):
            caa_state, caa_class, caa_mini = "Configured", "good", "Live"
            caa_detail = "CAA records restrict which CAs can issue certificates."
        else:
            caa_state, caa_class, caa_mini = "Not deployed", "missing", "Absent"
            caa_detail = "Any CA can issue certificates for this domain — rogue cert risk."

        # MTA-STS (best-effort: not always present in output dict)
        mtasts_subs = [s for s in self.subdomains if "mta-sts" in (s.get("dns_name") or s.get("host") or "").lower()]
        if mtasts_subs:
            mtasts_state, mtasts_class, mtasts_mini = "Configured", "good", "Live"
            mtasts_detail = "MTA-STS policy published; receivers can verify TLS before delivery."
        else:
            mtasts_state, mtasts_class, mtasts_mini = "Not deployed", "missing", "Absent"
            mtasts_detail = "No MTA-STS policy. Inbound TLS is not enforced for receivers."

        # DNSSEC
        rdap = self.rdap or {}
        if rdap.get("dnssec_enabled"):
            dnssec_state, dnssec_class, dnssec_mini = "Enabled", "good", "Signed"
            dnssec_detail = "DNSSEC validates DNS responses cryptographically."
        else:
            dnssec_state, dnssec_class, dnssec_mini = "Not enabled", "missing", "Unsigned"
            dnssec_detail = "DNSSEC not enabled — DNS responses are not cryptographically validated."

        return [
            {"label": "DMARC",   "state": dmarc_state,  "state_class": dmarc_class,  "mini_label": dmarc_mini,  "detail": dmarc_detail},
            {"label": "SPF",     "state": spf_state,    "state_class": spf_class,    "mini_label": spf_mini,    "detail": spf_detail},
            {"label": "BIMI",    "state": bimi_state,   "state_class": bimi_class,   "mini_label": bimi_mini,   "detail": bimi_detail},
            {"label": "CAA",     "state": caa_state,    "state_class": caa_class,    "mini_label": caa_mini,    "detail": caa_detail},
            {"label": "MTA-STS", "state": mtasts_state, "state_class": mtasts_class, "mini_label": mtasts_mini, "detail": mtasts_detail},
            {"label": "DNSSEC",  "state": dnssec_state, "state_class": dnssec_class, "mini_label": dnssec_mini, "detail": dnssec_detail},
        ]

    # ----- Section 07: Hidden infrastructure -------------------------------

    def _build_registration(self) -> dict[str, Any] | None:
        """Build the registration strip data for §07.

        Reads from self.rdap (populated by the upstream rdap_lookup_async module).
        Returns None if RDAP failed or is missing — template skips the strip.

        Fields consumed:
            registered, updated, expires
            domain_age_days, days_to_expiry
            registrar_name, registrar_address, registrar_label, registrar_score
            abuse_email
            dnssec_enabled, lock_count, recent_transfer
        """
        rdap = self.rdap or {}
        if not rdap.get("rdap_available"):
            return None

        # ── Domain age cell ────────────────────────────────────────────────
        age_days = rdap.get("domain_age_days")
        registered = rdap.get("registered") or "—"
        if isinstance(age_days, int) and age_days >= 0:
            if age_days >= 365:
                years = age_days / 365.25
                age_value = f"{years:.1f} years"
            else:
                age_value = f"{age_days} days"
            age_sub = f"Registered {registered}"
            if isinstance(age_days, int) and age_days < 90:
                age_sub += ' &middot; <span class="risk-chip warn">New domain</span>'
        else:
            age_value = "—"
            age_sub = "Registration date unavailable"

        # ── Last updated cell ──────────────────────────────────────────────
        updated = rdap.get("updated") or "—"
        days_to_expiry = rdap.get("days_to_expiry")
        if updated and updated != "—":
            updated_value = updated
            # Derive a sub-line that combines days-since-update + expiry context
            try:
                from datetime import datetime
                u_date = datetime.strptime(updated, "%Y-%m-%d")
                days_since = max(0, (datetime.now() - u_date).days)
                if days_since == 0:
                    updated_sub = "Updated today"
                elif days_since < 365:
                    updated_sub = f"{days_since} days ago"
                else:
                    yrs = days_since / 365.25
                    updated_sub = f"{yrs:.1f} years ago"
            except (ValueError, TypeError):
                updated_sub = ""
        else:
            updated_value = "—"
            updated_sub = "No 'last changed' event in RDAP"

        # Add expiry context to the updated sub-line where relevant
        if isinstance(days_to_expiry, int) and days_to_expiry > 0:
            if days_to_expiry < 30:
                updated_sub += ' &middot; <span class="risk-chip bad">Expires in ' + str(days_to_expiry) + 'd</span>'
            elif days_to_expiry < 90:
                updated_sub += ' &middot; <span class="risk-chip warn">Expires in ' + str(days_to_expiry) + 'd</span>'

        # ── Registrar cell ─────────────────────────────────────────────────
        registrar_value = rdap.get("registrar_name") or "—"
        registrar_label = rdap.get("registrar_label") or ""
        registrar_score = rdap.get("registrar_score", 0) or 0
        if registrar_score >= 2:
            chip_class = "bad"
        elif registrar_score == 1:
            chip_class = "warn"
        elif "low" in registrar_label.lower() or "enterprise" in registrar_label.lower():
            chip_class = "good"
        else:
            chip_class = "med"
        registrar_chip_class = chip_class if registrar_label else None
        registrar_chip_label = registrar_label

        # ── Abuse contact cell ─────────────────────────────────────────────
        abuse_value = rdap.get("abuse_email") or "Not found"

        # Build the 'security' sub-line under abuse contact: DNSSEC + lock count + transfer signal
        sec_bits = []
        if rdap.get("dnssec_enabled"):
            sec_bits.append('<span class="risk-chip good">DNSSEC on</span>')
        else:
            sec_bits.append('<span class="risk-chip warn">DNSSEC off</span>')
        lock_count = rdap.get("lock_count", 0) or 0
        if lock_count >= 4:
            sec_bits.append('<span class="risk-chip good">Locked</span>')
        elif lock_count > 0:
            sec_bits.append(f'{lock_count} lock{"s" if lock_count != 1 else ""}')
        if rdap.get("recent_transfer"):
            sec_bits.append('<span class="risk-chip warn">Recent transfer</span>')
        security_sub = " &middot; ".join(sec_bits)

        return {
            "rdap_available":       True,
            "dnssec_enabled":       bool(rdap.get("dnssec_enabled")),
            "age_value":            age_value,
            "age_sub":              age_sub,
            "updated_value":        updated_value,
            "updated_sub":          updated_sub,
            "registrar_value":      registrar_value,
            "registrar_chip_class": registrar_chip_class,
            "registrar_chip_label": registrar_chip_label,
            "abuse_value":          abuse_value,
            "security_sub":         security_sub,
            "address":              (rdap.get("registrar_address") or "").strip() or None,
        }

    def _estate_count(self, risk_level: str) -> int:
        return sum(1 for s in self.subdomains if s.get("risk_level") == risk_level)

    def _estate_missed_renewals_count(self) -> int:
        return len((self.cert_analysis or {}).get("missed_renewals", []) or [])

    def _estate_cross_san_count(self) -> int:
        return len((self.cert_analysis or {}).get("cross_domain_sans", []) or [])

    def _estate_callout(self) -> dict[str, Any] | None:
        """Choose one summary callout line for the page."""
        if self._estate_missed_renewals_count() > 0:
            n = self._estate_missed_renewals_count()
            return {
                "kind": "warn",
                "icon": "!",
                "text": (f"<strong>{n} certificate{'s' if n != 1 else ''} missed auto-renewal.</strong> "
                         "After expiry, browsers display security warnings to all visitors. Trigger manual "
                         "renewal and verify the ACME/Let's Encrypt cron jobs."),
            }
        if self._estate_cross_san_count() > 10:
            return {
                "kind": "warn",
                "icon": "i",
                "text": (f"<strong>{self._estate_cross_san_count()} cross-domain SANs detected.</strong> "
                         "Shared certificate SANs reveal infrastructure relationships between unrelated estates. "
                         "Worth reviewing whether any of those relationships should be visible to outsiders."),
            }
        if self._estate_count("high") > 0:
            return {
                "kind": "warn",
                "icon": "!",
                "text": (f"<strong>{self._estate_count('high')} high-risk subdomain{'s' if self._estate_count('high') != 1 else ''}.</strong> "
                         "Review the sample below — typically staging, dev, or legacy infrastructure that hasn't been hardened."),
            }
        return {
            "kind": "good",
            "icon": "✓",
            "text": ("<strong>Estate hygiene looks clean.</strong> No missed certificate renewals, "
                     "no high-risk subdomains, and cross-domain SAN exposure is within normal range."),
        }

    def _build_subdomain_sample(self, limit: int = 8) -> list[dict[str, Any]]:
        """Subdomains sorted by risk for the sample table."""
        order = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}
        items = sorted(self.subdomains, key=lambda s: order.get(s.get("risk_level", "info"), 5))
        out = []
        for s in items[:limit]:
            risk = s.get("risk_level", "info")
            risk_class = "high" if risk in ("critical", "high") else "med" if risk == "medium" else "low"
            risk_label = risk.upper() if risk in ("critical", "high") else risk.title()
            # cert expiry from the canonical subdomain shape (days_remaining/is_expired)
            days = s.get("days_remaining")
            if s.get("is_expired"):
                cert_str = "cert expired"
            elif isinstance(days, int):
                cert_str = f"{days}d cert"
            else:
                cert_str = "—"
            notes = []
            if s.get("is_dangling_cname"):           notes.append("dangling CNAME")
            if s.get("is_takeover_vulnerable"):      notes.append("takeover-vulnerable")
            if s.get("is_malicious_ip"):             notes.append("malicious IP")
            if s.get("is_delegated"):                notes.append("delegated")
            if not notes:                            notes.append("active")
            out.append({
                "host":       s.get("dns_name") or s.get("host") or "—",
                "age":        cert_str,
                "notes":      ", ".join(notes),
                "risk_class": risk_class,
                "risk_label": risk_label,
            })
        return out

    # ----- Section 08: Timeline --------------------------------------------

    def _build_timeline_summary(self) -> str:
        """Narrative summary for the timeline page header block."""
        rdap = self.rdap or {}
        age_days = rdap.get("domain_age_days") or 0
        registered = rdap.get("registered") or "—"
        ch = self.changes or {}
        any_changes = any(ch.get(k) for k in ("ns_changed", "ip_changed", "country_changed",
                                              "ttl_drop_big", "is_dynamic_dns", "mx_misconfigured"))
        if any_changes:
            return (f"Domain registered {registered} ({age_days} days old). "
                    f"<strong>Notable infrastructure changes</strong> observed over the past twelve months — "
                    "see the signal grid below for specifics.")
        return (f"Domain registered {registered} ({age_days} days old). "
                "<strong>Infrastructure has been stable</strong> over the past twelve months — "
                "no NS, IP, country, TTL, or MX changes outside normal operation.")

    def _build_change_signal_list(self) -> list[dict[str, Any]]:
        """The six change-signal cards across the timeline page."""
        ch = self.changes or {}
        signals = [
            ("NS provider",     "ns_changed",        "Changed", "Stable"),
            ("Hosting IP",      "ip_changed",        "Changed", "Stable"),
            ("Country",         "country_changed",   "Moved",   "Stable"),
            ("TTL behaviour",   "ttl_drop_big",      "Anomalous", "Stable"),
            ("Dynamic DNS",     "is_dynamic_dns",    "Active",  "Not used"),
            ("MX configuration","mx_misconfigured",  "Issue",   "Healthy"),
        ]
        # ⚠️ `changes` is EMPTY on the live path (no contract field yet). Reading a
        # missing key as the stable label meant every card asserted "Stable" /
        # "Healthy" from data we never had — which is how the timeline came to report
        # "MX configuration — Healthy" for a domain the DNS page reports as having no
        # MX records at all. With no baseline there is nothing to compare against, so
        # the honest state is "not assessed". Same rule as the nullable scores.
        assessed = bool(ch)
        return [
            {"label": label, "changed": bool(ch.get(key)), "assessed": assessed,
             "state": (active_label if ch.get(key) else stable_label) if assessed
                      else "Not assessed"}
            for label, key, active_label, stable_label in signals
        ]

    # ----- Section 09: Roadmap ---------------------------------------------

    def _build_roadmap_bucket(self, bucket: str) -> list[dict[str, str]]:
        """Bucket findings into fortnight/quarter/year by severity heuristic.

        Heuristic:
        - fortnight  ← critical findings + section 09 priorities marked "Fortnight"
        - quarter    ← high findings + DMARC/SPF/BIMI work + section 09 priorities marked "Quarter"
        - year       ← medium findings + estate-wide hygiene work
        """
        out: list[dict[str, str]] = []

        for p in self._build_priorities():
            if p["when"].lower() == bucket:
                out.append({
                    "title":   p["title"],
                    "surface": p["surface_label"],
                    "effort":  p["effort"],
                })

        # Add findings not already covered by priorities
        priority_titles = {p["title"] for p in self._build_priorities()}
        for f in self.findings:
            sev = f.get("severity", "")
            title = (f.get("title") or f.get("finding") or "Untitled finding")[:80]
            if title in priority_titles:
                continue
            if bucket == "fortnight" and sev == "critical":
                out.append({"title": title, "surface": "Infra", "effort": "varies"})
            elif bucket == "quarter" and sev == "high":
                out.append({"title": title, "surface": "Infra", "effort": "varies"})
            elif bucket == "year" and sev == "medium":
                out.append({"title": title, "surface": "Infra", "effort": "varies"})

        # Cap per bucket for visual hygiene
        return out[:6]

    # ----- Section 10: Glossary --------------------------------------------

    @staticmethod
    def _glossary_items() -> list[dict[str, str]]:
        """The eight terms a cold reader actually meets. Longer lists go unread."""
        return [
            {"term": "Trusted platform impersonation",
             "def":  "Attackers imitate a platform your staff trust to capture credentials. 85&ndash;90% of observed activity."},
            {"term": "Brand impersonation",
             "def":  "Attackers imitate your brand to defraud your customers &mdash; lookalikes, typosquats, fraudulent certificates."},
            {"term": "<span class=\"acronym\">DMARC</span>",
             "def":  "Tells receiving servers what to do with unauthenticated mail claiming to be from you (none / quarantine / reject)."},
            {"term": "<span class=\"acronym\">SPF</span>",
             "def":  "Lists which mail servers may send as your domain."},
            {"term": "<span class=\"acronym\">CAA</span>",
             "def":  "Restricts which certificate authorities may issue for your domain."},
            {"term": "Dangling CNAME",
             "def":  "A subdomain pointing at a deleted service &mdash; claimable by an attacker."},
            {"term": "Certificate Transparency",
             "def":  "Public logs of every SSL certificate issued; we watch them in real time."},
            {"term": "Trust Grade",
             "def":  "Our A&ndash;F grade from a 0&ndash;100 composite; higher = more exposed."},
        ]

    # ----- TOC -------------------------------------------------------------

    @staticmethod
    def _toc_items() -> list[dict[str, str]]:
        return [
            {"title": "At-a-glance", "kind": "context", "section": "glance",
             "desc": "Your Trust Grade, how the two slices of your attack surface compare, and what to fix first."},
            {"title": "How the attack economy works", "kind": "context", "section": "attack_economy",
             "desc": "Why exposure has little to do with whether anyone singled you out."},
            {"title": "External threat", "kind": "findings", "section": "external_summary",
             "desc": "Who is imitating your platforms and your brand, from this domain\u2019s own observations."},
            {"title": "Outbound posture", "kind": "findings", "section": "controls",
             "desc": "DMARC, SPF, CAA, MTA-STS &mdash; whether your own domain can be spoofed, hijacked or mis-issued against."},
            {"title": "Full DNS records", "kind": "findings", "section": "dns_records",
             "desc": "Every record we captured, with the defensive weaknesses called out inline."},
            {"title": "Infrastructure & routing intelligence", "kind": "findings", "section": "infra_routing",
             "desc": "The quality of the IP, prefix and ASN hosting you &mdash; routing integrity, reputation, co-tenancy."},
            {"title": "Hidden infrastructure", "kind": "findings", "section": "hidden_infra",
             "desc": "Forgotten subdomains and dormant services &mdash; the assets attackers find that you may not know exist."},
            {"title": "Twelve-month timeline", "kind": "findings", "section": "timeline",
             "desc": "Infrastructure changes over the past year, and any that look unusual."},
            {"title": "Your minimisation roadmap", "kind": "action", "section": "roadmap",
             "desc": "The fixes sequenced by impact &mdash; fortnight, quarter, year &mdash; with effort and ownership."},
            {"title": "IT remediation plan", "kind": "action", "section": "remediation_plan",
             "desc": "Every fix with its current state and exact step. Detachable, for whoever owns the changes."},
            # Plain "&": the toc template escapes it. Pre-encoding double-encodes.
            {"title": "Glossary & methodology", "kind": "context", "section": "glossary",
             "desc": "Definitions of every technical term, plus how the evidence was gathered."},
        ]
