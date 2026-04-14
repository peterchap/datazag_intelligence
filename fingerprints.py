# fingerprints.py

TXT_FINGERPRINTS = [
    # Identity / SSO
    (r"^MS=ms",                               "Microsoft 365",                    "identity"),
    (r"^MS=[A-F0-9]{40}$",                   "Microsoft 365 (alt token)",         "identity"),
    (r"adobe-idp-site-verification=",         "Adobe IDP",                        "identity"),
    (r"cisco-ci-domain-verification=",        "Cisco CI / Webex",                 "identity"),
    (r"apple-domain-verification=",           "Apple",                            "identity"),

    # Google
    (r"^google-site-verification=",           "Google Workspace / Search Console","saas"),

    # Marketing / CRM
    (r"pardot\d+=",                           "Salesforce Pardot",                "saas"),
    (r"^asv=",                                "Atlassian (Jira/Confluence)",       "saas"),
    (r"miro-verification=",                   "Miro",                             "saas"),
    (r"lucidlink-verification=",              "LucidLink",                        "saas"),
    (r"formstack-domain-verification=",       "Formstack",                        "saas"),
    (r"onetrust-domain-verification=",        "OneTrust",                         "saas"),
    (r"hubspot-developer-verification=",      "HubSpot",                          "saas"),
    (r"intercom-verification-code=",          "Intercom",                         "saas"),
    (r"zendesk-verification=",                "Zendesk",                          "saas"),
    (r"drift-domain-verification=",           "Drift",                            "saas"),
    (r"segment-site-verification=",           "Segment",                          "saas"),
    (r"marketo-domain-verification=",         "Marketo",                          "saas"),
    (r"klaviyo-site-verification=",           "Klaviyo",                          "saas"),

    # Payment / Legal
    (r"stripe-verification=",                 "Stripe",                           "payment"),
    (r"docusign=",                            "DocuSign",                         "saas"),
    (r"^amazonses:",                          "Amazon SES",                       "email"),

    # Monitoring / Security
    (r"intersight=",                          "Cisco Intersight",                 "saas"),
    (r"have-i-been-pwned-verification=",      "HaveIBeenPwned",                   "security"),
    (r"globalsign-domain-verification=",      "GlobalSign CA",                    "security"),

    # Social / Publishing
    (r"facebook-domain-verification=",        "Facebook / Meta",                  "saas"),
    (r"brave-ledger-verification=",           "Brave Publisher",                  "saas"),
    (r"pinterest-site-verification=",         "Pinterest",                        "saas"),

    # Email policy
    (r"^v=spf1",                              "SPF Policy",                       "email"),
    (r"^v=DMARC1",                            "DMARC Policy",                     "email"),
]

ADDITIONAL_TXT_FINGERPRINTS = [
    # Password managers
    (r"lastpass-verification-code=",          "LastPass",                         "identity"),
    (r"1password-site-verification=",         "1Password",                        "identity"),
    (r"dashlane-domain-verification=",        "Dashlane",                         "identity"),
    (r"bitwarden-domain-verification=",       "Bitwarden",                        "identity"),

    # AI / Dev tooling
    (r"^v=MCPv1;",                            "MCP Server (Anthropic)",           "ai_infra"),
    (r"anthropic-domain-verification",        "Anthropic / Claude API",           "ai_infra"),
    (r"cursor-domain-verification",           "Cursor AI",                        "ai_infra"),
    (r"openai-domain-verification=",          "OpenAI API",                       "ai_infra"),
    (r"github-copilot-",                      "GitHub Copilot",                   "ai_infra"),

    # Developer / DevOps
    (r"postman-domain-verification=",         "Postman",                          "saas"),
    (r"mongodb-site-verification=",           "MongoDB Atlas",                    "saas"),
    (r"bugcrowd-verification=",               "Bugcrowd",                         "security"),
    (r"airtable-verification=",               "Airtable",                         "saas"),
    (r"notion-domain-verification=",          "Notion",                           "saas"),
    (r"canva-site-verification=",             "Canva",                            "saas"),
    (r"pendo-domain-verification=",           "Pendo",                            "saas"),
    (r"anodot-domain-verification=",          "Anodot",                           "saas"),
    (r"status-page-domain-verification=",     "Atlassian Statuspage",             "saas"),
    (r"jamf-site-verification=",              "Jamf MDM",                         "saas"),
    (r"krisp-domain-verification=",           "Krisp",                            "saas"),
    (r"zoom-domain-verification=",            "Zoom",                             "saas"),
    (r"knowbe4-site-verification=",           "KnowBe4",                          "security"),
    (r"dropbox-domain-verification=",         "Dropbox",                          "saas"),
    (r"apperio-domain-verification=",         "Apperio",                          "saas"),
    (r"twilio-domain-verification=",          "Twilio",                           "saas"),
    (r"atlassian-domain-verification=",       "Atlassian Cloud",                  "saas"),
    (r"atlassian-sending-domain-verification=","Atlassian Mail",                  "email"),

    # Salesforce
    (r"^SFMC-",                               "Salesforce Marketing Cloud",       "saas"),
    (r"^SFMC--",                              "Salesforce Marketing Cloud",       "saas"),

    # Trend Micro
    (r"^tmes=",                               "Trend Micro Email Security",       "security"),

    # Email marketing
    (r"v=verifydomain",                       "Microsoft 365 (legacy verify)",    "identity"),

    # Cloud assets in TXT (anomaly signal)
    (r"\.cloudfront\.net$",                   "AWS CloudFront reference",         "infra"),
]

# Services with confirmed material breach history
HIGH_RISK_SAAS = {
    "lastpass":  "LastPass — 2022 vault exfiltration breach",
    "okta":      "Okta — 2023 support system breach",
    "twilio":    "Twilio — 2022 employee phishing breach",
    "mailchimp": "Mailchimp — 2023 social engineering breach",
    "circleci":  "CircleCI — 2023 secrets exposure breach",
    "dropbox":   "Dropbox Sign — 2024 data breach",
}

# TXT content anomaly patterns
TXT_ANOMALY_PATTERNS = [
    (r"[^a-zA-Z0-9=:_\-. /+@]",
     "Contains unusual characters — possible leaked secret or stale record"),
    (r"(?:password|passwd|secret|token|key|api_key|apikey|credential)",
     "Contains sensitive keyword — potential credential exposure"),
]