"""
mx_platforms.py
---------------
Lookup table: MX host -> email PLATFORM + category. A subdomain's MX usually points
at a sending/receiving SaaS, not the corporate mailbox — transactional ESPs
(SendGrid, Mailgun, SES, Postmark...), marketing ESPs (Mailchimp, Marketo, HubSpot,
Klaviyo...), security gateways (Proofpoint, Mimecast...), support desks (Zendesk,
Freshdesk...), or another mailbox provider. Surfacing these reveals the email-vendor
/ shadow-SaaS attack surface the apex MX alone misses.

Substring match against the (lowercased) MX exchange host; longest key wins.
Curated — extend freely. Could later move to a provider_catalog category in the lake
or feed a corpus-driven auto-builder (cf. build_ns_provider_catalog.py).
"""

# (mx_host_substring, provider, category)
MX_PLATFORMS = [
    # ── Transactional ESPs ────────────────────────────────────────────────
    ("sendgrid.net",        "SendGrid",            "Transactional ESP"),
    ("mailgun.org",         "Mailgun",             "Transactional ESP"),
    ("mailgun.net",         "Mailgun",             "Transactional ESP"),
    ("amazonses.com",       "Amazon SES",          "Transactional ESP"),
    ("inbound-smtp",        "Amazon SES",          "Transactional ESP"),  # inbound-smtp.<region>.amazonaws.com
    ("mtasv.net",           "Postmark",            "Transactional ESP"),
    ("postmarkapp.com",     "Postmark",            "Transactional ESP"),
    ("sparkpostmail.com",   "SparkPost",           "Transactional ESP"),
    ("mailjet.com",         "Mailjet",             "Transactional ESP"),
    ("mandrillapp.com",     "Mandrill",            "Transactional ESP"),
    ("socketlabs",          "SocketLabs",          "Transactional ESP"),
    ("elasticemail",        "Elastic Email",       "Transactional ESP"),
    ("smtp2go",             "SMTP2GO",             "Transactional ESP"),
    ("sendpulse",           "SendPulse",           "Transactional ESP"),
    ("mailersend",          "MailerSend",          "Transactional ESP"),
    # ── Marketing ESPs / automation ───────────────────────────────────────
    ("mcsv.net",            "Mailchimp",           "Marketing ESP"),
    ("rsgsv.net",           "Mailchimp",           "Marketing ESP"),
    ("mailchimp",           "Mailchimp",           "Marketing ESP"),
    ("mktomail.com",        "Marketo",             "Marketing ESP"),
    ("hubspotemail.net",    "HubSpot",             "Marketing ESP"),
    ("hubspot",             "HubSpot",             "Marketing ESP"),
    ("pardot.com",          "Pardot",              "Marketing ESP"),
    ("exacttarget.com",     "Salesforce Marketing Cloud", "Marketing ESP"),
    ("klaviyomail.com",     "Klaviyo",             "Marketing ESP"),
    ("klaviyo",             "Klaviyo",             "Marketing ESP"),
    ("sailthru",            "Sailthru",            "Marketing ESP"),
    ("iterable",            "Iterable",            "Marketing ESP"),
    ("braze",               "Braze",               "Marketing ESP"),
    ("customer.io",         "Customer.io",         "Marketing ESP"),
    ("sendinblue",          "Brevo (Sendinblue)",  "Marketing ESP"),
    ("brevo",               "Brevo",               "Marketing ESP"),
    ("constantcontact",     "Constant Contact",    "Marketing ESP"),
    ("createsend.com",      "Campaign Monitor",    "Marketing ESP"),
    ("cmail1.com",          "Campaign Monitor",    "Marketing ESP"),
    ("emarsys",             "Emarsys",             "Marketing ESP"),
    ("responsys",           "Oracle Responsys",    "Marketing ESP"),
    ("dotmailer",           "Dotdigital",          "Marketing ESP"),
    ("dotdigital",          "Dotdigital",          "Marketing ESP"),
    # ── Support / helpdesk ────────────────────────────────────────────────
    ("zendesk.com",         "Zendesk",             "Support Platform"),
    ("freshdesk",           "Freshdesk",           "Support Platform"),
    ("freshemail",          "Freshdesk",           "Support Platform"),
    ("helpscout",           "Help Scout",          "Support Platform"),
    ("intercom",            "Intercom",            "Support Platform"),
    ("desk.com",            "Salesforce Desk",     "Support Platform"),
    # ── Security gateways (inbound filtering) ─────────────────────────────
    ("pphosted.com",        "Proofpoint",          "Security Gateway"),
    ("ppe-hosted.com",      "Proofpoint",          "Security Gateway"),
    ("mimecast",            "Mimecast",            "Security Gateway"),
    ("messagelabs.com",     "Symantec.cloud",      "Security Gateway"),
    ("barracuda",           "Barracuda",           "Security Gateway"),
    ("barracudanetworks",   "Barracuda",           "Security Gateway"),
    ("iphmx.com",           "Cisco Ironport",      "Security Gateway"),
    ("trendmicro",          "Trend Micro",         "Security Gateway"),
    ("fireeyecloud",        "FireEye",             "Security Gateway"),
    ("mailcontrol.com",     "Forcepoint",          "Security Gateway"),
    # ── Mailbox providers (corporate / consumer) ──────────────────────────
    ("mail.protection.outlook.com", "Microsoft 365", "Mailbox Provider"),
    ("outlook.com",         "Microsoft 365",       "Mailbox Provider"),
    ("google.com",          "Google Workspace",    "Mailbox Provider"),
    ("googlemail.com",      "Google Workspace",    "Mailbox Provider"),
    ("zoho",                "Zoho Mail",           "Mailbox Provider"),
    ("yandex",              "Yandex",              "Mailbox Provider"),
    ("fastmail",            "Fastmail",            "Mailbox Provider"),
    ("messagingengine.com", "Fastmail",            "Mailbox Provider"),
    ("pphosted",            "Proofpoint",          "Security Gateway"),
    ("secureserver.net",    "GoDaddy / Microsoft", "Mailbox Provider"),
    ("emailsrvr.com",       "Rackspace Email",     "Mailbox Provider"),
]

# longest key first so the most specific match wins
_SORTED = sorted(MX_PLATFORMS, key=lambda t: -len(t[0]))


def classify_mx(mx_host: str):
    """(provider, category) for an MX exchange host, or (None, None).
    Accepts a bare host or a "pref host" string."""
    if not mx_host:
        return (None, None)
    h = str(mx_host).strip().lower()
    if " " in h:                 # "10 mxa.mailgun.org" -> "mxa.mailgun.org"
        h = h.split(" ", 1)[-1].strip()
    h = h.rstrip(".")
    for key, provider, category in _SORTED:
        if key in h:
            return (provider, category)
    return (None, None)
