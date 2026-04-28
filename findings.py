"""
DatazagCanonicalAdapter
-----------------------
Parses the full Datazag DNS record format — the canonical flat shape
that includes DNS records, annotation, risk scoring, cert data,
SMTP banner, change detection, and labels in a single object.

No separate scorer calls needed. Everything is inline.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from typing import Optional
from fingerprints import HIGH_RISK_SAAS

# ---------------------------------------------------------------------------
# Certificate data
# ---------------------------------------------------------------------------

@dataclass
class CertProfile:
    ok: bool
    days_remaining: Optional[int]
    issuer: str
    issuer_org: Optional[str]       # Parsed from issuer string
    san_count: Optional[int]
    label: Optional[str]            # "low_friction_ca" | "ev_ca" | "ov_ca" etc.
    is_expiring_soon: bool          # < 30 days
    is_lets_encrypt: bool
    is_self_signed: bool


@dataclass  
class SMTPProfile:
    cert: Optional[CertProfile]
    banner_raw: Optional[str]
    banner_host: Optional[str]
    banner_detail: Optional[str]
    provider_confirmed: bool        # Banner confirms MX provider identity
    provider_name: Optional[str]    # Extracted from banner


# ---------------------------------------------------------------------------
# Email authentication — full picture
# ---------------------------------------------------------------------------

@dataclass
class EmailAuthProfile:
    # SPF
    spf_raw: Optional[str]
    spf_strictness: str             # "strict" | "soft" | "permissive" | "none"
    spf_includes: list[str]
    spf_ip4_ranges: list[str]
    spf_all_mechanism: str          # "-all" | "~all" | "+all" | "?all" | "none"

    # DMARC
    dmarc_raw: Optional[str]
    dmarc_policy: Optional[str]     # "reject" | "quarantine" | "none"
    dmarc_pct: int                  # percentage — 100 means full enforcement
    dmarc_aspf: Optional[str]       # "s" (strict) | "r" (relaxed)
    dmarc_adkim: Optional[str]
    dmarc_rua: Optional[str]
    dmarc_ruf: Optional[str]
    dmarc_fo: Optional[str]         # Failure reporting options

    # MTA-STS
    mta_sts_status: str             # "NOERROR" | "NXDOMAIN" | "NOT_FOUND"
    mta_sts_mode: Optional[str]     # "enforce" | "testing" | "none"

    # TLS-RPT
    tls_rpt_status: str
    tls_rpt_rua: Optional[str]

    # BIMI
    bimi_status: str
    bimi_raw: Optional[str]

    # DNSSEC
    dnssec_enabled: Optional[bool]

    # Derived
    is_fully_authenticated: bool    # SPF -all + DMARC p=reject + strict alignment
    is_spoofable: bool
    spoofing_severity: str
    missing_layers: list[str]       # What's absent that should be there


# ---------------------------------------------------------------------------
# Infrastructure labels (already computed inline)
# ---------------------------------------------------------------------------

@dataclass
class InfrastructureAnnotation:
    # MX provider
    mx_provider_name: Optional[str]
    mx_mbp_category: Optional[str]   # "Mailbox Provider" | "Email Security Provider" etc.
    mx_risk_bias: float
    mx_trust_nudge: float

    # NS provider
    ns_provider_name: Optional[str]
    ns_provider_category: Optional[str]
    ns_brand_hit: bool
    ns_risk_bias: Optional[float]

    # Provider trust
    provider_trust_nudge: float
    is_cdn_ugc: bool

    # ASN / ISP
    asn: int
    isp_name: Optional[str]
    isp_country: Optional[str]
    asn_risk_level: str             # "trustworthy" | "low" | "medium" | "high" | "critical"

    # TLD
    tld_country: Optional[str]
    tld_risk_level: str

    # Computed net trust
    net_trust_score: float          # sum of all nudges


# ---------------------------------------------------------------------------
# Risk scoring (already computed inline)
# ---------------------------------------------------------------------------

@dataclass
class RiskScoreDetail:
    rule: str
    points: int
    description: Optional[str]


@dataclass
class ComputedRiskProfile:
    score: int                      # 0–100
    bucket: str                     # "low" | "medium" | "high" | "critical"
    reasons: list[RiskScoreDetail]
    profile: str                    # "default" | custom profile name
    config_version: str

    # Derived
    positive_contributions: list[RiskScoreDetail]   # Rules that raised score
    negative_contributions: list[RiskScoreDetail]   # Rules that lowered score
    net_trust_rules: int                             # Points from trust rules only


# ---------------------------------------------------------------------------
# Change detection signals
# ---------------------------------------------------------------------------

@dataclass
class ChangeSignals:
    ns_changed: bool
    ip_changed: bool
    country_changed: bool
    ttl_drop_big: bool
    is_dynamic_dns: bool
    mx_misconfigured_provider: bool
    parking_points: int
    subdomain_points: int
    any_change_signal: bool
    any_threat_signal: bool


# ---------------------------------------------------------------------------
# Full canonical parsed record
# ---------------------------------------------------------------------------

@dataclass
class CanonicalDNSRecord:
    domain: str
    scanned_at: str

    # Infrastructure
    a_records: list[str]
    aaaa_records: list[str]
    mx_records: list[dict]
    ns_records: list[str]
    txt_records: list[str]
    soa_records: list[str]          # New: SOA extraction
    soa_ttl_min: int                # New: SOA TTL
    ns_ttl_min: int                 # New: NS TTL
    mail_a_records: list[str]       # New: mail subdomain resolution
    www_a_records: list[str]        # New: www subdomain resolution
    ip_int: int
    is_dual_stack: bool

    # DNS provider
    ns_primary: Optional[str]

    # Email auth — full picture
    email_auth: EmailAuthProfile

    # Certificates
    https_cert: Optional[CertProfile]
    smtp: SMTPProfile

    # Annotation (inline)
    annotation: InfrastructureAnnotation

    # Risk score (pre-computed inline)
    risk: ComputedRiskProfile

    # Change detection
    changes: ChangeSignals

    # Labels (pre-computed)
    label_dmarc_policy: Optional[str]
    label_spf_strictness: Optional[str]
    label_ttl_bucket: Optional[str]
    label_ssl_issuer: Optional[str]
    label_active_infrastructure: bool

    # Boolean threat flags
    is_phishing: bool
    is_malware: bool
    is_new_domain: bool
    has_security_txt: bool

    # Derived
    has_caa: bool
    caa_records: list[str]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class DatazagCanonicalAdapter:
    """
    Parses the full flat Datazag DNS record into a CanonicalDNSRecord.
    Handles all new fields: cert data, SMTP banner, MTA-STS,
    TLS-RPT, BIMI, change signals, labels, and inline risk score.
    """

    def __init__(self, raw: dict):
        self.r = raw
        self.records = raw.get("dns_profile", {}).get("records", {})
        self.dns_profile = raw.get("dns_profile", {})

    def parse(self) -> CanonicalDNSRecord:
        return CanonicalDNSRecord(
            domain=self.r["domain"],
            scanned_at=self.r.get("scanned_at_utc", ""),
            a_records=self._get_raw("A"),
            aaaa_records=self._get_raw("AAAA"),
            mx_records=self._parse_mx(),
            ns_records=self._get_raw("NS"),
            txt_records=self._get_raw("TXT"),
            soa_records=self._get_raw("SOA"),
            soa_ttl_min=self._get_ttl("SOA"),
            ns_ttl_min=self._get_ttl("NS"),
            mail_a_records=self._get_raw("MAIL_A"),
            www_a_records=self._get_raw("WWW_A"),
            ip_int=int(self.r.get("ip_int", 0)),
            is_dual_stack=bool(self._get_raw("AAAA")),
            ns_primary=self.r.get("ns"),
            email_auth=self._parse_email_auth(),
            https_cert=self._parse_https_cert(),
            smtp=self._parse_smtp(),
            annotation=self._parse_annotation(),
            risk=self._parse_risk(),
            changes=self._parse_changes(),
            label_dmarc_policy=self.r.get("label_dmarc_policy"),
            label_spf_strictness=self.r.get("label_spf_strictness"),
            label_ttl_bucket=self.r.get("label_ttl_bucket"),
            label_ssl_issuer=self.r.get("label_ssl_issuer"),
            label_active_infrastructure=bool(self.r.get("label_active_infrastructure")),
            is_phishing=bool(self.r.get("is_phishing")),
            is_malware=bool(self.r.get("is_malware")),
            is_new_domain=bool(self.r.get("is_new_domain")),
            has_security_txt=bool(self.r.get("has_security_txt")),
            has_caa=bool(self._get_raw("CAA")),
            caa_records=self._get_raw("CAA"),
        )

    # --- Record getters -----------------------------------------------------

    def _get_raw(self, rtype: str) -> list[str]:
        rec = self.records.get(rtype, {})
        if rec.get("status") in ("NODATA", "NXDOMAIN", "NOT_FOUND"):
            return []
        return rec.get("raw", [])

    def _get_ttl(self, rtype: str) -> int:
        rec = self.records.get(rtype, {})
        return int(rec.get("ttl", 0))

    def _parse_mx(self) -> list[dict]:
        results = []
        for entry in self._get_raw("MX"):
            parts = entry.split(":", 1)
            if len(parts) == 2:
                try:
                    results.append({
                        "priority": int(parts[0]),
                        "host": parts[1].strip().rstrip(".")
                    })
                except ValueError:
                    results.append({"priority": 99, "host": entry})
        return sorted(results, key=lambda x: x["priority"])

    # --- Email auth ---------------------------------------------------------

    def _parse_email_auth(self) -> EmailAuthProfile:
        import re

        spf_raw = self.r.get("spf_raw") or self.dns_profile.get("spf_auth", {}).get("raw")
        
        # Parse SPF
        includes, ip4s, all_mech = [], [], "none"
        if spf_raw:
            for token in spf_raw.split():
                t = token.lower()
                if t.startswith("include:"):  includes.append(token[8:])
                elif t.startswith("ip4:"):    ip4s.append(token[4:])
                elif t in ("-all","~all","+all","?all"): all_mech = t

        # Parse DMARC
        dmarc_raw_list = self.dns_profile.get("dmarc_auth", {}).get("raw", [])
        dmarc_str = dmarc_raw_list[0] if dmarc_raw_list else None
        # Also handle stringified list from flat fields
        if not dmarc_str:
            dmarc_flat = self.r.get("dmarc", "")
            try:
                parsed = ast.literal_eval(dmarc_flat) if isinstance(dmarc_flat, str) and dmarc_flat.startswith("[") else None
                if parsed:
                    dmarc_str = parsed[0]
            except Exception:
                pass

        dmarc_parts = {}
        if dmarc_str:
            for token in dmarc_str.split(";"):
                token = token.strip()
                if "=" in token:
                    k, v = token.split("=", 1)
                    dmarc_parts[k.strip().lower()] = v.strip()

        dmarc_policy = dmarc_parts.get("p")
        dmarc_pct    = int(dmarc_parts.get("pct", 100))

        # MTA-STS
        mta_sts  = self.dns_profile.get("mta_sts_auth", {})
        tls_rpt  = self.dns_profile.get("tls_rpt_auth", {})
        bimi     = self.dns_profile.get("bimi_auth", {})

        # Spoofing severity
        no_spf   = not spf_raw
        no_dmarc = not dmarc_policy
        dmarc_nxdomain = self.dns_profile.get("dmarc_auth", {}).get("status") == "NXDOMAIN"

        if no_spf and (no_dmarc or dmarc_nxdomain):
            spoofing_severity = "critical"
            is_spoofable = True
        elif no_spf or no_dmarc:
            spoofing_severity = "high"
            is_spoofable = True
        elif all_mech in ("+all", "?all"):
            spoofing_severity = "high"
            is_spoofable = True
        elif dmarc_policy == "none":
            spoofing_severity = "medium"
            is_spoofable = True
        else:
            spoofing_severity = "none"
            is_spoofable = False

        # Fully authenticated check
        is_fully_authenticated = (
            all_mech == "-all" and
            dmarc_policy == "reject" and
            dmarc_parts.get("aspf") == "s" and
            dmarc_parts.get("adkim") == "s" and
            dmarc_pct == 100
        )

        # What's missing
        missing = []
        if mta_sts.get("status") in ("NXDOMAIN", "NOT_FOUND"):
            missing.append("MTA-STS")
        if tls_rpt.get("status") in ("NXDOMAIN", "NOT_FOUND"):
            missing.append("TLS-RPT")
        if bimi.get("status") in ("NOT_FOUND", "NXDOMAIN"):
            missing.append("BIMI")
        if not self.r.get("has_security_txt"):
            missing.append("security.txt")
        if not self._get_raw("CAA"):
            missing.append("CAA")
        if dmarc_policy == "quarantine":
            missing.append("DMARC p=reject (currently quarantine)")

        spf_strictness = self.r.get("label_spf_strictness", "unknown")

        return EmailAuthProfile(
            spf_raw=spf_raw,
            spf_strictness=spf_strictness,
            spf_includes=includes,
            spf_ip4_ranges=ip4s,
            spf_all_mechanism=all_mech,
            dmarc_raw=dmarc_str,
            dmarc_policy=dmarc_policy,
            dmarc_pct=dmarc_pct,
            dmarc_aspf=dmarc_parts.get("aspf"),
            dmarc_adkim=dmarc_parts.get("adkim"),
            dmarc_rua=dmarc_parts.get("rua", "").lstrip("mailto:") or None,
            dmarc_ruf=dmarc_parts.get("ruf", "").lstrip("mailto:") or None,
            dmarc_fo=dmarc_parts.get("fo"),
            mta_sts_status=mta_sts.get("status", "UNKNOWN"),
            mta_sts_mode=self.r.get("mta_sts_mode") or None,
            tls_rpt_status=tls_rpt.get("status", "UNKNOWN"),
            tls_rpt_rua=self.r.get("tlsrpt_rua_present") or None,
            bimi_status=bimi.get("status", "NOT_FOUND"),
            bimi_raw=bimi.get("raw"),
            dnssec_enabled=bool(self.r.get("dnssec")) if self.r.get("dnssec") else None,
            is_fully_authenticated=is_fully_authenticated,
            is_spoofable=is_spoofable,
            spoofing_severity=spoofing_severity,
            missing_layers=missing,
        )

    # --- Certificate parsers ------------------------------------------------

    def _parse_cert(
        self,
        ok_key: str,
        days_key: str,
        issuer_key: str,
        san_key: Optional[str] = None,
        label_key: Optional[str] = None,
    ) -> Optional[CertProfile]:
        if not self.r.get(ok_key) and not self.r.get(days_key):
            return None
        issuer = self.r.get(issuer_key, "")
        days   = self.r.get(days_key)

        # Extract org name from issuer string
        # "countryName=US, organizationName=Let's Encrypt, commonName=E7"
        org = None
        for part in issuer.split(","):
            part = part.strip()
            if part.lower().startswith("organizationname="):
                org = part.split("=", 1)[1].strip()
                break

        return CertProfile(
            ok=bool(self.r.get(ok_key)),
            days_remaining=int(days) if days is not None else None,
            issuer=issuer,
            issuer_org=org,
            san_count=self.r.get(san_key) if san_key else None,
            label=self.r.get(label_key) if label_key else None,
            is_expiring_soon=int(days or 999) < 30,
            is_lets_encrypt="let's encrypt" in issuer.lower(),
            is_self_signed="self" in issuer.lower(),
        )

    def _parse_https_cert(self) -> Optional[CertProfile]:
        return self._parse_cert(
            "https_cert_ok", "https_cert_days_left",
            "https_cert_issuer", "https_cert_san_count", "label_ssl_issuer"
        )

    def _parse_smtp(self) -> SMTPProfile:
        cert = self._parse_cert(
            "smtp_cert_ok", "smtp_cert_days_left", "smtp_cert_issuer"
        )
        banner = self.r.get("mx_banner_raw", "")
        # Confirm provider identity from banner vs DNS annotation
        mx_name = self.r.get("mx_provider_name", "")
        provider_confirmed = bool(
            banner and mx_name and
            any(word.lower() in banner.lower() for word in mx_name.split())
        )
        return SMTPProfile(
            cert=cert,
            banner_raw=banner or None,
            banner_host=self.r.get("mx_banner_host") or None,
            banner_detail=self.r.get("mx_banner_details") or None,
            provider_confirmed=provider_confirmed,
            provider_name=self.r.get("mx_provider_name") or None,
        )

    # --- Annotation ---------------------------------------------------------

    def _parse_annotation(self) -> InfrastructureAnnotation:
        mx_trust    = float(self.r.get("mx_trust_nudge", 0))
        mx_risk     = float(self.r.get("mx_risk_bias", 0))
        prov_trust  = float(self.r.get("provider_trust_nudge", 0))
        ns_risk     = self.r.get("ns_risk_bias")

        return InfrastructureAnnotation(
            mx_provider_name=self.r.get("mx_provider_name"),
            mx_mbp_category=self.r.get("mx_mbp_category"),
            mx_risk_bias=mx_risk,
            mx_trust_nudge=mx_trust,
            ns_provider_name=self.r.get("ns_provider_name"),
            ns_provider_category=self.r.get("ns_provider_category"),
            ns_brand_hit=bool(self.r.get("ns_brand_hit")),
            ns_risk_bias=float(ns_risk) if ns_risk is not None else None,
            provider_trust_nudge=prov_trust,
            is_cdn_ugc=bool(self.r.get("is_cdn_ugc")),
            asn=int(self.r.get("asn", 0)),
            isp_name=self.r.get("isp_name"),
            isp_country=self.r.get("isp_country"),
            asn_risk_level=self.r.get("asn_risk_level", "unknown"),
            tld_country=self.r.get("tld_country"),
            tld_risk_level=self.r.get("tld_risk_level", "unknown"),
            net_trust_score=mx_trust + prov_trust + mx_risk,
        )

    # --- Risk score ---------------------------------------------------------

    def _parse_risk(self) -> ComputedRiskProfile:
        reasons_raw = self.r.get("reasons", "[]")
        try:
            reasons_list = (
                json.loads(reasons_raw)
                if isinstance(reasons_raw, str)
                else reasons_raw
            )
        except json.JSONDecodeError:
            try:
                reasons_list = ast.literal_eval(reasons_raw)
            except Exception:
                reasons_list = []

        reasons = [
            RiskScoreDetail(
                rule=item.get("rule", "unknown"),
                points=int(item.get("points", 0)),
                description=item.get("description"),
            )
            for item in reasons_list
        ]

        positive = [r for r in reasons if r.points > 0]
        negative = [r for r in reasons if r.points < 0]
        net_trust = sum(r.points for r in negative)

        return ComputedRiskProfile(
            score=int(self.r.get("risk_score", 0)),
            bucket=self.r.get("risk_bucket", "unknown"),
            reasons=reasons,
            profile=self.r.get("risk_profile", "default"),
            config_version=self.r.get("risk_config_version", ""),
            positive_contributions=positive,
            negative_contributions=negative,
            net_trust_rules=net_trust,
        )

    # --- Change signals -----------------------------------------------------

    def _parse_changes(self) -> ChangeSignals:
        return ChangeSignals(
            ns_changed=bool(self.r.get("ns_changed")),
            ip_changed=bool(self.r.get("ip_changed")),
            country_changed=bool(self.r.get("country_changed")),
            ttl_drop_big=bool(self.r.get("ttl_drop_big")),
            is_dynamic_dns=bool(self.r.get("is_dynamic_dns")),
            mx_misconfigured_provider=bool(self.r.get("mx_misconfigured_provider")),
            parking_points=int(self.r.get("parking_points", 0)),
            subdomain_points=int(self.r.get("subdomain_points", 0)),
            any_change_signal=any([
                self.r.get("ns_changed"),
                self.r.get("ip_changed"),
                self.r.get("country_changed"),
                self.r.get("ttl_drop_big"),
            ]),
            any_threat_signal=any([
                self.r.get("is_phishing"),
                self.r.get("is_malware"),
                self.r.get("is_dynamic_dns"),
                self.r.get("mx_misconfigured_provider"),
                int(self.r.get("parking_points", 0)) > 3,
            ]),
        )

    # --- Pipeline format ----------------------------------------------------

    def to_pipeline_format(self) -> dict:
        """
        Returns the dict shape expected by DNSRecordExtractor
        and SubdomainDiscoveryPipeline — unchanged from previous adapter.
        Now also passes cert and SMTP data through.
        """
        record = self.parse()
        dkim_selectors = []
        for txt in record.txt_records:
            txt_lower = txt.lower()
            if "google" in txt_lower:     dkim_selectors.append("google")
            if "outlook" in txt_lower or "ms=" in txt_lower:
                dkim_selectors.extend(["selector1", "selector2"])
            if "tmes" in txt_lower:       dkim_selectors.append("tmes")
            if "salesforce" in txt_lower: dkim_selectors.extend(["sfdc", "salesforce"])

        return {
            "MX":              record.mx_records,
            "NS":              record.ns_records,
            "TXT":             record.txt_records,
            "SRV":             {},
            "DKIM_SELECTORS":  list(set(dkim_selectors)),
            "MTA_STS":         f"mta-sts.{record.domain}",
            # Pass through enrichment data for report renderers
            "_annotation":     record.annotation,
            "_risk":           record.risk,
            "_https_cert":     record.https_cert,
            "_smtp":           record.smtp,
            "_email_auth":     record.email_auth,
            "_changes":        record.changes,
        }


def passive_security_findings_v2(
    record,
    subs: dict = None,
    rdap: dict = None,
    subdomains: list = None,
) -> list[dict]:
    """
    Generates a finding for every security layer — both present and missing.
    Missing layers are flagged with their security implication, not just noted.
    """
    findings = []
    ea  = record.email_auth
    ann = record.annotation
    c   = record.https_cert
    s   = record.smtp

    # -----------------------------------------------------------------------
    # SPF
    # -----------------------------------------------------------------------
    if not ea.spf_raw:
        findings.append({
            "finding":     "no_spf",
            "severity":    "critical",
            "title":       "No SPF record",
            "evidence":    "spf_auth status: NOT_FOUND",
            "detail":      (
                f"Any mail server in the world can send email claiming to be from "
                f"@{record.domain} and most receivers will accept it. This is the "
                f"baseline requirement for email authentication."
            ),
            "remediation": (
                f"Add TXT record at {record.domain}: "
                f"'v=spf1 include:<your-mail-provider> -all'. "
                f"If the domain sends no email use 'v=spf1 -all'."
            ),
        })
    elif ea.spf_all_mechanism in ("+all", "?all"):
        findings.append({
            "finding":     "spf_too_permissive",
            "severity":    "critical",
            "title":       f"SPF uses {ea.spf_all_mechanism} — anyone can send",
            "evidence":    ea.spf_raw,
            "detail":      (
                f"{ea.spf_all_mechanism} neutralises SPF entirely. Any server can send "
                f"as @{record.domain} and SPF will pass."
            ),
            "remediation": "Change to -all (hard fail). Use ~all only as a temporary testing measure.",
        })
    elif ea.spf_all_mechanism == "~all":
        findings.append({
            "finding":     "spf_soft_fail",
            "severity":    "medium",
            "title":       "SPF uses ~all (soft fail) — not hard fail",
            "evidence":    ea.spf_raw,
            "detail":      (
                "Soft fail marks unauthorised mail as suspicious but many receivers "
                "still deliver it. Hard fail (-all) provides stronger protection."
            ),
            "remediation": "Change ~all to -all once all legitimate senders are in the SPF record.",
        })

    if ea.spf_raw and ea.spf_lookup_count >= 8:
        findings.append({
            "finding":     "spf_lookup_limit",
            "severity":    "medium",
            "title":       f"SPF approaching 10-lookup limit ({ea.spf_lookup_count} lookups)",
            "evidence":    f"Includes: {', '.join(ea.spf_includes)}",
            "detail":      (
                "DNS resolvers stop processing SPF after 10 lookups. Legitimate mail "
                "may fail SPF if the limit is exceeded, causing delivery failures."
            ),
            "remediation": "Flatten SPF using a service like dmarcian or Valimail, or consolidate senders.",
        })

    # -----------------------------------------------------------------------
    # DMARC
    # -----------------------------------------------------------------------
    dmarc_status = getattr(record, '_dmarc_raw_status', None)
    if not ea.dmarc_policy:
        nxdomain = ea.dmarc_rua is None and ea.dmarc_ruf is None
        findings.append({
            "finding":     "no_dmarc",
            "severity":    "critical",
            "title":       "No DMARC record" + (" — _dmarc subdomain NXDOMAIN" if nxdomain else ""),
            "evidence":    f"_dmarc.{record.domain} returns {'NXDOMAIN' if nxdomain else 'no policy'}",
            "detail":      (
                f"Without DMARC, receivers have no policy for handling spoofed mail from "
                f"@{record.domain}. The domain owner also receives no reports about "
                f"spoofing attempts."
            ),
            "remediation": (
                f"Add TXT record at _dmarc.{record.domain}: "
                f"'v=DMARC1; p=quarantine; rua=mailto:dmarc@{record.domain}; pct=100'. "
                f"Start with p=quarantine, escalate to p=reject after monitoring reports."
            ),
        })
    elif ea.dmarc_policy == "none":
        findings.append({
            "finding":     "dmarc_policy_none",
            "severity":    "high",
            "title":       "DMARC policy is p=none — monitoring only, no enforcement",
            "evidence":    ea.dmarc_raw,
            "detail":      (
                "p=none instructs receivers to take no action on unauthenticated mail. "
                "It provides reporting visibility but zero spoofing protection."
            ),
            "remediation": "Escalate to p=quarantine once reports confirm all legitimate senders are authenticated.",
        })
    elif ea.dmarc_policy == "quarantine":
        findings.append({
            "finding":     "dmarc_quarantine_strict_alignment",
            "severity":    "medium",
            "title":       "DMARC p=quarantine — one step from full enforcement",
            "evidence":    ea.dmarc_raw,
            "detail":      (
                "Spoofed mail is sent to spam rather than rejected outright. "
                + (f"aspf={ea.dmarc_aspf} and adkim={ea.dmarc_adkim} alignment already set. "
                   if ea.dmarc_aspf and ea.dmarc_adkim else "")
                + "Escalating to p=reject is the final step."
            ),
            "remediation": "Change p=quarantine to p=reject. Monitor rua reports for 2-4 weeks first if unsure.",
        })

    if ea.dmarc_policy and not ea.dmarc_rua:
        findings.append({
            "finding":     "dmarc_no_reporting",
            "severity":    "medium",
            "title":       "DMARC configured but no reporting address (rua)",
            "evidence":    ea.dmarc_raw,
            "detail":      (
                "Without rua=, the domain owner receives no aggregate reports about "
                "who is sending mail on their behalf. Reporting is essential for "
                "identifying legitimate senders before escalating policy."
            ),
            "remediation": f"Add rua=mailto:dmarc@{record.domain} to the DMARC record.",
        })

    if ea.dmarc_policy and ea.dmarc_pct and ea.dmarc_pct < 100:
        findings.append({
            "finding":     "dmarc_partial_enforcement",
            "severity":    "medium",
            "title":       f"DMARC pct={ea.dmarc_pct} — partial enforcement only",
            "evidence":    ea.dmarc_raw,
            "detail":      (
                f"Only {ea.dmarc_pct}% of unauthenticated mail is subject to the DMARC policy. "
                f"The remaining {100 - ea.dmarc_pct}% is delivered regardless."
            ),
            "remediation": "Increase pct=100 once you are confident all legitimate senders pass authentication.",
        })

    # -----------------------------------------------------------------------
    # MTA-STS
    # -----------------------------------------------------------------------
    if ea.mta_sts_status in ("NXDOMAIN", "NOT_FOUND", "NODATA"):
        findings.append({
            "finding":     "no_mta_sts",
            "severity":    "medium",
            "title":       "No MTA-STS policy",
            "evidence":    f"_mta-sts.{record.domain} returns {ea.mta_sts_status}",
            "detail":      (
                "MTA-STS (RFC 8461) prevents SMTP downgrade attacks by publishing a policy "
                "that instructs sending mail servers to require TLS. Without it, an attacker "
                "with network access can intercept email by stripping TLS from the connection."
            ),
            "remediation": (
                f"1. Create DNS TXT record: _mta-sts.{record.domain} → 'v=STSv1; id=<timestamp>'\n"
                f"2. Serve policy at https://mta-sts.{record.domain}/.well-known/mta-sts.txt\n"
                f"   Content: version: STSv1 / mode: enforce / mx: {record.mx_records[0]['host'] if record.mx_records else '<your-mx>'} / max_age: 86400"
            ),
        })
    elif ea.mta_sts_mode and ea.mta_sts_mode != "enforce":
        findings.append({
            "finding":     "mta_sts_not_enforcing",
            "severity":    "medium",
            "title":       f"MTA-STS present but mode={ea.mta_sts_mode} — not enforcing",
            "evidence":    f"mta_sts_mode: {ea.mta_sts_mode}",
            "detail":      "MTA-STS is configured but not in enforce mode — TLS is not required.",
            "remediation": "Change MTA-STS policy mode from testing to enforce.",
        })

    # -----------------------------------------------------------------------
    # TLS-RPT
    # -----------------------------------------------------------------------
    if ea.tls_rpt_status in ("NXDOMAIN", "NOT_FOUND", "NODATA"):
        findings.append({
            "finding":     "no_tls_rpt",
            "severity":    "info",
            "title":       "No TLS-RPT reporting configured",
            "evidence":    f"_smtp._tls.{record.domain} returns {ea.tls_rpt_status}",
            "detail":      (
                "TLS-RPT (RFC 8460) provides reports on SMTP TLS connection failures. "
                "Without it there is no visibility into delivery failures, "
                "certificate errors, or MTA-STS policy violations."
            ),
            "remediation": (
                f"Add TXT record at _smtp._tls.{record.domain}: "
                f"'v=TLSRPTv1; rua=mailto:tls-rpt@{record.domain}'"
            ),
        })

    # -----------------------------------------------------------------------
    # BIMI
    # -----------------------------------------------------------------------
    if ea.bimi_status in ("NOT_FOUND", "NXDOMAIN", "NODATA"):
        findings.append({
            "finding":     "no_bimi",
            "severity":    "info",
            "title":       "No BIMI record — brand logo not displayed in email",
            "evidence":    f"default._bimi.{record.domain} not found",
            "detail":      (
                "BIMI (Brand Indicators for Message Identification) displays your brand logo "
                "in Gmail, Apple Mail, and Yahoo Mail for authenticated email. "
                "It requires DMARC p=reject as a prerequisite."
                + (" DMARC p=reject is not yet in place — fix that first." 
                   if ea.dmarc_policy != "reject" else "")
            ),
            "remediation": (
                "Prerequisites: DMARC p=reject + a verified SVG logo. "
                f"Then add TXT record: default._bimi.{record.domain} → "
                "'v=BIMI1; l=https://yourdomain.com/logo.svg'"
            ),
        })

    # -----------------------------------------------------------------------
    # DNSSEC
    # -----------------------------------------------------------------------
    if not ea.dnssec_enabled:
        findings.append({
            "finding":     "no_dnssec",
            "severity":    "info",
            "title":       "DNSSEC not enabled",
            "evidence":    "dnssec field empty or false",
            "detail":      (
                "DNSSEC cryptographically signs DNS responses, preventing cache poisoning "
                "and DNS spoofing attacks. Without it, an attacker could redirect traffic "
                "by poisoning DNS caches."
            ),
            "remediation": "Enable DNSSEC through your DNS provider or registrar. Both must support it.",
        })

    # -----------------------------------------------------------------------
    # DNSSEC inconsistency (registrar vs DNS scan)
    # -----------------------------------------------------------------------   
    rdap = rdap or {}
    if rdap.get("dnssec_enabled") and not ea.dnssec_enabled:
        findings.append({
            "finding":     "dnssec_inconsistent",
            "severity":    "medium",
            "title":       "DNSSEC status inconsistent — registrar says enabled but DNS scan shows otherwise",
            "evidence":    "rdap.dnssec_enabled=True but dnssec field empty in DNS scan",
            "detail":      (
                "The registrar RDAP record reports DNSSEC as enabled but the DNS scan "
                "could not confirm active DNSSEC signatures. This may indicate an incomplete "
                "DNSSEC configuration — the DS record may be published at the registrar "
                "but DNSKEY records are not being served by the authoritative nameservers."
            ),
            "remediation": (
                "Verify DNSSEC is fully configured end-to-end: check that both DS records "
                "are published at the registrar and DNSKEY records are being served by "
                "your authoritative nameservers. Use dnssec-debugger.verisignlabs.com to validate."
            ),
        })

    # -----------------------------------------------------------------------
    # CAA records
    # -----------------------------------------------------------------------
    if not record.has_caa:
        findings.append({
            "finding":     "no_caa",
            "severity":    "medium",
            "title":       "No CAA records — any CA can issue certificates",
            "evidence":    f"CAA query returns NODATA",
            "detail":      (
                f"Certificate Authority Authorisation records restrict which CAs can issue "
                f"TLS certificates for {record.domain}. Without CAA records, any of the "
                f"hundreds of publicly-trusted CAs could issue a certificate, increasing "
                f"the risk of mis-issuance or fraudulent certificates."
                + (f" Currently using {record.https_cert.issuer_org if record.https_cert else 'unknown CA'} for HTTPS"
                   + (f" and {record.smtp.cert.issuer_org if record.smtp.cert else ''} for SMTP." 
                      if record.smtp.cert else ".")
                   if record.https_cert else "")
            ),
            "remediation": (
                f"Add CAA records for each CA you use. "
                f"Example: '0 issue \"{record.https_cert.issuer_org.lower().replace(' ','')+'.com' if record.https_cert and record.https_cert.issuer_org else 'letsencrypt.org'}\"'. "
                f"Check crt.sh to identify all CAs that have issued certificates for this domain."
            ),
        })

    # -----------------------------------------------------------------------
    # Security.txt
    # -----------------------------------------------------------------------
    if not record.has_security_txt:
        findings.append({
            "finding":     "no_security_txt",
            "severity":    "info",
            "title":       "No security.txt — no responsible disclosure policy",
            "evidence":    "has_security_txt: false",
            "detail":      (
                "security.txt (RFC 9116) provides a standardised way for security "
                "researchers to report vulnerabilities. Without it, researchers "
                "have no formal channel and may disclose publicly."
            ),
            "remediation": (
                f"Publish at https://{record.domain}/.well-known/security.txt "
                f"with Contact, Expires, and Preferred-Languages fields."
            ),
        })

    # -----------------------------------------------------------------------
    # Certificate findings
    # -----------------------------------------------------------------------
    if c:
        if c.days_remaining is not None:
            if c.days_remaining <= 14:
                findings.append({
                    "finding":     "cert_expiring_soon",
                    "severity":    "critical",
                    "title":       f"HTTPS certificate expires in {c.days_remaining} days — URGENT",
                    "evidence":    f"Issuer: {c.issuer_org}, days_remaining: {c.days_remaining}",
                    "detail":      (
                        f"Certificate from {c.issuer_org} expires in {c.days_remaining} days. "
                        f"After expiry, browsers will show a security warning to all visitors "
                        f"and HTTPS connections will fail. Renewal is overdue."
                    ),
                    "remediation": "Renew immediately — auto-renewal has likely failed. Check certbot/ACME client logs.",
                })
            elif c.days_remaining <= 30:
                findings.append({
                    "finding":     "cert_expiring_soon",
                    "severity":    "high",
                    "title":       f"HTTPS certificate expires in {c.days_remaining} days",
                    "evidence":    f"Issuer: {c.issuer_org}, days_remaining: {c.days_remaining}",
                    "detail":      (
                        f"Certificate from {c.issuer_org} expires in {c.days_remaining} days. "
                        f"After expiry, browsers will show a security warning to all visitors."
                    ),
                    "remediation": "Trigger certificate renewal immediately. Check auto-renewal is configured.",
                })
            elif c.days_remaining <= 60:
                findings.append({
                    "finding":     "cert_expiring_warning",
                    "severity":    "medium",
                    "title":       f"HTTPS certificate expires in {c.days_remaining} days — renewal due soon",
                    "evidence":    f"Issuer: {c.issuer_org}, days_remaining: {c.days_remaining}",
                    "detail":      (
                        f"Certificate from {c.issuer_org} expires in {c.days_remaining} days. "
                        f"Let's Encrypt auto-renews at 30 days — verify auto-renewal is configured "
                        f"and working before this window closes."
                    ),
                    "remediation": "Verify auto-renewal configuration. Run a dry-run renewal to confirm: certbot renew --dry-run",
                })

    # -----------------------------------------------------------------------
    # SMTP banner verification
    # -----------------------------------------------------------------------
    if s.provider_confirmed:
        findings.append({
            "finding":     "mx_provider_banner_confirmed",
            "severity":    "info",
            "title":       f"MX provider confirmed live via SMTP banner",
            "evidence":    s.banner_raw,
            "detail":      (
                f"{s.provider_name} gateway is live and responding. "
                f"Provider identity confirmed from banner — not just DNS assertion."
            ),
            "remediation": None,
        })

    # -----------------------------------------------------------------------
    # ASN / network risk from rule engine
    # -----------------------------------------------------------------------
    for reason in record.risk.positive_contributions:
        if "network_risk" in reason.rule or "asn" in reason.rule.lower():
            findings.append({
                "finding":     reason.rule,
                "severity":    "high" if reason.points >= 8 else "medium",
                "title":       f"Network risk penalty: {reason.rule} (+{reason.points} points)",
                "evidence":    f"ASN: {ann.asn} ({ann.isp_name}) — risk level: {ann.asn_risk_level}",
                "detail":      (
                    f"The hosting ASN AS{ann.asn} ({ann.isp_name}) contributed "
                    f"+{reason.points} points to the risk score. "
                    f"ASN risk level: {ann.asn_risk_level}. "
                    f"This is common for shared CDN infrastructure (Cloudflare, Fastly) "
                    f"which hosts both legitimate and malicious content."
                ),
                "remediation": (
                    "Verify this is expected infrastructure. For CDN-hosted sites "
                    "this is a known false-positive — the penalty reflects shared "
                    "infrastructure risk, not a direct threat signal."
                ),
            })
        elif "ttl" in reason.rule.lower():
            findings.append({
                "finding":     reason.rule,
                "severity":    "medium" if reason.points >= 5 else "info",
                "title":       f"Short TTL penalty: {reason.rule} (+{reason.points} points)",
                "evidence":    f"label_ttl_bucket: {record.label_ttl_bucket}, a_ttl: {getattr(record, 'a_ttl', '?')}",
                "detail":      (
                    f"DNS TTL is classified as '{record.label_ttl_bucket}'. "
                    f"Short TTLs are a characteristic of fast-flux infrastructure "
                    f"and contributed +{reason.points} to the risk score. "
                    f"Legitimate reasons include CDN failover requirements."
                ),
                "remediation": (
                    "If infrastructure is stable, increase A record TTL to 3600+ seconds "
                    "to reduce the fast-flux penalty and improve DNS caching efficiency."
                ),
            })

    # -----------------------------------------------------------------------
    # IPv6
    # -----------------------------------------------------------------------
    if not record.is_dual_stack:
        findings.append({
            "finding":     "no_ipv6",
            "severity":    "info",
            "title":       "No IPv6 — single-stack IPv4 only",
            "evidence":    "AAAA record status: NODATA",
            "detail":      (
                "The domain has no AAAA records. IPv6 is increasingly expected "
                "for modern infrastructure. Single-stack IPv4 may indicate legacy "
                "hosting or origin infrastructure."
            ),
            "remediation": "Enable IPv6 at your hosting provider or CDN if supported.",
        })


    # -----------------------------------------------------------------------
    # Per-subdomain findings — from enriched subdomain resolution
    # -----------------------------------------------------------------------
    for sub in (subdomains or []):
        fqdn = sub.get("dns_name", "")
        if not fqdn:
            continue

        # Malicious IP
        if sub.get("is_malicious_ip"):
            feeds = sub.get("ip_malicious_feeds", [])
            ips   = sub.get("a_records", [])
            findings.append({
                "finding":     "subdomain_malicious_ip",
                "severity":    "critical",
                "title":       f"{fqdn} resolves to known malicious IP",
                "evidence":    (
                    f"IP: {ips[0] if ips else '?'}, "
                    f"Feeds: {', '.join(feeds) if feeds else 'blocklist'}"
                ),
                "detail":      (
                    f"{fqdn} resolves to an IP currently listed on "
                    f"{len(feeds) or 'active'} threat feed(s). "
                    f"May indicate compromised subdomain, DNS hijacking, "
                    f"or migration to malicious infrastructure."
                ),
                "remediation": (
                    "Verify this DNS record is authorised. If unexpected, "
                    "treat as active compromise — check for DNS hijacking "
                    "and rotate credentials immediately."
                ),
            })

        # CNAME takeover
        if sub.get("is_takeover_vulnerable") and sub.get("is_dangling_cname"):
            platform = sub.get("takeover_provider", "unknown platform")
            cname    = sub.get("cname", "?")
            findings.append({
                "finding":     f"subdomain_takeover_{fqdn.replace('.','_')}",
                "severity":    "critical",
                "title":       f"Subdomain takeover risk: {fqdn} → {platform}",
                "evidence":    f"CNAME: {cname} → target does not resolve",
                "detail":      (
                    f"{fqdn} has a dangling CNAME pointing to {platform}. "
                    f"The CNAME target no longer resolves — an attacker could "
                    f"register the {platform} resource and serve content under "
                    f"{fqdn}, receiving cookies, sessions, and traffic "
                    f"intended for this organisation."
                ),
                "remediation": (
                    f"Remove the CNAME for {fqdn} immediately, "
                    f"or reclaim the {platform} resource it points to."
                ),
            })
        elif sub.get("is_dangling_cname") and not sub.get("is_takeover_vulnerable"):
            findings.append({
                "finding":     f"subdomain_dangling_cname_{fqdn.replace('.','_')}",
                "severity":    "medium",
                "title":       f"Dangling CNAME: {fqdn}",
                "evidence":    f"CNAME: {sub.get('cname','?')} → does not resolve",
                "detail":      (
                    f"{fqdn} has a CNAME pointing to a host that does not resolve. "
                    f"The subdomain is unreachable and the stale record should be removed."
                ),
                "remediation": f"Remove or update the CNAME record for {fqdn}.",
            })

        # RFC1918 internal IP in public DNS
        if sub.get("internal_ips"):
            findings.append({
                "finding":     f"subdomain_internal_ip_{fqdn.replace('.','_')}",
                "severity":    "medium",
                "title":       f"Internal IP exposed in public DNS: {fqdn}",
                "evidence":    f"A record: {sub['internal_ips'][0]}",
                "detail":      (
                    f"{fqdn} resolves to RFC1918 private address {sub['internal_ips'][0]}. "
                    f"This reveals internal network topology and the subdomain "
                    f"is unreachable from the internet — likely a misconfiguration."
                ),
                "remediation": (
                    "Remove or correct this DNS record. "
                    "Internal hostnames should not appear in public DNS."
                ),
            })

        # MX PTR mismatch — from subdomain_summary
        for mx_ptr in (subs or {}).get("mx_ptr_results", []):
            if not mx_ptr.get("ptr_valid"):
                findings.append({
                    "finding":     "mx_ptr_mismatch",
                    "severity":    "medium",
                    "title":       f"MX PTR mismatch: {mx_ptr['mx_host']}",
                    "evidence":    (
                        f"MX IP: {mx_ptr['mx_ip']}, "
                        f"PTR: {', '.join(mx_ptr['ptr_records']) or 'absent'}"
                    ),
                    "detail":      (
                        f"The PTR record for MX server {mx_ptr['mx_host']} "
                        f"({mx_ptr['mx_ip']}) does not match the forward hostname. "
                        f"Many receiving mail servers reject or flag email from IPs "
                        f"with mismatched PTR records — affecting deliverability "
                        f"and spam filter trust scores."
                    ),
                    "remediation": (
                        "Ask your mail provider to configure a matching PTR record "
                        "for this IP, or contact your hosting provider."
                    ),
                })
            break  # one finding covers all MX PTR mismatches
        
    # -----------------------------------------------------------------------
    # Subdomain HTTP security headers (requires subs data from output dict)
    # -----------------------------------------------------------------------
    if subs and subs.get("no_https_pct", 0) > 50:
        findings.append({
            "finding":     "hsts_absent_majority",
            "severity":    "high",
            "title":       f"HSTS absent on {subs['no_https_pct']}% of live subdomains",
            "evidence":    f"{subs.get('no_hsts_count', '?')} of {subs.get('total', '?')} subdomains missing HSTS header",
            "detail":      (
                "HTTP Strict Transport Security is absent on the majority of subdomains. "
                "Without HSTS, browsers will accept HTTP connections, enabling SSL stripping "
                "attacks where an attacker downgrades HTTPS to HTTP and intercepts credentials."
            ),
            "remediation": (
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                "to all web server responses. For nginx: add_header Strict-Transport-Security "
                "'max-age=31536000; includeSubDomains' always; "
                "For Apache: Header always set Strict-Transport-Security "
                "'max-age=31536000; includeSubDomains'"
            ),
        })

    if subs and subs.get("no_csp_pct", 0) > 50:
        findings.append({
            "finding":     "csp_absent_majority",
            "severity":    "high",
            "title":       f"Content Security Policy absent on {subs['no_csp_pct']}% of subdomains",
            "evidence":    f"{subs.get('no_csp_count', '?')} of {subs.get('total', '?')} subdomains missing CSP header",
            "detail":      (
                "Content Security Policy is absent on the majority of subdomains. "
                "Without CSP, cross-site scripting attacks can execute arbitrary JavaScript "
                "in users' browsers, enabling credential theft and data exfiltration."
            ),
            "remediation": (
                "Add a Content-Security-Policy header to all web server responses. "
                "Start with 'Content-Security-Policy: default-src \\'self\\'' and "
                "expand the policy to cover legitimate third-party sources."
            ),
        })

    if subs and subs.get("version_disclosed_count", 0) > 0:
        findings.append({
            "finding":     "server_version_disclosed",
            "severity":    "medium",
            "title":       f"Server version disclosed on {subs['version_disclosed_count']} subdomains",
            "evidence":    f"Server header reveals version on {subs['version_disclosed_count']} subdomains",
            "detail":      (
                "Web server version strings are exposed in HTTP response headers across "
                "multiple subdomains. This provides attackers with specific targeting "
                "information for exploit development against known CVEs."
            ),
            "remediation": (
                "Configure web servers to suppress version disclosure. "
                "For nginx: server_tokens off; "
                "For Apache: ServerTokens Prod and ServerSignature Off; "
                "For LiteSpeed: set Response Header to 'No Version'."
            ),
        })

    # -----------------------------------------------------------------------
    # DNS Infrastructure & Redundancy
    # -----------------------------------------------------------------------
    if len(record.ns_records) == 1:
        findings.append({
            "finding":     "single_ns_record",
            "severity":    "high",
            "title":       "No DNS redundancy — single nameserver configured",
            "evidence":    f"NS: {record.ns_records[0]}",
            "detail":      (
                "This domain is served by only a single nameserver. This represents "
                "a critical single point of failure. If the nameserver goes offline or "
                "is targeted by DDoS, the entire domain will become unresolvable."
            ),
            "remediation": "Configure at least two geographically dispersed nameservers.",
        })

    if ann.ns_risk_bias and ann.ns_risk_bias > 2.0:
        findings.append({
            "finding":     "ns_bad_neighborhood",
            "severity":    "high",
            "title":       "Nameservers hosted in high-risk infrastructure",
            "evidence":    f"Provider: {ann.ns_provider_name or 'Unknown'} (Risk Bias: {ann.ns_risk_bias})",
            "detail":      (
                "The authoritative nameservers for this domain are located on an ASN or provider "
                "associated with bulletproof hosting or significant malicious activity. "
                "This severely damages the domain's trust score."
            ),
            "remediation": "Migrate DNS hosting to a reputable enterprise provider (e.g., Cloudflare, Route53).",
        })

    if record.soa_ttl_min and record.soa_ttl_min > 0 and record.soa_ttl_min < 3300:
        findings.append({
            "finding":     "anomalous_soa_ttl",
            "severity":    "high",
            "title":       f"Anomalous SOA TTL — extremely rapid zone rotation ({record.soa_ttl_min}s)",
            "evidence":    f"SOA TTL: {record.soa_ttl_min} seconds",
            "detail":      (
                "The Start of Authority (SOA) record has a TTL under 55 minutes. While sometimes "
                "used briefly during migrations, sustained low SOA TTLs are heavily associated "
                "with fast-flux networks, dynamic DNS, and DGA malware evasion tactics."
            ),
            "remediation": "Increase the SOA TTL to standard enterprise levels (e.g., 3600 or 86400) unless actively migrating.",
        })

    # -----------------------------------------------------------------------
    # Spoofing summary finding
    # -----------------------------------------------------------------------
    if ea.is_spoofable:
        findings.append({
            "finding":     "domain_spoofable",
            "severity":    ea.spoofing_severity,
            "title":       f"Domain is spoofable — {ea.spoofing_severity} severity",
            "evidence":    (
                f"SPF: {ea.spf_all_mechanism or 'missing'}, "
                f"DMARC: {ea.dmarc_policy or 'missing'}"
            ),
            "detail":      (
                f"The combination of current SPF and DMARC configuration means "
                f"@{record.domain} addresses can be impersonated. "
                f"An attacker can send phishing or BEC email appearing to come from "
                f"this domain with no access to its infrastructure."
            ),
            "remediation": ea.missing_layers[0] if ea.missing_layers else "Review email authentication configuration.",
        })

    # Deduplicate — keep the first occurrence of each finding key,
# preferring ones with actual evidence over n/a
        seen = {}
        for f in findings:
            key = f.get("finding", "")
            if key not in seen:
                seen[key] = f
            else:
                # Replace with this one if it has better evidence
                existing = seen[key]
                if (not existing.get("evidence") or existing.get("evidence") == "n/a") \
                        and f.get("evidence") and f.get("evidence") != "n/a":
                    seen[key] = f

        return [f for f in seen.values() if f.get("finding")]