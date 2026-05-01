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
from fingerprints import TXT_FINGERPRINTS, ADDITIONAL_TXT_FINGERPRINTS, TXT_ANOMALY_PATTERNS

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
    spf_lookup_count: int

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
    is_hosting_cdn: bool 

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

    # Expanded profiles (newly added)
    subdomains: list[dict] = field(default_factory=list)
    cert_analysis: dict = field(default_factory=dict)
    rdap: dict = field(default_factory=dict)
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
            subdomains=self.r.get("subdomains", []),
            cert_analysis=self.r.get("cert_analysis", {}),
            
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
            rdap=self.r.get("rdap") or {},
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
        spf_raw = self.r.get("spf_raw") or self.dns_profile.get("spf_auth", {}).get("raw")
        
        # Count SPF DNS lookups
        lookup_count = 0
        if spf_raw:
            for token in spf_raw.split():
                t = token.lower()
                if t.startswith(("include:", "a:", "mx:", "exists:", "redirect=")):
                    lookup_count += 1

        # Parse SPF
        includes, ip4s, all_mech = [], [], "none"
        if spf_raw:
            for token in spf_raw.split():
                t = token.lower()
                if t.startswith("include:"):  includes.append(token[8:])
                elif t.startswith("ip4:"):    ip4s.append(token[4:])
                elif t in ("-all","~all","+all","?all"): all_mech = t

        # Parse DMARC
        dmarc_auth_section = self.dns_profile.get("dmarc_auth", {})
        dmarc_raw_list = dmarc_auth_section.get("raw", [])
        dmarc_str = dmarc_raw_list[0] if dmarc_raw_list else None
        # Flat-field fallback only for old-format files that pre-date dmarc_auth section.
        # If dmarc_auth is present (even empty), the lookup ran — never override with stale data.
        if not dmarc_str and "dmarc_auth" not in self.dns_profile:
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
        dmarc_pct    = int(dmarc_parts.get("pct", 100)) if dmarc_policy else None

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
            spf_lookup_count=lookup_count,
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
            is_hosting_cdn=bool(self.r.get("is_hosting_cdn")),
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