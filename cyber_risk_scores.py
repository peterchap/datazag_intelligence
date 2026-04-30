"""
cyber_risk_scores.py
--------------------
Six-dimension cyber risk scoring for insurance underwriting.
Derives independently interpretable risk scores from Datazag's
DNS intelligence data — no additional data collection required.

Dimensions:
    1. BEC (Business Email Compromise)     — 35% weight
    2. Ransomware exposure                 — 25% weight
    3. Data breach exposure                — 20% weight
    4. Supply chain risk                   — 10% weight
    5. Phishing platform risk              —  5% weight
    6. Infrastructure maturity (offset)    —  5% weight (reduces composite)

Floor overrides (bypass weighted model for binary critical findings):
    subdomain_takeover                     → floor 65
    cert_missed_renewal                    → floor 40

Usage:
    from cyber_risk_scores import CyberRiskScorer

    scorer  = CyberRiskScorer()
    profile = scorer.score(output, partner_context="Atlassian Platinum Partner")

    print(profile.underwriting_score)   # 0-100
    print(profile.premium_signal)       # "standard" | "loading" | "heavy_loading" | "decline"
    print(profile.bec.narrative)        # human-readable explanation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Known high-risk SaaS — confirmed material breach history
# ---------------------------------------------------------------------------

HIGH_RISK_SAAS = {
    "lastpass":  "LastPass — 2022 vault exfiltration breach",
    "okta":      "Okta — 2023 support system breach",
    "twilio":    "Twilio — 2022 employee phishing breach",
    "mailchimp": "Mailchimp — 2023 social engineering breach",
    "circleci":  "CircleCI — 2023 secrets exposure breach",
    "dropbox":   "Dropbox Sign — 2024 data breach",
}

# MX providers with confirmed enterprise email security capabilities
MX_SECURITY_GATEWAYS = {
    "proofpoint", "mimecast", "trend micro", "barracuda",
    "sophos", "fortimail", "cisco ironport", "microsoft defender",
    "google workspace", "abnormal", "agari", "fortinet",
}

# Subdomain keywords that indicate customer/employee-facing auth systems
AUTH_SUBDOMAIN_KEYWORDS = {
    "portal", "login", "auth", "sso", "signin", "account",
    "secure", "access", "id", "identity", "vpn", "remote",
}


# ---------------------------------------------------------------------------
# Subdomain risk summary — parsed once, shared across dimension scorers
# ---------------------------------------------------------------------------

@dataclass
class SubdomainRiskSummary:
    """Parsed subdomain intelligence — built once in score() and passed around."""
    total:                  int
    takeover_vulnerable:    list[dict]   # subdomains with is_takeover_vulnerable=True
    high_risk:              list[dict]   # subdomains with risk_level="high"
    auth_surface_takeovers: list[dict]   # takeovers on auth-keyword subdomains
    has_takeover:           bool
    has_auth_takeover:      bool         # portal/login/sso subdomain taken over
    takeover_providers:     list[str]    # e.g. ["Azure Cloud"]

    @classmethod
    def from_raw(cls, subdomains: list[dict]) -> "SubdomainRiskSummary":
        takeovers  = [s for s in subdomains if s.get("is_takeover_vulnerable")]
        high_risk  = [s for s in subdomains if s.get("risk_level") == "high"]
        auth_tko   = [
            s for s in takeovers
            if any(kw in s.get("dns_name", "").lower() for kw in AUTH_SUBDOMAIN_KEYWORDS)
        ]
        providers  = list({s.get("takeover_provider") for s in takeovers if s.get("takeover_provider")})
        return cls(
            total=len(subdomains),
            takeover_vulnerable=takeovers,
            high_risk=high_risk,
            auth_surface_takeovers=auth_tko,
            has_takeover=bool(takeovers),
            has_auth_takeover=bool(auth_tko),
            takeover_providers=providers,
        )


# ---------------------------------------------------------------------------
# Score dataclasses — one per dimension
# ---------------------------------------------------------------------------

@dataclass
class BECRiskScore:
    score: int
    band: str
    spoofing_possible: bool
    dmarc_enforcing: bool
    spf_hard_fail: bool
    strict_alignment: bool
    mx_security_gateway: bool
    mta_sts_enforcing: bool
    has_reporting: bool
    key_gaps: list[str]
    narrative: str


@dataclass
class RansomwareExposureScore:
    score: int
    band: str
    short_ttl_flag: bool
    dynamic_dns: bool
    new_domain: bool
    infrastructure_change_signals: bool
    cdn_ugc: bool
    high_asn_risk: bool
    key_gaps: list[str]
    narrative: str


@dataclass
class DataBreachExposureScore:
    score: int
    band: str
    credential_risk_saas: list[str]
    no_dnssec: bool
    no_mta_sts: bool
    spoofable: bool
    subdomain_takeover: bool
    auth_surface_takeover: bool
    key_gaps: list[str]
    narrative: str


@dataclass
class SupplyChainRiskScore:
    score: int
    band: str
    saas_count: int
    high_risk_saas_count: int
    ai_infrastructure: bool
    payment_processor_count: int
    identity_provider_count: int
    email_marketing_count: int
    key_gaps: list[str]
    narrative: str


@dataclass
class PhishingPlatformScore:
    score: int
    band: str
    spoofable: bool
    no_caa: bool
    shared_hosting: bool
    high_asn_abuse: bool
    no_security_txt: bool
    subdomain_takeover: bool
    auth_surface_takeover: bool
    key_gaps: list[str]
    narrative: str


@dataclass
class InfrastructureMaturityScore:
    score: int
    band: str
    dual_stack_ipv6: bool
    has_caa: bool
    has_dnssec: bool
    has_mta_sts: bool
    has_tls_rpt: bool
    has_bimi: bool
    has_security_txt: bool
    cert_health: bool
    smtp_banner_confirmed: bool
    dmarc_reporting: bool
    hsts_coverage: float          # 0.0–1.0 fraction of subdomains with HSTS
    csp_coverage: float           # 0.0–1.0 fraction of subdomains with CSP
    maturity_level: str
    narrative: str


@dataclass
class CyberRiskProfile:
    domain: str
    bec:               BECRiskScore
    ransomware:        RansomwareExposureScore
    data_breach:       DataBreachExposureScore
    supply_chain:      SupplyChainRiskScore
    phishing_platform: PhishingPlatformScore
    maturity:          InfrastructureMaturityScore
    subdomains:        SubdomainRiskSummary

    # Composite underwriting output
    underwriting_score:    int
    underwriting_band:     str
    premium_signal:        str
    primary_claim_vector:  str
    floor_override:        Optional[str]   # None or name of finding that set the floor
    score_breakdown:       dict


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class CyberRiskScorer:
    """
    Derives a six-dimension cyber risk profile from Datazag output dict.

    Weights reflect relative insurance claim frequency and severity:
        BEC              35%  — highest frequency
        Ransomware       25%  — highest severity
        Data breach      20%
        Supply chain     10%
        Phishing platform 5%
        Maturity offset  -5%  — good maturity reduces composite

    Floor overrides ensure the weighted model cannot under-score binary
    critical findings that are immediately exploitable regardless of
    overall posture quality.
    """

    WEIGHTS = {
        "bec":               0.35,
        "ransomware":        0.25,
        "data_breach":       0.20,
        "supply_chain":      0.10,
        "phishing_platform": 0.05,
        "maturity_offset":   0.05,
    }

    # Binary critical findings → minimum composite score
    FLOOR_OVERRIDES: list[tuple[str, int]] = [
        ("auth_subdomain_takeover",  75),   # portal/login/sso taken over → heavy loading
        ("subdomain_takeover",       65),   # any subdomain takeover → loading
        ("cert_missed_renewal",      40),   # missed auto-renewal → loading
    ]

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def score(
        self,
        output: dict,
        partner_context: Optional[str] = None,
    ) -> CyberRiskProfile:
        ea      = output.get("email_auth", {})
        tech    = output.get("technographics", {})
        ti      = output.get("txt_intelligence", {})
        certs   = output.get("certificates", {})
        flags   = output.get("threat_flags", {})
        changes = output.get("change_signals", {})
        labels  = output.get("labels", {})
        dns     = output.get("dns_records", {})
        domain  = output.get("domain", "")

        # ── Parse subdomain intelligence ─────────────────────────────────
        raw_subdomains = output.get("subdomains") or []
        subs = SubdomainRiskSummary.from_raw(raw_subdomains)

        # ── Parse findings into { finding_code: finding_dict } ───────────
        # Gives O(1) lookup instead of scanning the list in every scorer
        raw_findings = output.get("findings") or []
        findings_map: dict[str, dict] = {
            f["finding"]: f for f in raw_findings if f.get("finding")
        }

        # ── HSTS / CSP coverage from findings ────────────────────────────
        # findings carry the parsed pct — extract for maturity scoring
        hsts_coverage, csp_coverage = self._parse_http_coverage(findings_map, subs)

        # ── Cert missed renewal from cert_analysis ────────────────────────
        cert_analysis   = output.get("cert_analysis") or output.get("certificate_intelligence") or {}
        missed_renewals = cert_analysis.get("missed_renewals", 0) if isinstance(cert_analysis, dict) else 0

        # ── Dimension scores ──────────────────────────────────────────────
        bec        = self._score_bec(ea, tech)
        ransomware = self._score_ransomware(flags, changes, labels, tech)
        breach     = self._score_data_breach(ti, ea, flags, subs)
        supply     = self._score_supply_chain(ti, partner_context)
        phishing   = self._score_phishing_platform(ea, flags, tech, dns, subs)
        maturity   = self._score_maturity(ea, flags, certs, dns, hsts_coverage, csp_coverage)

        underwriting, band, premium, primary, floor_override = self._composite(
            bec, ransomware, breach, supply, phishing, maturity,
            subs=subs,
            missed_renewals=missed_renewals,
        )

        return CyberRiskProfile(
            domain=domain,
            bec=bec,
            ransomware=ransomware,
            data_breach=breach,
            supply_chain=supply,
            phishing_platform=phishing,
            maturity=maturity,
            subdomains=subs,
            underwriting_score=underwriting,
            underwriting_band=band,
            premium_signal=premium,
            primary_claim_vector=primary,
            floor_override=floor_override,
            score_breakdown={
                "bec":               bec.score,
                "ransomware":        ransomware.score,
                "data_breach":       breach.score,
                "supply_chain":      supply.score,
                "phishing_platform": phishing.score,
                "maturity_offset":   maturity.score,
            },
        )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_http_coverage(
        findings_map: dict[str, dict],
        subs: SubdomainRiskSummary,
    ) -> tuple[float, float]:
        """
        Derive HSTS and CSP subdomain coverage fractions from findings.
        Returns (hsts_coverage, csp_coverage) as 0.0–1.0.
        """
        hsts_coverage = 1.0
        csp_coverage  = 1.0

        if subs.total == 0:
            return hsts_coverage, csp_coverage

        # hsts_absent_majority: "3 of 3 subdomains missing HSTS header"
        if "hsts_absent_majority" in findings_map:
            ev = findings_map["hsts_absent_majority"].get("evidence", "")
            # e.g. "3 of 3 subdomains missing HSTS header"
            try:
                parts = ev.split()
                missing = int(parts[0])
                total   = int(parts[2])
                hsts_coverage = max(0.0, (total - missing) / total)
            except (ValueError, IndexError):
                hsts_coverage = 0.0

        # ESTATE_HSTS_LOW: "Only 33% of 3 live subdomains have HSTS configured"
        elif "ESTATE_HSTS_LOW" in findings_map:
            ev = findings_map["ESTATE_HSTS_LOW"].get("evidence", "")
            try:
                pct = float(ev.split("%")[0].split()[-1])
                hsts_coverage = pct / 100.0
            except (ValueError, IndexError):
                hsts_coverage = 0.5

        if "csp_absent_majority" in findings_map:
            ev = findings_map["csp_absent_majority"].get("evidence", "")
            try:
                parts = ev.split()
                missing = int(parts[0])
                total   = int(parts[2])
                csp_coverage = max(0.0, (total - missing) / total)
            except (ValueError, IndexError):
                csp_coverage = 0.0

        return hsts_coverage, csp_coverage

    # -----------------------------------------------------------------------
    # Dimension scorers
    # -----------------------------------------------------------------------

    def _score_bec(self, ea: dict, tech: dict) -> BECRiskScore:
        score = 100
        gaps  = []

        spf_raw      = ea.get("spf_raw", "")
        spf_hard     = ea.get("spf") == "-all"
        spf_present  = bool(spf_raw)
        dmarc_reject  = ea.get("dmarc_policy") == "reject"
        dmarc_any     = bool(ea.get("dmarc_policy"))
        strict_align  = ea.get("aspf") == "s" and ea.get("adkim") == "s"
        mx_name       = (tech.get("mx_provider_name") or "").lower()
        mx_secure     = any(gw in mx_name for gw in MX_SECURITY_GATEWAYS)
        mta_enforcing = (
            ea.get("mta_sts") == "NOERROR" and
            ea.get("mta_sts_mode") == "enforce"
        )
        has_reporting = bool(ea.get("dmarc_rua"))

        if not spf_present:
            score -= 35
            gaps.append("No SPF record — any server can send as this domain")
        elif not spf_hard:
            score -= 15
            gaps.append("SPF uses ~all (soft fail) — spoofed mail may be delivered")

        if not dmarc_any:
            score -= 35
            gaps.append("No DMARC policy — no enforcement mechanism")
        elif not dmarc_reject:
            score -= 20
            gaps.append(f"DMARC p={ea.get('dmarc_policy')} — not reject")

        if not strict_align:
            score -= 10
            gaps.append("DMARC alignment not strict (aspf/adkim not set to s)")

        if not mx_secure:
            score -= 10
            gaps.append("No dedicated email security gateway detected")

        if not mta_enforcing:
            score -= 5
            gaps.append("MTA-STS not enforcing — SMTP downgrade risk")

        if not has_reporting:
            score -= 5
            gaps.append("No DMARC reporting (rua) — zero spoofing visibility")

        score = max(0, score)
        band  = self._risk_band(score)

        if score >= 80:
            narrative = (
                "BEC risk is low. SPF hard-fail and DMARC p=reject are both enforced"
                + (" with strict alignment." if strict_align else ".")
                + (f" {tech.get('mx_provider_name', 'Email gateway')} provides gateway security." if mx_secure else "")
                + " Spoofed email would be rejected before reaching any employee."
            )
        elif score >= 50:
            narrative = (
                f"Moderate BEC risk. Some authentication layers are in place but "
                f"{gaps[0].lower() if gaps else 'gaps exist'}. "
                f"A targeted attacker could craft email that bypasses current controls."
            )
        elif score >= 25:
            narrative = (
                f"High BEC risk. Critical email authentication gaps: "
                f"{'; '.join(gaps[:2])}. "
                f"Business email compromise — including fraudulent payment instructions "
                f"and wire transfer fraud — is viable without infrastructure access."
            )
        else:
            narrative = (
                f"Critical BEC exposure. This domain can be impersonated by any actor "
                f"with no technical access required. {len(gaps)} authentication layers "
                f"are missing. BEC attacks using this domain are viable immediately."
            )

        return BECRiskScore(
            score=score, band=band,
            spoofing_possible=ea.get("is_spoofable", False),
            dmarc_enforcing=dmarc_reject,
            spf_hard_fail=spf_hard,
            strict_alignment=strict_align,
            mx_security_gateway=mx_secure,
            mta_sts_enforcing=mta_enforcing,
            has_reporting=has_reporting,
            key_gaps=gaps, narrative=narrative,
        )

    def _score_ransomware(
        self,
        flags: dict,
        changes: dict,
        labels: dict,
        tech: dict,
    ) -> RansomwareExposureScore:
        score = 0
        gaps  = []

        short_ttl    = labels.get("ttl_bucket") in ("short", "very_short", "fast_flux_candidate")
        dynamic_dns  = flags.get("is_dynamic_dns", False) or changes.get("is_dynamic_dns", False)
        new_domain   = flags.get("is_new_domain", False)
        infra_change = changes.get("any_change", False)
        cdn_ugc      = tech.get("is_cdn_ugc", False)
        asn_risk     = tech.get("asn_risk_level", "unknown")
        high_asn     = asn_risk in ("high", "critical")

        if dynamic_dns:
            score += 30
            gaps.append("Dynamic DNS — infrastructure associated with C2 patterns")
        if short_ttl:
            score += 20
            gaps.append("Short TTL / fast-flux candidate — infrastructure instability signal")
        if new_domain:
            score += 20
            gaps.append("New domain — common characteristic of phishing/ransomware campaigns")
        if infra_change:
            score += 15
            gaps.append("Recent infrastructure changes (NS/IP/country changed)")
        if cdn_ugc:
            score += 10
            gaps.append("CDN/UGC hosting — shared infrastructure with potentially malicious content")
        if high_asn:
            score += 15
            gaps.append(f"ASN risk level: {asn_risk} — elevated network risk classification")

        score = min(100, score)
        band  = self._risk_band(score)

        if score == 0:
            narrative = (
                "No significant ransomware infrastructure signals detected. "
                "DNS patterns are consistent with stable, legitimate hosting."
            )
        elif score < 30:
            narrative = (
                f"Low ransomware infrastructure risk. Minor signals present: "
                f"{gaps[0].lower() if gaps else 'none significant'}."
            )
        elif score < 60:
            narrative = (
                f"Moderate ransomware exposure signals. {len(gaps)} indicators present. "
                f"These patterns appear in ransomware delivery and C2 infrastructure "
                f"but are context-dependent."
            )
        else:
            narrative = (
                f"Elevated ransomware infrastructure signals. {len(gaps)} risk factors "
                f"including {gaps[0].lower()}. Manual investigation recommended before binding."
            )

        return RansomwareExposureScore(
            score=score, band=band,
            short_ttl_flag=short_ttl,
            dynamic_dns=dynamic_dns,
            new_domain=new_domain,
            infrastructure_change_signals=infra_change,
            cdn_ugc=cdn_ugc,
            high_asn_risk=high_asn,
            key_gaps=gaps, narrative=narrative,
        )

    def _score_data_breach(
        self,
        ti: dict,
        ea: dict,
        flags: dict,
        subs: SubdomainRiskSummary,
    ) -> DataBreachExposureScore:
        score = 0
        gaps  = []

        all_saas   = ti.get("all_identified", [])
        cred_risk  = [s for s in all_saas if any(k in s.lower() for k in HIGH_RISK_SAAS)]
        no_dnssec  = not ea.get("dnssec")
        no_mta_sts = ea.get("mta_sts") not in ("NOERROR",)
        spoofable  = ea.get("is_spoofable", False)
        new_domain = flags.get("is_new_domain", False)

        if cred_risk:
            score += min(40, len(cred_risk) * 15)
            gaps.append(f"Breached credential stores in stack: {', '.join(cred_risk[:2])}")
        if no_dnssec:
            score += 15
            gaps.append("No DNSSEC — DNS hijacking could redirect traffic and email")
        if no_mta_sts:
            score += 10
            gaps.append("No MTA-STS — inbound email can be intercepted in transit")
        if spoofable:
            score += 15
            gaps.append("Domain spoofable — phishing attacks targeting customers are viable")
        if new_domain:
            score += 10
            gaps.append("New domain — limited breach history baseline")

        # ── Subdomain takeover contribution ──────────────────────────────
        # A takeover on an auth-surface subdomain is a direct credential
        # harvesting vector — material data breach risk
        if subs.has_auth_takeover:
            score += 30
            names = [s["dns_name"] for s in subs.auth_surface_takeovers]
            gaps.append(
                f"Auth-surface subdomain takeover: {', '.join(names)} — "
                f"attacker can serve credential-harvesting pages from legitimate namespace"
            )
        elif subs.has_takeover:
            score += 15
            names = [s["dns_name"] for s in subs.takeover_vulnerable]
            gaps.append(
                f"Subdomain takeover: {', '.join(names)} — "
                f"attacker controls content under this domain"
            )

        score = min(100, score)
        band  = self._risk_band(score)

        if score < 20:
            narrative = "Low data breach exposure. No known credential risks identified in the SaaS stack."
        elif score < 50:
            narrative = (
                f"Moderate data breach exposure. {'; '.join(gaps[:2])}. "
                f"A successful attack could leverage these gaps to access or exfiltrate data."
            )
        else:
            narrative = (
                f"High data breach exposure. {len(gaps)} risk factors including "
                f"{gaps[0].lower()}. "
                + (
                    f"The presence of {', '.join(cred_risk[:2])} in the stack means "
                    f"credentials from known breaches may already be in threat actor hands. "
                    if cred_risk else ""
                )
                + (
                    f"Subdomain takeover on {subs.auth_surface_takeovers[0]['dns_name']} "
                    f"via {subs.auth_surface_takeovers[0].get('takeover_provider', 'cloud provider')} "
                    f"enables high-fidelity credential harvesting with no phishing infrastructure required. "
                    if subs.has_auth_takeover else ""
                )
                + "Data breach probability is elevated above baseline."
            )

        return DataBreachExposureScore(
            score=score, band=band,
            credential_risk_saas=cred_risk,
            no_dnssec=no_dnssec,
            no_mta_sts=no_mta_sts,
            spoofable=spoofable,
            subdomain_takeover=subs.has_takeover,
            auth_surface_takeover=subs.has_auth_takeover,
            key_gaps=gaps, narrative=narrative,
        )

    def _score_supply_chain(
        self,
        ti: dict,
        partner_context: Optional[str],
    ) -> SupplyChainRiskScore:
        score = 0
        gaps  = []

        all_saas   = ti.get("all_identified", [])
        saas_count = len(all_saas)
        high_risk  = [s for s in all_saas if any(k in s.lower() for k in HIGH_RISK_SAAS)]
        ai_infra   = bool(ti.get("ai_infrastructure"))
        payments   = len(ti.get("payment_processors", []))
        identity   = len(ti.get("identity_providers", []))
        email_mktg = len(ti.get("email_marketing", []))

        if saas_count >= 20:
            score += 25
            gaps.append(f"Large SaaS footprint ({saas_count} platforms) — broad attack surface")
        elif saas_count >= 10:
            score += 15
            gaps.append(f"Significant SaaS footprint ({saas_count} platforms)")
        elif saas_count >= 5:
            score += 8

        if high_risk:
            score += min(30, len(high_risk) * 15)
            gaps.append(f"Known-breached SaaS in stack: {', '.join(high_risk[:3])}")
        if ai_infra:
            score += 10
            gaps.append("AI infrastructure — new attack surface category")
        if payments >= 5:
            score += 10
            gaps.append(f"{payments} payment integrations — high-value fraud target")
        if identity >= 3:
            score += 10
            gaps.append(f"{identity} identity providers — credential aggregation risk")
        if email_mktg >= 2:
            score += 5
            gaps.append(f"{email_mktg} email marketing platforms — outbound spoofing surface")

        multiplier = 1.0
        if partner_context:
            ctx = partner_context.lower()
            if any(k in ctx for k in ("platinum", "elite", "premier", "enterprise")):
                multiplier = 1.8
            elif any(k in ctx for k in ("partner", "reseller", "gold")):
                multiplier = 1.5
            elif any(k in ctx for k in ("supplier", "vendor")):
                multiplier = 1.3

        score = min(100, int(score * multiplier))
        band  = self._risk_band(score)

        if score < 20:
            narrative = f"Minimal supply chain risk. Lean SaaS stack with {saas_count} identified service{'s' if saas_count != 1 else ''}."
        elif score < 50:
            narrative = (
                f"Moderate supply chain exposure. {saas_count} SaaS services identified. "
                + (f"High-risk vendors include {', '.join(high_risk[:2])}. " if high_risk else "")
                + "Each integration represents a potential third-party breach pathway."
            )
        else:
            narrative = (
                f"Significant supply chain risk. {saas_count} SaaS platforms"
                + (f" including known-breached services ({', '.join(high_risk[:2])})." if high_risk else ".")
                + (f" AI infrastructure confirms production AI agent access to business systems." if ai_infra else "")
                + f" A breach at any vendor could expose this organisation's data."
            )

        return SupplyChainRiskScore(
            score=score, band=band,
            saas_count=saas_count,
            high_risk_saas_count=len(high_risk),
            ai_infrastructure=ai_infra,
            payment_processor_count=payments,
            identity_provider_count=identity,
            email_marketing_count=email_mktg,
            key_gaps=gaps, narrative=narrative,
        )

    def _score_phishing_platform(
        self,
        ea: dict,
        flags: dict,
        tech: dict,
        dns: dict,
        subs: SubdomainRiskSummary,
    ) -> PhishingPlatformScore:
        score = 0
        gaps  = []

        spoofable  = ea.get("is_spoofable", False)
        no_caa     = not flags.get("has_caa", False)
        cdn_ugc    = tech.get("is_cdn_ugc", False)
        high_asn   = tech.get("asn_risk_level") in ("high", "critical")
        no_sec_txt = not flags.get("has_security_txt", False)

        if spoofable:
            score += 50
            gaps.append("Domain is spoofable — can be used to impersonate this brand in email")
        if no_caa:
            score += 20
            gaps.append("No CAA records — fraudulent certificates can be obtained for this domain")
        if cdn_ugc:
            score += 10
            gaps.append("CDN/UGC hosting — shared with potentially malicious content")
        if high_asn:
            score += 15
            gaps.append(f"ASN risk: {tech.get('asn_risk_level')} — elevated abuse history")
        if no_sec_txt:
            score += 5
            gaps.append("No security.txt — no responsible disclosure channel for researchers")

        # ── Subdomain takeover — legitimate namespace hijack ──────────────
        # An attacker controlling a subdomain can serve convincing phishing
        # pages under the target's own domain — higher fidelity than spoofing
        if subs.has_auth_takeover:
            score += 40
            tko  = subs.auth_surface_takeovers[0]
            name = tko["dns_name"]
            prov = tko.get("takeover_provider", "cloud provider")
            gaps.insert(0,
                f"Auth-surface subdomain takeover ({name} via {prov}) — attacker can serve "
                f"phishing pages within the legitimate {name.split('.', 1)[-1]} namespace"
            )
        elif subs.has_takeover:
            score += 25
            tko  = subs.takeover_vulnerable[0]
            name = tko["dns_name"]
            prov = tko.get("takeover_provider", "cloud provider")
            gaps.insert(0,
                f"Subdomain takeover ({name} via {prov}) — content served under legitimate domain namespace"
            )

        score = min(100, score)
        band  = self._risk_band(score)

        if subs.has_auth_takeover:
            tko  = subs.auth_surface_takeovers[0]
            narrative = (
                f"Critical phishing platform risk. {tko['dns_name']} is vulnerable to "
                f"takeover via a dangling CNAME to {tko.get('cname', tko.get('takeover_provider', 'cloud resource'))}. "
                f"An attacker claiming this {tko.get('takeover_provider', 'cloud')} resource can serve "
                f"credential-harvesting pages under the legitimate domain — "
                f"bypassing browser warnings and anti-phishing controls entirely. "
                + ("The domain is also spoofable, enabling parallel email-based attacks. " if spoofable else "")
            )
        elif subs.has_takeover:
            tko  = subs.takeover_vulnerable[0]
            narrative = (
                f"High phishing platform risk. {tko['dns_name']} is vulnerable to subdomain takeover "
                f"via {tko.get('takeover_provider', 'cloud provider')}. "
                f"An attacker can serve malicious content under this organisation's domain namespace."
                + (" Domain is also spoofable." if spoofable else "")
            )
        elif score < 20:
            narrative = "Low phishing platform risk. Strong email authentication prevents spoofing of this domain."
        elif score < 50:
            narrative = (
                f"Moderate phishing platform risk. {gaps[0] if gaps else 'Some gaps present'}. "
                f"This domain could be used as a launchpad for attacks against customers or partners."
            )
        else:
            narrative = (
                f"High phishing platform risk. This domain can be trivially spoofed, "
                f"making it a viable tool for attacking the customer base. "
                f"Attackers can send email appearing to be from this organisation with zero infrastructure access."
            )

        return PhishingPlatformScore(
            score=score, band=band,
            spoofable=spoofable,
            no_caa=no_caa,
            shared_hosting=cdn_ugc,
            high_asn_abuse=high_asn,
            no_security_txt=no_sec_txt,
            subdomain_takeover=subs.has_takeover,
            auth_surface_takeover=subs.has_auth_takeover,
            key_gaps=gaps, narrative=narrative,
        )

    def _score_maturity(
        self,
        ea: dict,
        flags: dict,
        certs: dict,
        dns: dict,
        hsts_coverage: float = 1.0,
        csp_coverage: float  = 1.0,
    ) -> InfrastructureMaturityScore:
        score = 0

        ipv6      = bool(dns.get("aaaa"))
        caa       = flags.get("has_caa", False)
        dnssec    = bool(ea.get("dnssec"))
        mta_sts   = ea.get("mta_sts") == "NOERROR"
        tls_rpt   = ea.get("tls_rpt") == "NOERROR"
        bimi      = ea.get("bimi") == "NOERROR"
        sec_txt   = flags.get("has_security_txt", False)
        cert_ok   = (
            bool(certs.get("https_ok")) and
            (certs.get("https_days_left") or 0) > 30 and
            not certs.get("https_lets_encrypt")
        )
        smtp_ok   = certs.get("provider_live", False)
        reporting = bool(ea.get("dmarc_rua"))

        if ipv6:      score += 10
        if caa:       score += 15
        if dnssec:    score += 15
        if mta_sts:   score += 15
        if tls_rpt:   score += 10
        if bimi:      score += 10
        if sec_txt:   score += 5
        if cert_ok:   score += 10
        if smtp_ok:   score += 5
        if reporting: score += 5

        # ── HSTS / CSP coverage deductions ───────────────────────────────
        # Full coverage = no penalty. Partial/zero coverage reduces maturity.
        # Max deduction: 10pts HSTS + 5pts CSP = 15pts
        if hsts_coverage < 1.0:
            deduction = round((1.0 - hsts_coverage) * 10)
            score = max(0, score - deduction)
        if csp_coverage < 1.0:
            deduction = round((1.0 - csp_coverage) * 5)
            score = max(0, score - deduction)

        score = min(100, score)

        if score >= 80:   level, band = "exemplary",    "low"
        elif score >= 55: level, band = "advanced",     "low"
        elif score >= 30: level, band = "intermediate", "medium"
        else:             level, band = "basic",        "high"

        narratives = {
            "exemplary":    "Infrastructure maturity is exemplary. All major security layers deployed. Consistent with a mature security programme.",
            "advanced":     "Strong infrastructure maturity. Most security layers in place with minor gaps remaining.",
            "intermediate": "Moderate infrastructure maturity. Core email authentication present but several hardening layers missing.",
            "basic":        "Basic infrastructure maturity. Significant security layers absent. Organisation appears to be in early stages of security hardening.",
        }

        return InfrastructureMaturityScore(
            score=score, band=band,
            dual_stack_ipv6=ipv6,
            has_caa=caa,
            has_dnssec=dnssec,
            has_mta_sts=mta_sts,
            has_tls_rpt=tls_rpt,
            has_bimi=bimi,
            has_security_txt=sec_txt,
            cert_health=cert_ok,
            smtp_banner_confirmed=smtp_ok,
            dmarc_reporting=reporting,
            hsts_coverage=hsts_coverage,
            csp_coverage=csp_coverage,
            maturity_level=level,
            narrative=narratives[level],
        )

    # -----------------------------------------------------------------------
    # Composite
    # -----------------------------------------------------------------------

    def _composite(
        self,
        bec: BECRiskScore,
        ransomware: RansomwareExposureScore,
        breach: DataBreachExposureScore,
        supply: SupplyChainRiskScore,
        phishing: PhishingPlatformScore,
        maturity: InfrastructureMaturityScore,
        subs: SubdomainRiskSummary,
        missed_renewals: int = 0,
    ) -> tuple[int, str, str, str, Optional[str]]:
        """
        Weighted composite + floor overrides.

        Floor overrides ensure binary critical findings cannot be
        averaged away by a clean posture elsewhere. Applied after the
        weighted calculation — the highest applicable floor wins.
        """
        raw = (
            bec.score        * self.WEIGHTS["bec"] +
            ransomware.score * self.WEIGHTS["ransomware"] +
            breach.score     * self.WEIGHTS["data_breach"] +
            supply.score     * self.WEIGHTS["supply_chain"] +
            phishing.score   * self.WEIGHTS["phishing_platform"] -
            maturity.score   * self.WEIGHTS["maturity_offset"]
        )
        composite = max(0, min(100, round(raw)))

        # ── Floor overrides ───────────────────────────────────────────────
        floor_override: Optional[str] = None
        floor_applied  = composite

        if subs.has_auth_takeover:
            floor = 75
            if floor > floor_applied:
                floor_applied    = floor
                floor_override   = "auth_subdomain_takeover"
        elif subs.has_takeover:
            floor = 65
            if floor > floor_applied:
                floor_applied    = floor
                floor_override   = "subdomain_takeover"

        if missed_renewals > 0:
            floor = 40
            if floor > floor_applied:
                floor_applied    = floor
                floor_override   = "cert_missed_renewal"

        composite = floor_applied

        band = self._risk_band(composite)

        if composite >= 80:   premium = "decline"
        elif composite >= 65: premium = "heavy_loading"
        elif composite >= 45: premium = "loading"
        else:                 premium = "standard"

        scores = {
            "Business Email Compromise": bec.score        * self.WEIGHTS["bec"],
            "Ransomware":                ransomware.score * self.WEIGHTS["ransomware"],
            "Data breach":               breach.score     * self.WEIGHTS["data_breach"],
            "Supply chain attack":       supply.score     * self.WEIGHTS["supply_chain"],
            "Phishing platform abuse":   phishing.score   * self.WEIGHTS["phishing_platform"],
        }
        primary = max(scores, key=scores.get)

        # If floor override is active, it's the primary driver
        if floor_override:
            primary = floor_override.replace("_", " ").title()

        return composite, band, premium, primary, floor_override

    # -----------------------------------------------------------------------
    # Utilities
    # -----------------------------------------------------------------------

    @staticmethod
    def _risk_band(score: int) -> str:
        if score >= 75: return "critical"
        if score >= 50: return "high"
        if score >= 25: return "medium"
        return "low"