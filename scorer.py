from __future__ import annotations

import ast
import math
from dataclasses import dataclass
from typing import Optional, Any

# ---------------------------------------------------------------------------
# Normalised internal types — mapped from your exact formats
# ---------------------------------------------------------------------------

@dataclass
class NormalisedIPScore:
    ip: str
    prefix: str
    asn: int

    # Raw scores (0.0–1.0)
    prefix_infra_score: float
    asn_core_risk: float
    ip_direct_threat_score: float
    final_ip_risk_score: float

    # Parsed reason codes
    reason_codes: list[str]

    # Derived
    score_pct: int                    # final_ip_risk_score * 100, rounded
    is_flagged: bool                  # final_ip_risk_score > 0.5
    is_active_threat: bool            # ip_direct_threat_score > 0.3
    is_cdn_safe: bool                 # "CDN_SAFE" in reason_codes
    threat_categories: list[str]      # Extracted from reason codes

    @classmethod
    def from_raw(cls, raw: dict) -> "NormalisedIPScore":
        reason_raw = raw.get("reason_codes", "[]")
        try:
            codes = ast.literal_eval(reason_raw) if isinstance(reason_raw, str) else reason_raw
        except (ValueError, SyntaxError):
            codes = []

        final = float(raw.get("final_ip_risk_score", 0))

        # Map reason codes to threat categories
        threat_map = {
            "PHISHING":    "phishing",
            "MALWARE":     "malware",
            "SPAM":        "spam",
            "C2":          "c2_command_control",
            "SCANNER":     "scanner",
            "BOTNET":      "botnet",
            "PROXY":       "proxy_anonymiser",
            "BULLETPROOF": "bulletproof_hosting",
        }
        categories = [
            threat_map[k] for k in threat_map
            if any(k in code.upper() for code in codes)
        ]

        return cls(
            ip=raw["ip"],
            prefix=raw.get("prefix", ""),
            asn=int(raw.get("asn", 0)),
            prefix_infra_score=float(raw.get("prefix_infra_score", 0)),
            asn_core_risk=float(raw.get("asn_core_risk", 0)),
            ip_direct_threat_score=float(raw.get("ip_direct_threat_score", 0)),
            final_ip_risk_score=final,
            reason_codes=codes,
            score_pct=round(final * 100),
            is_flagged=final > 0.5,
            is_active_threat=float(raw.get("ip_direct_threat_score", 0)) > 0.3,
            is_cdn_safe=any("CDN_SAFE" in c.upper() for c in codes),
            threat_categories=categories,
        )


@dataclass
class NormalisedDomainScore:
    domain: str
    ip: str

    # Boolean threat flags
    is_phishing: bool
    is_malware: bool
    is_parked: bool
    is_disposable: bool

    # Email infrastructure
    dmarc: Optional[str]
    spf: Optional[str]
    mx_status_flag: str         # "ACTIVE" | "INACTIVE" | "NONE"

    # IP score for this domain's resolution
    final_ip_risk_score: float
    score_pct: int

    # Metadata
    last_scanned: str

    # Derived
    is_flagged: bool
    threat_categories: list[str]

    @classmethod
    def from_raw(cls, raw: dict) -> "NormalisedDomainScore":
        final = float(raw.get("final_ip_risk_score", 0))
        categories = []
        if raw.get("is_phishing"):   categories.append("phishing")
        if raw.get("is_malware"):    categories.append("malware")
        if raw.get("is_parked"):     categories.append("parked")
        if raw.get("is_disposable"): categories.append("disposable")

        return cls(
            domain=raw.get("domain", ""),
            ip=raw.get("ip", ""),
            is_phishing=bool(raw.get("is_phishing", False)),
            is_malware=bool(raw.get("is_malware", False)),
            is_parked=bool(raw.get("is_parked", False)),
            is_disposable=bool(raw.get("is_disposable", False)),
            dmarc=raw.get("dmarc"),
            spf=raw.get("spf"),
            mx_status_flag=raw.get("mx_status_flag", "UNKNOWN"),
            final_ip_risk_score=final,
            score_pct=round(final * 100),
            last_scanned=raw.get("ducklake_insert_time", ""),
            is_flagged=final > 0.5 or bool(raw.get("is_phishing") or raw.get("is_malware")),
            threat_categories=categories,
        )

@dataclass
class NormalisedAnnotation:
    domain: str
    ip_int: int

    # MX intelligence
    mx_provider_name: Optional[str]
    mx_mbp_category: Optional[str]
    mx_risk_bias: float           # negative = trusted, positive = risky
    mx_trust_nudge: float         # positive = more trusted

    # NS intelligence
    ns_provider_name: Optional[str]
    ns_provider_category: Optional[str]
    ns_brand_hit: bool

    # Provider trust
    provider_trust_nudge: float

    # ASN / ISP
    asn: int
    isp_name: Optional[str]
    isp_country: Optional[str]
    asn_risk_level: str           # "unknown" | "trustworthy" | "low" | "medium" | "high"

    # TLD
    tld_country: Optional[str]
    tld_risk_level: str           # "trustworthy" | "low" | "medium" | "high"

    # Flags
    is_cdn_ugc: bool

    # Derived
    net_trust_score: float        # sum of all nudges — positive = more trusted
    is_trusted_infrastructure: bool

    @classmethod
    def from_raw(cls, raw: dict) -> "NormalisedAnnotation":
        mx_trust    = float(raw.get("mx_trust_nudge", 0))
        mx_risk     = float(raw.get("mx_risk_bias", 0))
        prov_trust  = float(raw.get("provider_trust_nudge", 0))
        net_trust   = mx_trust + prov_trust + mx_risk   # mx_risk is negative when trusted

        return cls(
            domain=raw.get("domain", ""),
            ip_int=int(raw.get("ip_int", 0)),
            mx_provider_name=raw.get("mx_provider_name"),
            mx_mbp_category=raw.get("mx_mbp_category"),
            mx_risk_bias=mx_risk,
            mx_trust_nudge=mx_trust,
            ns_provider_name=raw.get("ns_provider_name"),
            ns_provider_category=raw.get("ns_provider_category"),
            ns_brand_hit=bool(raw.get("ns_brand_hit", False)),
            provider_trust_nudge=prov_trust,
            asn=int(raw.get("asn", 0)),
            isp_name=raw.get("isp_name"),
            isp_country=raw.get("isp_country"),
            asn_risk_level=raw.get("asn_risk_level", "unknown"),
            tld_country=raw.get("tld_country"),
            tld_risk_level=raw.get("tld_risk_level", "unknown"),
            is_cdn_ugc=bool(raw.get("is_cdn_ugc", False)),
            net_trust_score=net_trust,
            is_trusted_infrastructure=net_trust > 1.0,
        )

# ---------------------------------------------------------------------------
# Composite scorer — wires all three formats into a final brief score
# ---------------------------------------------------------------------------

@dataclass
class CompositeScore:
    """
    Final scored output for a domain's complete DNS profile.
    Each component is independently interpretable.
    """
    domain: str

    # Component scores (0–100)
    dns_posture_score: int          # From DNSIntelligenceEngine
    ip_risk_score: int              # From NormalisedIPScore
    domain_threat_score: int        # From NormalisedDomainScore
    infrastructure_trust_score: int # From NormalisedAnnotation nudges
    email_security_score: int       # SPF + DMARC + MX provider trust

    # Nudge adjustments applied
    mx_trust_nudge_applied: float
    provider_trust_nudge_applied: float
    tld_risk_adjustment: float

    # Final
    composite_score: int            # 0–100, higher = riskier
    confidence: str                 # "high" | "medium" | "low"
    risk_band: str                  # "critical" | "high" | "medium" | "low"

    # Breakdown narrative
    primary_driver: str             # What's driving the score most
    score_components: dict


class DatazagCompositeScorer:
    """
    Combines all three Datazag scorer outputs into a single composite.

    Weight rationale:
      dns_posture     35% — most directly observable, hardest to fake
      email_security  25% — direct spoofing/phishing risk signal
      ip_risk         20% — infrastructure reputation
      domain_threat   15% — direct threat classification
      infra_trust      5% — nudge adjustments from annotation module
    """

    WEIGHTS = {
        "dns_posture":      0.35,
        "email_security":   0.25,
        "ip_risk":          0.20,
        "domain_threat":    0.15,
        "infra_trust":      0.05,
    }

    # ASN risk level → score contribution
    ASN_RISK_SCORES = {
        "trustworthy": 0,
        "unknown":    15,
        "low":        25,
        "medium":     50,
        "high":       85,
    }

    # TLD risk → adjustment
    TLD_RISK_ADJUSTMENTS = {
        "trustworthy": -5,    # Pulls score down slightly
        "unknown":      0,
        "low":          5,
        "medium":      15,
        "high":        30,
    }

    def compute(
        self,
        domain: str,
        dns_posture_score: int,         # From DNSIntelligenceEngine.scores.overall_risk
        email_spoof_score: int,         # From DNSIntelligenceEngine.scores.spoofing_risk
        ip_score: Optional[NormalisedIPScore],
        domain_score: Optional[NormalisedDomainScore],
        annotation: Optional[NormalisedAnnotation],
    ) -> CompositeScore:

        # --- IP risk component ---
        ip_risk = 0
        if ip_score:
            ip_risk = ip_score.score_pct
            # Boost if direct threat (not just infrastructure risk)
            if ip_score.is_active_threat:
                ip_risk = min(100, ip_risk + 30)
            # CDN safe signals suppress infrastructure noise
            if ip_score.is_cdn_safe:
                ip_risk = max(0, ip_risk - 20)

        # --- Domain threat component ---
        domain_threat = 0
        if domain_score:
            domain_threat = domain_score.score_pct
            if domain_score.is_phishing: domain_threat = min(100, domain_threat + 60)
            if domain_score.is_malware:  domain_threat = min(100, domain_threat + 70)
            if domain_score.is_parked:   domain_threat = min(100, domain_threat + 10)

        # --- Email security component ---
        # Combines DNS posture spoofing score with MX provider trust nudges
        email_security = email_spoof_score
        mx_nudge = 0.0
        prov_nudge = 0.0
        if annotation:
            # mx_trust_nudge is positive = trusted MX → reduces email risk
            mx_nudge = annotation.mx_trust_nudge
            prov_nudge = annotation.provider_trust_nudge
            # Each unit of trust nudge reduces email score by 5 points
            email_security = max(0, email_security - int((mx_nudge + prov_nudge) * 5))
            # mx_risk_bias is negative when trusted, positive when risky
            email_security = max(0, min(100,
                email_security + int(annotation.mx_risk_bias * 3)
            ))

        # --- Infrastructure trust component ---
        # Lower = more trusted infrastructure
        infra_trust_score = 50  # Neutral baseline
        tld_adjustment = 0.0
        asn_score = 0
        if annotation:
            # Net trust score > 0 = trusted infrastructure
            infra_trust_score = max(0, min(100,
                50 - int(annotation.net_trust_score * 10)
            ))
            tld_adjustment = self.TLD_RISK_ADJUSTMENTS.get(annotation.tld_risk_level, 0)
            asn_score = self.ASN_RISK_SCORES.get(annotation.asn_risk_level, 15)
            infra_trust_score = max(0, min(100,
                (infra_trust_score + asn_score) // 2 + int(tld_adjustment)
            ))

        # --- Weighted composite ---
        components = {
            "dns_posture":    dns_posture_score,
            "email_security": email_security,
            "ip_risk":        ip_risk,
            "domain_threat":  domain_threat,
            "infra_trust":    infra_trust_score,
        }
        weighted = sum(
            components[k] * self.WEIGHTS[k]
            for k in components
        )
        composite = max(0, min(100, round(weighted)))

        # Primary driver
        driver_scores = {
            "DNS posture":          dns_posture_score * self.WEIGHTS["dns_posture"],
            "Email security":       email_security * self.WEIGHTS["email_security"],
            "IP reputation":        ip_risk * self.WEIGHTS["ip_risk"],
            "Domain threat flags":  domain_threat * self.WEIGHTS["domain_threat"],
        }
        primary_driver = max(driver_scores, key=driver_scores.get)

        # Confidence — based on data completeness
        data_present = sum([
            ip_score is not None,
            domain_score is not None,
            annotation is not None,
        ])
        confidence = "high" if data_present == 3 else "medium" if data_present >= 1 else "low"

        risk_band = (
            "critical" if composite >= 75 else
            "high"     if composite >= 50 else
            "medium"   if composite >= 25 else
            "low"
        )

        return CompositeScore(
            domain=domain,
            dns_posture_score=dns_posture_score,
            ip_risk_score=ip_risk,
            domain_threat_score=domain_threat,
            infrastructure_trust_score=infra_trust_score,
            email_security_score=email_security,
            mx_trust_nudge_applied=mx_nudge,
            provider_trust_nudge_applied=prov_nudge,
            tld_risk_adjustment=tld_adjustment,
            composite_score=composite,
            confidence=confidence,
            risk_band=risk_band,
            primary_driver=primary_driver,
            score_components={k: round(v * self.WEIGHTS[k]) for k, v in components.items()},
        )