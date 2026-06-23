"""
intelligence_contract.py
------------------------
The single typed boundary between riskscore (the gold-layer single source of
truth) and the report renderers.

riskscore's `DomainIntelligenceAPI.get_domain_intelligence(...)` returns a nested
"medallion" JSON payload (schema_version "1.0"). This module mirrors that payload
as Pydantic models so that:

  * every field the renderers/narrative read is declared in ONE place,
  * partial or empty payloads degrade to explicit defaults instead of raising,
  * scale normalisation happens once (all *_risk fields are clamped to 0.0–1.0;
    `certstream.hits`, `dga_entropy` and impersonation counts are counts, NOT 0–1).

It also derives the two-pillar *view-model* (Trust Surface / Threat Surface /
External Threat) plus a 0–100 composite score and an A–F grade that the
healthreport Jinja engine renders.

Field names mirror riskscore/infrastructure/domain_intelligence_api.py:144-225.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from healthreport.grade import TrustGrade, score_to_grade


def _clamp01(v) -> float:
    try:
        f = float(v or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if f < 0.0 else 1.0 if f > 1.0 else f


# ---------------------------------------------------------------------------
# Medallion payload models (mirror the riskscore struct_pack)
# ---------------------------------------------------------------------------

class _Base(BaseModel):
    # Ignore unknown keys (e.g. the optional `scores` block when a profile is set,
    # or any future field riskscore adds) so the contract never breaks on add.
    model_config = ConfigDict(extra="ignore")


class Facts(_Base):
    asn: int = 0
    prefix: Optional[str] = None
    isp: Optional[str] = None              # network/org name (from asn_ip4)
    isp_country: Optional[str] = None
    asn_risk_level: str = "unknown"
    is_manrs_member: bool = False
    manrs_status: str = "Unknown"
    is_manrs_culprit: bool = False


class Routing(_Base):
    moas_detected: bool = False
    prefixes_churn_total: int = 0
    rpki_state: Literal["valid", "invalid", "unknown"] = "unknown"


class EmailSecurity(_Base):
    mx_type: str = "unknown"
    mx_risk_score: float = 0.0           # 0..1
    dmarc_risk: bool = False             # True == at risk (no enforcement)
    spf_risk: bool = False               # True == at risk (not strict)
    modern_security_present: bool = False

    @field_validator("mx_risk_score")
    @classmethod
    def _clamp(cls, v):
        return _clamp01(v)


class FeedFlag(_Base):
    listed: bool = False


class ThreatFeeds(_Base):
    feodo: FeedFlag = Field(default_factory=FeedFlag)
    urlhaus: FeedFlag = Field(default_factory=FeedFlag)
    sslbl: FeedFlag = Field(default_factory=FeedFlag)
    threatfox: FeedFlag = Field(default_factory=FeedFlag)
    spamhaus: FeedFlag = Field(default_factory=FeedFlag)

    def listed_feeds(self) -> list[str]:
        out = []
        for name in ("feodo", "urlhaus", "sslbl", "threatfox", "spamhaus"):
            if getattr(self, name).listed:
                out.append(name)
        return out


class Certstream(_Base):
    hits: int = 0                        # count, NOT 0..1


class PivotFinding(_Base):
    dimension: str = ""                  # "asn" | "ip" | ...
    value: str = ""
    malicious_count: int = 0
    examples: list[str] = Field(default_factory=list)


class Concentration(_Base):
    pivot_findings: list[PivotFinding] = Field(default_factory=list)


class DomainDnsFacts(_Base):
    lowest_ttl: int = 0
    a_record_count: int = 0
    is_dangling_cname: bool = False
    cname_target: Optional[str] = None
    dga_entropy: float = 0.0             # unbounded Shannon entropy


class HistoricalVelocity(_Base):
    ip_changes_30d: int = 0
    asn_diversity_30d: int = 0
    geo_diversity_30d: int = 0
    ip_churn_score: float = 0.0          # 0..1

    @field_validator("ip_churn_score")
    @classmethod
    def _clamp(cls, v):
        return _clamp01(v)


class RiskAssessment(_Base):
    infra_score: float = 0.0
    ip_direct_threat_score: float = 0.0
    reason_codes: list[str] = Field(default_factory=list)
    fast_flux_risk: float = 0.0
    dga_risk: float = 0.0
    concentration_risk: float = 0.0
    certstream_risk: float = 0.0
    dangling_cname_risk: float = 0.0

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _none_to_list(cls, v):
        return v or []

    @field_validator(
        "infra_score", "ip_direct_threat_score", "fast_flux_risk", "dga_risk",
        "concentration_risk", "certstream_risk", "dangling_cname_risk",
    )
    @classmethod
    def _clamp(cls, v):
        return _clamp01(v)

    def worst_subscore(self) -> float:
        return max(
            self.infra_score, self.ip_direct_threat_score, self.fast_flux_risk,
            self.dga_risk, self.concentration_risk, self.certstream_risk,
            self.dangling_cname_risk,
        )


class DomainIntelligence(_Base):
    """Root medallion payload."""
    schema_version: str = "1.0"
    generated_at: Optional[str] = None
    domain: str = ""
    facts: Facts = Field(default_factory=Facts)
    routing: Routing = Field(default_factory=Routing)
    email_security: EmailSecurity = Field(default_factory=EmailSecurity)
    threat_feeds: ThreatFeeds = Field(default_factory=ThreatFeeds)
    certstream: Certstream = Field(default_factory=Certstream)
    concentration: Concentration = Field(default_factory=Concentration)
    domain_dns_facts: DomainDnsFacts = Field(default_factory=DomainDnsFacts)
    historical_velocity: HistoricalVelocity = Field(default_factory=HistoricalVelocity)
    risk_assessment: RiskAssessment = Field(default_factory=RiskAssessment)
    data_freshness: dict[str, str] = Field(default_factory=dict)
    # error envelope passthrough ({"error","code"} from the API on 404/500)
    error: Optional[str] = None
    code: Optional[int] = None

    @property
    def is_error(self) -> bool:
        return self.code is not None and self.code >= 400

    @property
    def has_intelligence(self) -> bool:
        """False for NXDOMAIN / not-found / error payloads."""
        return not self.is_error and self.schema_version == "1.0" and bool(self.domain)


# ---------------------------------------------------------------------------
# Platform-impersonation models (from the riskscore rollup endpoint)
# ---------------------------------------------------------------------------

class PlatformImpersonation(_Base):
    """Per-platform impersonation counts over rolling windows.

    `platform` is the imitated platform/brand (e.g. "microsoft365"); counts are
    distinct impersonating domains observed in CT logs within the window.
    """
    platform: str
    category: str = ""
    count_7d: int = 0
    count_30d: int = 0
    # Current rollup snapshot (ref.platform_impersonation) — no window split there.
    impersonating_domains: int = 0       # distinct impersonating domains, current
    hits: int = 0                        # total hits, current
    sample_domains: list[str] = Field(default_factory=list)
    # "exact"   = certstream exact brand/platform match (rollup kind platform|brand)
    # "lookalike" = fuzzy typosquat candidate (kind *_typosquat) — lower confidence
    confidence: Literal["exact", "lookalike"] = "exact"

    @property
    def trend(self) -> Literal["up", "down", "flat"]:
        # Compare last-7d rate against the prior 3 weeks' average weekly rate.
        prior_weekly = max(0.0, (self.count_30d - self.count_7d) / 3.0)
        if self.count_7d > prior_weekly * 1.25:
            return "up"
        if self.count_7d < prior_weekly * 0.75:
            return "down"
        return "flat"


class BrandExposure(_Base):
    """Lookalikes of the customer's OWN brand/domain."""
    count_7d: int = 0
    count_30d: int = 0
    sample_domains: list[str] = Field(default_factory=list)
    confidence: Literal["exact", "lookalike"] = "exact"


# ---------------------------------------------------------------------------
# Free-report brand funnel (the riskscore brand-funnel endpoint)
# ---------------------------------------------------------------------------
#
# The FREE Health Report's brand page renders an active-scan funnel computed at
# report time from CHEAP corpus data only — pattern generation, `gold.dns_wide`
# resolution state, a DGA cross-check, and passively-observed certs. See
# healthreport/brand_page_data_contract.md. Two invariants are enforced by
# CONSTRUCTION here (the producer endpoint must honour them):
#   * brand-scoped — NEVER populated from `ref.platform_impersonation`
#     (platform-global; that is the "157" conflation bug), and
#   * cheap-only — NEVER carries capture-derived weaponization columns
#     (those are paid-tier and cost a per-domain fetch).

class BrandCandidate(_Base):
    """One generated brand-lookalike candidate, checked against cheap corpus
    data at report time. Carries no capture-derived weaponization fields."""
    domain: str = ""
    status: str = "generated"      # generated | nxdomain | parked | resolving
    registered: bool = False
    has_a: bool = False
    has_mx: bool = False
    domain_age_days: Optional[int] = None
    dga_risk: float = 0.0          # 0..1 string-entropy signature
    has_cert: bool = False         # a cert was already observed passively (no fetch)
    priority: int = 0

    @field_validator("dga_risk", mode="before")
    @classmethod
    def _clamp_dga(cls, v):
        return _clamp01(v)


class BrandFunnel(_Base):
    """Active-scan brand funnel for the FREE health report
    (brand_page_data_contract.md §3). Built producer-side from cheap corpus data
    and served by the riskscore brand-funnel endpoint. Brand-scoped by
    construction — it must never be filled from platform-global impersonation
    counts or capture-dependent columns."""
    monitored: bool = False                # a registered brand_id exists (paid Watch active)
    candidates_generated: int = 0
    checked: int = 0                       # candidates actually resolution-checked (capped)
    registered: int = 0                    # resolving or parked
    resolving: int = 0                     # resolving to live infrastructure
    dga_flagged: int = 0                   # resolving + DGA/entropy attack signature
    near_miss: Optional[BrandCandidate] = None
    samples: list[BrandCandidate] = Field(default_factory=list)

    @property
    def present(self) -> bool:
        return self.candidates_generated > 0 or self.near_miss is not None


# ---------------------------------------------------------------------------
# Annotation-lake labels (the DuckLake `v_annotated` row for the domain)
# ---------------------------------------------------------------------------
#
# The dnsproject live scan attaches the DuckLake (Neon catalog + `datazag-lake`
# R2 data), reads the per-domain `v_annotated` (or a report-tailored view) row,
# and drops it into the live-scan output as `output["annotation"]`. This is the
# AUTHORITATIVE source for mailbox / nameserver / hosting providers, infra-risk
# labels, and the detected platform stack — it supersedes the renderer-side
# regex fingerprinting (now a fallback) and resolves the MX-over-TXT priority at
# source. Every field is optional: when the block is absent (snapshot-only runs,
# older scans) the renderer falls back to the medallion + technographics.

class PlatformSignal(_Base):
    """One detected-platform signal from the annotation lake (a tech-fingerprint
    row). `match_type` records HOW it was detected — mx / cname / spf / txt / ns /
    regdom / host — which sets evidence strength; `confidence` is the lake's own
    0.0–1.0 score (>= 0.7 ⇒ rendered as 'confirmed')."""
    provider: str = ""
    category: str = ""
    signal_type: str = ""          # SPF_INCLUDE | TXT | MX | ...
    match_type: str = ""           # the fingerprint match (exact | suffix | regex)
    confidence: float = 0.0
    evidence: str = ""

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data):
        # Lake columns can be NULL; drop them so field defaults apply.
        return {k: v for k, v in data.items() if v is not None} if isinstance(data, dict) else data

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_conf(cls, v):
        return _clamp01(v)


class Annotation(_Base):
    """Flat per-domain labels from the annotation lake's `v_annotated` view,
    delivered as `output["annotation"]`. Authoritative for providers/labels;
    renderer fingerprinting is the fallback when this is absent."""
    domain: str = ""
    # mailbox / email
    mailbox_provider: Optional[str] = None
    mailbox_category: Optional[str] = None
    mailbox_role: Optional[str] = None
    # nameserver
    ns_provider: Optional[str] = None
    ns_category: Optional[str] = None
    # hosting / cloud
    cloud_provider: Optional[str] = None
    cloud_class: Optional[str] = None
    hosting_provider: Optional[str] = None
    hosting_class: Optional[str] = None
    is_fronted: bool = False
    # hosting network facts (lake fallback when the medallion is sparse)
    asn: Optional[int] = None
    asn_name: Optional[str] = None
    isp_country: Optional[str] = None
    prefix: Optional[str] = None
    # risk labels
    asn_risk_level: Optional[str] = None
    tld_risk_level: Optional[str] = None
    is_parked: bool = False
    # trust labels
    trust_label: Optional[str] = None
    hosting_trust: Optional[str] = None
    mailbox_trust: Optional[str] = None
    # detected platform stack (tech-fingerprint signals)
    platform_signals: list[PlatformSignal] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data):
        # The lake emits NULL for absent labels; drop them so bool/str defaults
        # apply (e.g. is_parked NULL → False) instead of failing validation.
        return {k: v for k, v in data.items() if v is not None} if isinstance(data, dict) else data

    @property
    def present(self) -> bool:
        """True when the lake returned usable labels for this domain."""
        return bool(
            self.mailbox_provider or self.ns_provider or self.cloud_provider
            or self.hosting_provider or self.trust_label or self.platform_signals
        )


# ---------------------------------------------------------------------------
# View-model (what the renderers consume)
# ---------------------------------------------------------------------------

class TrustSurface(BaseModel):
    """Defensibility / how well-run the estate is (higher score = worse)."""
    score: int = 0                       # 0..100
    grade: TrustGrade
    # email
    dmarc_risk: bool = False
    spf_risk: bool = False
    modern_security_present: bool = False
    mx_type: str = "unknown"
    mx_risk_score: float = 0.0
    # routing integrity
    asn: int = 0
    prefix: Optional[str] = None
    isp: Optional[str] = None
    isp_country: Optional[str] = None
    asn_risk_level: str = "unknown"
    rpki_state: str = "unknown"
    is_manrs_member: bool = False
    manrs_status: str = "Unknown"
    is_manrs_culprit: bool = False
    moas_detected: bool = False
    prefixes_churn_total: int = 0

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ThreatSurface(BaseModel):
    """Compromise / hosting-neighbourhood exposure (higher score = worse)."""
    score: int = 0                       # 0..100
    grade: TrustGrade
    infra_score: float = 0.0
    ip_direct_threat_score: float = 0.0
    fast_flux_risk: float = 0.0
    dga_risk: float = 0.0
    concentration_risk: float = 0.0
    certstream_risk: float = 0.0
    dangling_cname_risk: float = 0.0
    is_dangling_cname: bool = False
    cname_target: Optional[str] = None
    certstream_hits: int = 0
    listed_feeds: list[str] = Field(default_factory=list)
    pivot_findings: list[PivotFinding] = Field(default_factory=list)
    historical_velocity: HistoricalVelocity = Field(default_factory=HistoricalVelocity)
    reason_codes: list[str] = Field(default_factory=list)
    # weaponization verdict (gold.scenario_weaponization) + tld reputation
    is_live: bool = False
    weaponization_score: int = 0
    threat_intent: Optional[str] = None
    evasion_tactic: Optional[str] = None
    tld_risk_level: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ExternalThreat(BaseModel):
    """Platform-impersonation surface: imitations of the platforms the company uses.

    `total_*` cover PLATFORM impersonations only — own-brand lookalikes are a
    distinct surface (outbound / customer-facing) and are always reported
    separately via `own_brand`, never folded into the platform totals.
    """
    detected_platforms: list[str] = Field(default_factory=list)
    # EXACT certstream matches — drive the headline.
    impersonations: list[PlatformImpersonation] = Field(default_factory=list)
    own_brand: BrandExposure = Field(default_factory=BrandExposure)
    # FUZZY typosquat candidates (rollup *_typosquat kinds) — lower confidence,
    # rendered as a separate "lookalike candidates" section, never in the headline.
    lookalike_candidates: list[PlatformImpersonation] = Field(default_factory=list)
    own_brand_lookalikes: BrandExposure = Field(default_factory=BrandExposure)
    # Active-scan brand funnel (FREE health report). Brand-scoped by construction;
    # never sourced from platform-global impersonation data.
    brand_funnel: BrandFunnel = Field(default_factory=BrandFunnel)

    @property
    def total_7d(self) -> int:
        return sum(i.count_7d for i in self.impersonations)

    @property
    def total_30d(self) -> int:
        return sum(i.count_30d for i in self.impersonations)

    @property
    def lookalike_total_30d(self) -> int:
        return sum(i.count_30d for i in self.lookalike_candidates)

    @property
    def has_lookalikes(self) -> bool:
        return bool(self.lookalike_total_30d or self.own_brand_lookalikes.count_30d)


# --- Report enrichment models (live DNS + DuckLake; surfaced into the view-model) ---

class Registration(_Base):
    """Registration facts — intel.domain_rdap (fallback gold.dns_wide)."""
    registrar: Optional[str] = None
    registered_date: Optional[str] = None
    expires_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    dnssec: bool = False
    status: Optional[str] = None
    rdap_risk_score: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data):
        return {k: v for k, v in data.items() if v is not None} if isinstance(data, dict) else data


class DnsHygiene(_Base):
    """Rich DNS/email hygiene from the live scan (celery DNSRecords) — the detail
    behind the medallion's boolean risk flags (the report's hygiene page)."""
    spf_record: Optional[str] = None
    spf_strict: bool = False
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dkim_present: bool = False
    dnssec: bool = False
    mta_sts_mode: Optional[str] = None
    tlsrpt_present: bool = False
    bimi_present: bool = False
    caa_present: bool = False
    tls_issuer: Optional[str] = None
    tls_days_left: Optional[int] = None
    has_security_txt: bool = False

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data):
        return {k: v for k, v in data.items() if v is not None} if isinstance(data, dict) else data


class AbuseContacts(_Base):
    """Remediation routing — intel.tld_registrar_abuse_contacts / asn_abuse_contacts."""
    registrar_abuse_email: Optional[str] = None
    registrar_abuse_url: Optional[str] = None
    asn_abuse_email: Optional[str] = None
    asn_abuse_phone: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data):
        return {k: v for k, v in data.items() if v is not None} if isinstance(data, dict) else data


class DnsRecordSet(_Base):
    """Raw resolved DNS records for the report's Full-DNS-records section — sourced
    from the live celery rec (NOT the lake). Carried on the contract so the renderer
    reads records from the package instead of a side-channel `legacy` dict."""
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)    # "pref host" display strings
    ns: list[str] = Field(default_factory=list)
    caa: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)


class ReportViewModel(BaseModel):
    domain: str
    generated_at: Optional[str] = None
    data_freshness: dict[str, str] = Field(default_factory=dict)
    has_intelligence: bool = True
    composite_score: int = 0             # 0..100, higher = worse
    grade: TrustGrade
    trust: TrustSurface
    threat: ThreatSurface
    external_threat: ExternalThreat = Field(default_factory=ExternalThreat)
    findings: list[dict] = Field(default_factory=list)
    # DuckLake/live-DNS enrichment (authoritative; renderer reads these, not legacy)
    annotation: Annotation = Field(default_factory=Annotation)
    registration: Registration = Field(default_factory=Registration)
    hygiene: DnsHygiene = Field(default_factory=DnsHygiene)
    abuse: AbuseContacts = Field(default_factory=AbuseContacts)
    dns_records: DnsRecordSet = Field(default_factory=DnsRecordSet)
    # Live CT-log subdomain observations (CertSpotter) — list of dicts with
    # dns_name / is_expired / days_remaining / issuer_category / source.
    subdomains: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

# Weighted trust failures → 0..1 penalty. Weights are the v1 calibration.
_TRUST_WEIGHTS = {
    "dmarc_risk": 0.25,
    "spf_risk": 0.12,
    "no_modern_email": 0.13,
    "rpki_invalid": 0.20,
    "rpki_unknown": 0.08,
    "not_manrs": 0.05,
    "moas": 0.20,
    "manrs_culprit": 0.20,
}


def _trust_penalty(di: DomainIntelligence) -> float:
    es, rt, fa = di.email_security, di.routing, di.facts
    p = 0.0
    if es.dmarc_risk:
        p += _TRUST_WEIGHTS["dmarc_risk"]
    if es.spf_risk:
        p += _TRUST_WEIGHTS["spf_risk"]
    if not es.modern_security_present:
        p += _TRUST_WEIGHTS["no_modern_email"]
    if rt.rpki_state == "invalid":
        p += _TRUST_WEIGHTS["rpki_invalid"]
    elif rt.rpki_state == "unknown":
        p += _TRUST_WEIGHTS["rpki_unknown"]
    if not fa.is_manrs_member:
        p += _TRUST_WEIGHTS["not_manrs"]
    if rt.moas_detected:
        p += _TRUST_WEIGHTS["moas"]
    if fa.is_manrs_culprit:
        p += _TRUST_WEIGHTS["manrs_culprit"]
    return min(1.0, p)


def _threat_score01(di: DomainIntelligence) -> float:
    """Worst-of the infra sub-scores, floored when active threat-feed listings or
    live malicious certificate issuance are present (those are categorical, severe)."""
    base = di.risk_assessment.worst_subscore()
    if di.threat_feeds.listed_feeds():
        base = max(base, 0.85)
    if di.certstream.hits > 0:
        base = max(base, 0.70)
    if di.domain_dns_facts.is_dangling_cname:
        base = max(base, 0.70)
    return min(1.0, base)


# ---------------------------------------------------------------------------
# Teaser-tier redaction
# ---------------------------------------------------------------------------
# The teaser edition is a lead-gen artefact: grades, pillar scores, and headline
# counts stay visible; the specifics a buyer pays for (lookalike domains,
# co-tenant examples, evidence, remediation steps) are redacted HERE, on the
# view-model, so they never reach the teaser HTML/PDF source at all.

TEASER_REDACTED = "Included in the full report."


def _mask_domain(domain: str) -> str:
    """Mask a domain to a non-actionable hint: first 3 chars + TLD.
    'micros0ft-365-login.com' -> 'mic•••••.com'"""
    d = (domain or "").strip()
    if "." not in d:
        return d[:3] + "•••••" if d else d
    stem, _, tld = d.rpartition(".")
    return f"{stem[:3]}•••••.{tld}"


def redact_for_teaser(vm: ReportViewModel) -> ReportViewModel:
    """Return a deep copy of the view-model with paid-tier specifics removed.

    Kept:    grades, pillar scores, all counts, finding titles/severities.
    Masked:  impersonating/lookalike domains (first 3 chars + TLD).
    Removed: finding evidence/detail/remediation, co-tenant examples,
             dangling CNAME target.
    """
    t = vm.model_copy(deep=True)

    for imp in t.external_threat.impersonations + t.external_threat.lookalike_candidates:
        imp.sample_domains = [_mask_domain(d) for d in imp.sample_domains]
    for be in (t.external_threat.own_brand, t.external_threat.own_brand_lookalikes):
        be.sample_domains = [_mask_domain(d) for d in be.sample_domains]

    # Brand funnel: counts + the single highlighted near-miss survive (they ARE
    # the free report's demonstration); other generated candidate domains are masked.
    bf = t.external_threat.brand_funnel
    near = bf.near_miss.domain if bf.near_miss else None
    for c in bf.samples:
        if c.domain != near:
            c.domain = _mask_domain(c.domain)

    for pf in t.threat.pivot_findings:
        pf.examples = []
    if t.threat.cname_target:
        t.threat.cname_target = _mask_domain(t.threat.cname_target)

    t.findings = [
        {
            **f,
            "evidence": TEASER_REDACTED,
            "detail": TEASER_REDACTED,
            "remediation": TEASER_REDACTED,
        }
        for f in t.findings
    ]
    return t


def build_view_models(
    di: DomainIntelligence,
    detected_platforms: Optional[list[str]] = None,
    impersonations: Optional[list[PlatformImpersonation]] = None,
    own_brand: Optional[BrandExposure] = None,
    findings: Optional[list[dict]] = None,
    lookalike_candidates: Optional[list[PlatformImpersonation]] = None,
    own_brand_lookalikes: Optional[BrandExposure] = None,
    brand_funnel: Optional[BrandFunnel] = None,
    annotation: Optional[Annotation] = None,
    registration: Optional[Registration] = None,
    hygiene: Optional[DnsHygiene] = None,
    abuse: Optional[AbuseContacts] = None,
    weaponization: Optional[dict] = None,
    dns_records: Optional[DnsRecordSet] = None,
    subdomains: Optional[list[dict]] = None,
) -> ReportViewModel:
    """Compose the renderer view-model from the medallion payload + impersonation data
    + DuckLake/live-DNS enrichment (annotation/registration/hygiene/abuse/weaponization)."""
    detected_platforms = detected_platforms or []
    impersonations = impersonations or []
    own_brand = own_brand or BrandExposure()
    lookalike_candidates = lookalike_candidates or []
    own_brand_lookalikes = own_brand_lookalikes or BrandExposure(confidence="lookalike")
    brand_funnel = brand_funnel or BrandFunnel()
    annotation = annotation or Annotation()
    registration = registration or Registration()
    hygiene = hygiene or DnsHygiene()
    abuse = abuse or AbuseContacts()
    dns_records = dns_records or DnsRecordSet()
    subdomains = subdomains or []
    weaponization = weaponization or {}

    external = ExternalThreat(
        detected_platforms=detected_platforms,
        impersonations=impersonations,
        own_brand=own_brand,
        lookalike_candidates=lookalike_candidates,
        own_brand_lookalikes=own_brand_lookalikes,
        brand_funnel=brand_funnel,
    )

    if not di.has_intelligence:
        # NXDOMAIN / error → "not yet assessed" state, no false all-clear.
        unknown = score_to_grade(None)
        return ReportViewModel(
            domain=di.domain or "",
            generated_at=di.generated_at,
            data_freshness=di.data_freshness,
            has_intelligence=False,
            composite_score=0,
            grade=unknown,
            trust=TrustSurface(score=0, grade=unknown),
            threat=ThreatSurface(score=0, grade=unknown),
            external_threat=external,
            findings=findings or [],
            annotation=annotation,
            registration=registration,
            hygiene=hygiene,
            abuse=abuse,
            dns_records=dns_records,
            subdomains=subdomains,
        )

    trust01 = _trust_penalty(di)
    threat01 = _threat_score01(di)
    composite = round(100 * (0.65 * threat01 + 0.35 * trust01))

    trust = TrustSurface(
        score=round(100 * trust01),
        grade=score_to_grade(round(100 * trust01)),
        dmarc_risk=di.email_security.dmarc_risk,
        spf_risk=di.email_security.spf_risk,
        modern_security_present=di.email_security.modern_security_present,
        mx_type=di.email_security.mx_type,
        mx_risk_score=di.email_security.mx_risk_score,
        asn=di.facts.asn,
        prefix=di.facts.prefix,
        isp=di.facts.isp,
        isp_country=di.facts.isp_country,
        asn_risk_level=di.facts.asn_risk_level,
        rpki_state=di.routing.rpki_state,
        is_manrs_member=di.facts.is_manrs_member,
        manrs_status=di.facts.manrs_status,
        is_manrs_culprit=di.facts.is_manrs_culprit,
        moas_detected=di.routing.moas_detected,
        prefixes_churn_total=di.routing.prefixes_churn_total,
    )
    threat = ThreatSurface(
        score=round(100 * threat01),
        grade=score_to_grade(round(100 * threat01)),
        infra_score=di.risk_assessment.infra_score,
        ip_direct_threat_score=di.risk_assessment.ip_direct_threat_score,
        fast_flux_risk=di.risk_assessment.fast_flux_risk,
        dga_risk=di.risk_assessment.dga_risk,
        concentration_risk=di.risk_assessment.concentration_risk,
        certstream_risk=di.risk_assessment.certstream_risk,
        dangling_cname_risk=di.risk_assessment.dangling_cname_risk,
        is_dangling_cname=di.domain_dns_facts.is_dangling_cname,
        cname_target=di.domain_dns_facts.cname_target,
        certstream_hits=di.certstream.hits,
        listed_feeds=di.threat_feeds.listed_feeds(),
        pivot_findings=di.concentration.pivot_findings,
        historical_velocity=di.historical_velocity,
        reason_codes=di.risk_assessment.reason_codes,
        is_live=bool(weaponization.get("is_live", False)),
        weaponization_score=int(weaponization.get("weaponization_score") or 0),
        threat_intent=weaponization.get("threat_intent"),
        evasion_tactic=weaponization.get("evasion_tactic"),
        tld_risk_level=annotation.tld_risk_level,
    )
    return ReportViewModel(
        domain=di.domain,
        generated_at=di.generated_at,
        data_freshness=di.data_freshness,
        has_intelligence=True,
        composite_score=composite,
        grade=score_to_grade(composite),
        trust=trust,
        threat=threat,
        external_threat=external,
        findings=findings or [],
        annotation=annotation,
        registration=registration,
        hygiene=hygiene,
        abuse=abuse,
        dns_records=dns_records,
        subdomains=subdomains,
    )
