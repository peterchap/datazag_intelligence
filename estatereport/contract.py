"""
estatereport/contract.py
------------------------
Typed data model for the Cross-Estate Domain Risk Report (v2.2). Pydantic (the
repo convention; the spec's @dataclass sketches are illustrative). The renderer
BINDS these — it computes nothing analytic (grades, shares, severities, collapse
groupings all arrive populated, same principle as the free report's maturity tiers).

Severity vocabulary is the register's own: HIGH / ELEVATED / WATCH (never
critical/medium/low), matching the free-report priority family.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore")


Severity = Literal["high", "elevated", "watch"]
Tier = Literal["declared", "strong", "possible", "defensive"]


# ── Discovery (§2 page 2, §4 EstateDiscovery) ────────────────────────────────

class Evidence(_Base):
    kind: str                          # san | mx_spf | redirect | registrar | ns | crn | txt | lexical | aftermarket
    detail: str


class DiscoveredDomain(_Base):
    domain: str
    tier: Tier
    evidence: list[Evidence] = Field(default_factory=list)
    registrant_matches: Optional[bool] = None
    available_for_registration: Optional[bool] = None   # defensive tier
    linked_to: list[str] = Field(default_factory=list)  # declared domains that surfaced it


class EstateDiscovery(_Base):
    enabled: bool = False              # False → render the 4-tier model with declared-only + a note
    declared_count: int = 0
    total_found: int = 0               # every row across all four tiers (not a headline number)
    # The HEADLINE: declared + strongly associated — the estate we stand behind and
    # grade. Possible and defensive rows are listed but never counted as estate.
    estate_count: int = 0
    tiers: dict[str, list[DiscoveredDomain]] = Field(default_factory=dict)
    note: str = ""

    def tier_count(self, t: str) -> int:
        return len(self.tiers.get(t, []))


# ── Estate grade (§4 EstateGrade) ────────────────────────────────────────────

class EstateGrade(_Base):
    grade: str = "?"
    score: float = 0.0                 # 0–100, higher = worse
    domain_count: int = 0              # graded estate size (declared + strong)
    distribution: dict[str, int] = Field(default_factory=dict)   # grade → count


def share_text(n: int, N: int) -> str:
    """A share always travels with its denominator: "55% (6 of 11)"."""
    pct = round(n / N * 100) if N else 0
    return f"{pct}% ({n} of {N})"


# ── Concentration (§4/§4a) ───────────────────────────────────────────────────

class Concentration(_Base):
    dimension: str                     # registrar | mailbox | ns | asn | hosting | ca_issuer
    label: str
    provider: str
    share_post_discovery: float
    share_pre_discovery: Optional[float] = None   # None when discovery didn't run
    # The share's own denominator, carried so it is never rendered without it:
    # n = domains on the top provider, N = domains with a known value for this
    # dimension (dimensions differ: registrar may be known on 9, mailbox on 11).
    n: int = 0
    N: int = 0
    known_count: int = 0
    # resilience join (§4a)
    resilience_tier: str = "commodity"
    exit_friction: str = "medium"
    resilience_assessed: bool = False
    severity: Optional[Severity] = None            # None → row renders with tier context, no pill
    recommendation: str = ""
    surface_diversity_masking: bool = False
    bar_class: str = ""                            # "" | warm | hot — colour lives on the pill, bar mostly neutral

    @property
    def share_label(self) -> str:
        return share_text(self.n, self.N)


# ── Variance (§4 SegmentVariance) ────────────────────────────────────────────

class SegmentVariance(_Base):
    segment: str
    domain_count: int
    median_grade: str
    # Signed grade bands against the estate baseline, as a reader says it:
    # +1 = one band ABOVE (better), -2 = two bands below (worse), 0 = at baseline.
    # (crossestate's bands_below_baseline has the opposite sign.) Outlier if <= -2.
    bands_vs_baseline: int = 0

    @property
    def vs_baseline_label(self) -> str:
        b = self.bands_vs_baseline
        if b == 0:
            return "baseline"
        return f"{'+' if b > 0 else '−'}{abs(b)} band{'s' if abs(b) != 1 else ''}"
    outlier: bool = False


# ── Correlated weakness (§4) ─────────────────────────────────────────────────

class CorrelatedWeakness(_Base):
    control: str
    label: str
    affected: int
    estate_size: int
    pct: float
    segments: list[str] = Field(default_factory=list)
    segment_isolated: bool = False     # clean elsewhere → "one standard, two segments"
    hot: bool = False                  # red bar (high-severity control), else warn

    @property
    def share_label(self) -> str:
        return share_text(self.affected, self.estate_size)


# ── Active exposure (§4 / §2 page 4) ─────────────────────────────────────────

class PlatformLookalikes(_Base):
    """One imitated platform: its internet-wide 30-day total, shown ONCE, plus a few
    example lookalike domains. The total is about the platform, not this estate."""
    platform: str
    total_30d: int
    samples: list[str] = Field(default_factory=list)


class Exposure(_Base):
    # ONE total: distinct new lookalike domains of the estate's platforms, 30 days,
    # internet-wide, exact certificate matches. None when the counts could not be
    # verified as excluding registry-wildcard names: then no count is rendered at all.
    # (The fuzzy per-domain candidate sum, inflated by estate size, is gone.)
    total_30d: Optional[int] = None
    counts_verified: bool = False
    top_platform: Optional[str] = None
    top_share: float = 0.0             # top platform's share of total_30d (lookalike volume)
    platforms: list[PlatformLookalikes] = Field(default_factory=list)
    # Domains whose impersonation lookup could not RUN. total_30d excludes them
    # entirely, so with this non-empty a 0 is "not checked", not "none found", and a
    # non-zero total is a floor. Carried from ExposureRollup.unchecked_domains.
    unchecked_domains: list[str] = Field(default_factory=list)
    provenance: str = 'external_threat.impersonations · confidence = "exact"'   # JSON-only


# ── Calendar (§4 CalendarItem) ───────────────────────────────────────────────

class CalItem(_Base):
    domain: str
    segment: str = ""
    host: Optional[str] = None         # the name that lapses (domain or certificate hostname)
    item_kind: str
    due: Optional[str] = None          # None → standing
    days_left: Optional[int] = None    # from the report date; negative == overdue
    overdue: bool = False
    detail: str = ""
    due_class: str = "later"           # overdue | soon | later


# ── Exception register (§4 Exception_) ───────────────────────────────────────

class Exception_(_Base):
    rank: int
    # "info" is for context that is not a risk to this estate (platform-wide counts).
    severity: Literal["high", "elevated", "watch", "info"]
    title: str
    body_html: str = ""
    # JSON-only audit trail (internal field names, counts). Never rendered: a
    # reader sees body_html; an analyst reading the export sees where it came from.
    provenance: str = ""
    collapsed_from: Optional[str] = None   # JSON-only, e.g. "correlated_weakness × 6"


# ── Appendix A — remediation worksheet (§2b) ─────────────────────────────────

class RemediationEntry(_Base):
    domain: str
    segment: str = ""
    admin_point: str                   # zone host / registrar account — batching + ticket key
    now: str                           # formatted evidence string, never a raw field name
    fix: str                           # staged next step, not the end state


DOMAIN_TOKEN = "{domain}"


class RecordLine(_Base):
    """One line of a DNS / registrar change. Plain text, never markup: the renderer
    escapes it, so placeholders like <your-ca> survive instead of being eaten as
    tags. `{domain}` is substituted with a real domain at render (`for_domain`)."""
    kind: Literal["comment", "record"] = "record"
    text: str

    def for_domain(self, domain: str) -> "RecordLine":
        return RecordLine(kind=self.kind, text=self.text.replace(DOMAIN_TOKEN, domain))


class RemediationPattern(_Base):
    pattern_id: str                    # 1:1 with the control (dedup key)
    title: str
    why_html: str = ""
    priority: Literal["now", "soon", "plan"]        # from the maturity tier
    record_lines: list[RecordLine] = Field(default_factory=list)   # the fx-cmd block, written once

    def records_for(self, domain: str) -> list[RecordLine]:
        """The record block with `{domain}` filled in for one real domain."""
        return [ln.for_domain(domain) for ln in self.record_lines]

    @property
    def example_domain(self) -> Optional[str]:
        """The domain the main report shows the block for: the first entry."""
        return self.entries[0].domain if self.entries else None
    end_state: Optional[str] = None                 # e.g. "p=reject once rua confirms senders"
    entries: list[RemediationEntry] = Field(default_factory=list)
    overflow: int = 0                               # rows beyond the per-pattern cap


# ── The report ───────────────────────────────────────────────────────────────

class AdminPoint(_Base):
    key: str                           # zone host / registrar
    name: str
    detail: str = ""


# ── Entities (Phase 2: one record per company in the estate, plus the owner) ──

class Owner(_Base):
    name: str
    domain: str


class SubdomainSummary(_Base):
    """Hostnames OBSERVED IN CERTIFICATE TRANSPARENCY, not a live inventory."""
    source: str = "observed in certificate transparency"
    count: int = 0
    notable: list[str] = Field(default_factory=list)   # auth/login/admin/staging/dev/demo/vpn/api…


class SaasPlatform(_Base):
    provider: str
    category: str = ""
    evidence: str = ""                 # MX / SPF include / CNAME — never an ownership token


class EmailGateway(_Base):
    provider: str
    kind: Literal["gateway", "mailbox"]
    category: str = ""


class CertIssue(_Base):
    host: str
    kind: str                          # cert_expiring | cert_expired
    due: Optional[str] = None
    days_left: Optional[int] = None


class BrandLookalike(_Base):
    domain: str
    confidence: float
    signals: list[str] = Field(default_factory=list)


class BrandLookalikes(_Base):
    label: str
    total_matches: int = 0             # exact-label registrations after ownership exclusions
    active_matches: int = 0            # of those, at or above the confidence threshold
    shown: list[BrandLookalike] = Field(default_factory=list)


class DomainRecord(_Base):
    """One declared domain of an entity. The free tier reads only the primary
    domain's record; paid reads them all."""
    domain: str
    primary: bool = False
    assessed: bool = True
    not_assessed_reason: Optional[str] = None
    grade: Optional[str] = None
    score: Optional[float] = None
    controls: dict[str, str] = Field(default_factory=dict)   # vocab: estatereport/controls.py
    findings: list[str] = Field(default_factory=list)        # gaps, urgency order
    subdomains: SubdomainSummary = Field(default_factory=SubdomainSummary)
    saas: list[SaasPlatform] = Field(default_factory=list)
    email_gateway: Optional[EmailGateway] = None
    cert_issues: list[CertIssue] = Field(default_factory=list)


class LinkedDomain(_Base):
    domain: str
    tier: str                          # strong (owned, corroborated)
    evidence: list[Evidence] = Field(default_factory=list)


class Entity(_Base):
    name: str
    primary_domain: str
    role: str = "portfolio"            # owner | portfolio | insured | client
    domains: list[str] = Field(default_factory=list)          # declared domains
    assessed: bool = True              # primary domain assessed
    grade: Optional[str] = None        # the PRIMARY domain's grade
    score: Optional[float] = None
    prev_grade: Optional[str] = None   # set when a prior run exists
    controls: dict[str, str] = Field(default_factory=dict)    # primary domain, 7 controls
    top_issue: Optional[str] = None                           # primary domain
    records: list[DomainRecord] = Field(default_factory=list) # every declared domain, primary first
    # Attack surface across ALL declared domains (union of the records).
    subdomains: SubdomainSummary = Field(default_factory=SubdomainSummary)
    saas: list[SaasPlatform] = Field(default_factory=list)
    email_gateway: Optional[EmailGateway] = None
    cert_issues: list[CertIssue] = Field(default_factory=list)
    # None = not measured (no corpus index); an empty list would claim "none found".
    brand_lookalikes: Optional[BrandLookalikes] = None
    linked_domains: list[LinkedDomain] = Field(default_factory=list)
    insurer_signals: dict = Field(default_factory=dict)

    @property
    def primary_record(self) -> Optional["DomainRecord"]:
        return next((r for r in self.records if r.primary), self.records[0] if self.records else None)


class CorpusInfo(_Base):
    """Corpus size read live from the Observatory (`corpus_domains`)."""
    domains: int
    label: str                         # "364M"
    as_of: str = ""


class EstateReport(_Base):
    group: str
    generated_at: Optional[str] = None
    # Live from the Observatory; None when it is unreachable, and every sentence that
    # quotes the corpus size is then left out. Never a hard-coded figure.
    corpus: Optional[CorpusInfo] = None
    # Entity model (Phase 2). The owner's record has role "owner"; it is never part
    # of the estate grade, distribution or concentration.
    owner: Optional[Owner] = None
    entities: list[Entity] = Field(default_factory=list)
    peer_cohort: Optional[dict] = None                 # open question 1: null for now
    # How derived fields were produced (rules, thresholds), for the analyst reading JSON.
    provenance: dict[str, str] = Field(default_factory=dict)
    # page 1
    synthesis_html: str = ""
    dash: list[dict] = Field(default_factory=list)     # 4 cover cards {cls,key,state,note}
    lens_html: str = ""
    scope_caveat: str = ""
    # page 2
    discovery: EstateDiscovery = Field(default_factory=EstateDiscovery)
    grade_scope_note: str = ""
    # page 3
    grade: EstateGrade = Field(default_factory=EstateGrade)
    concentration: list[Concentration] = Field(default_factory=list)
    variance: list[SegmentVariance] = Field(default_factory=list)
    baseline_grade: str = "?"
    vanity_mx_note: str = ""
    # page 4
    correlated: list[CorrelatedWeakness] = Field(default_factory=list)
    exposure: Exposure = Field(default_factory=Exposure)
    # page 5
    calendar: list[CalItem] = Field(default_factory=list)
    exceptions: list[Exception_] = Field(default_factory=list)
    # page 6 — continuity (mostly static copy in the renderer)
    # appendix A
    admin_points: list[AdminPoint] = Field(default_factory=list)
    remediation: list[RemediationPattern] = Field(default_factory=list)
    appendix_pages: int = 1

    def core_pages(self) -> int:
        return 6
