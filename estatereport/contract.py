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


class EstateDiscovery(_Base):
    enabled: bool = False              # False → render the 4-tier model with declared-only + a note
    declared_count: int = 0
    total_found: int = 0               # declared + strong (the graded estate) ∪ possible ∪ defensive
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


# ── Concentration (§4/§4a) ───────────────────────────────────────────────────

class Concentration(_Base):
    dimension: str                     # registrar | mailbox | ns | asn | hosting | ca_issuer
    label: str
    provider: str
    share_post_discovery: float
    share_pre_discovery: Optional[float] = None   # None when discovery didn't run
    known_count: int = 0
    # resilience join (§4a)
    resilience_tier: str = "commodity"
    exit_friction: str = "medium"
    resilience_assessed: bool = False
    severity: Optional[Severity] = None            # None → row renders with tier context, no pill
    recommendation: str = ""
    surface_diversity_masking: bool = False
    bar_class: str = ""                            # "" | warm | hot — colour lives on the pill, bar mostly neutral


# ── Variance (§4 SegmentVariance) ────────────────────────────────────────────

class SegmentVariance(_Base):
    segment: str
    domain_count: int
    median_grade: str
    bands_below_baseline: int          # outlier if >= 2
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


# ── Active exposure (§4 / §2 page 4) ─────────────────────────────────────────

class ImpRow(_Base):
    domain: str
    target: str
    detail: str
    pattern: str = ""


class Exposure(_Base):
    total_exact: int = 0
    top_platform: Optional[str] = None
    top_share: float = 0.0
    rows: list[ImpRow] = Field(default_factory=list)
    lookalike_total: int = 0           # parallel, never summed into total_exact
    provenance: str = 'external_threat.impersonations · confidence = "exact"'


# ── Calendar (§4 CalendarItem) ───────────────────────────────────────────────

class CalItem(_Base):
    domain: str
    segment: str = ""
    item_kind: str
    due: Optional[str] = None          # None → standing
    overdue: bool = False
    detail: str = ""
    due_class: str = "later"           # overdue | soon | later


# ── Exception register (§4 Exception_) ───────────────────────────────────────

class Exception_(_Base):
    rank: int
    severity: Severity
    title: str
    body_html: str = ""
    evidence_line: str = ""            # monospace provenance
    collapsed_from: Optional[str] = None   # e.g. "correlated_weakness × 6"


# ── Appendix A — remediation worksheet (§2b) ─────────────────────────────────

class RemediationEntry(_Base):
    domain: str
    segment: str = ""
    admin_point: str                   # zone host / registrar account — batching + ticket key
    now: str                           # formatted evidence string, never a raw field name
    fix: str                           # staged next step, not the end state


class RemediationPattern(_Base):
    pattern_id: str                    # 1:1 with the control (dedup key)
    title: str
    why_html: str = ""
    priority: Literal["now", "soon", "plan"]        # from the maturity tier
    record_template: Optional[str] = None           # the fx-cmd block, written once
    end_state: Optional[str] = None                 # e.g. "p=reject once rua confirms senders"
    entries: list[RemediationEntry] = Field(default_factory=list)
    overflow: int = 0                               # rows beyond the per-pattern cap


# ── The report ───────────────────────────────────────────────────────────────

class AdminPoint(_Base):
    key: str                           # zone host / registrar
    name: str
    detail: str = ""


class EstateReport(_Base):
    group: str
    generated_at: Optional[str] = None
    corpus_label: str = "340M"         # single sourced constant (§3.8)
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
