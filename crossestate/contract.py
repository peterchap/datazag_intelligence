"""
crossestate/contract.py
-----------------------
The typed estate data model — the cross-estate analogue of
`intelligence_contract.ReportViewModel`. Mirrors its Pydantic conventions
(`_Base(extra="ignore")`, explicit defaults so partial estates degrade instead
of raising).

Hierarchy (the spec's three levels):

    EstateViewModel  (the GROUP / the buyer)
      └─ Segment     (the grouping dimension — customer tag or inferred)
           └─ DomainRef → ReportViewModel  (the per-domain contract, unchanged)

The analytics blocks (`concentration`, `correlated_weakness`, `variance`,
`exposure`, `calendar`) are deterministic aggregations computed by
`crossestate/analytics.py`; the `exceptions` register is rule-based
(`crossestate/exceptions.py`). `completeness` is the §2.1 stub.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from intelligence_contract import ReportViewModel


class _Base(BaseModel):
    # Ignore unknown keys so the estate contract never breaks on additive change,
    # matching intelligence_contract._Base.
    model_config = ConfigDict(extra="ignore")


# ---------------------------------------------------------------------------
# Thresholds — defaults here; customer-tunable via estate_run.py --thresholds
# ---------------------------------------------------------------------------

class EstateThresholds(_Base):
    """Calibration for the flag rules. Carried on the EstateViewModel so a
    render/JSON consumer can see exactly which thresholds produced the flags."""
    # §2.2 — a single provider covering more than this share of the estate is a
    # concentration flag ("if X falls, Y% of estate affected").
    concentration_flag_pct: float = 0.30
    # §2.3 — a weakness present on more than this share (estate or within a
    # segment) is "systemic", not isolated.
    systemic_weakness_pct: float = 0.50
    # §2.4 — a segment whose median grade is this many A–F bands below the estate
    # baseline is an outlier (the acquired-subsidiary-below-parent signal).
    variance_outlier_bands: int = 2
    # §2.5 — the top targeted platform holding more than this share of estate
    # exposure is a targeting-concentration flag.
    exposure_concentration_pct: float = 0.50
    # §2.6 — calendar horizons (days).
    cert_expiring_days: int = 30
    domain_expiring_days: int = 60


# ---------------------------------------------------------------------------
# §2.2 Concentration & accumulation
# ---------------------------------------------------------------------------

class ProviderShare(_Base):
    provider: str
    count: int = 0
    pct: float = 0.0                 # 0..1 of the domains with a known value here
    flagged: bool = False            # this provider alone exceeds the threshold


class ConcentrationDim(_Base):
    dimension: str                   # mailbox | ns | registrar | asn | hosting | ca_issuer
    label: str = ""
    shares: list[ProviderShare] = Field(default_factory=list)
    top_provider: Optional[str] = None
    top_pct: float = 0.0             # == "if the top provider falls, this share of the estate is affected"
    denom: int = 0                   # domains carrying a known value for this dimension
    flagged: bool = False            # top_pct >= thresholds.concentration_flag_pct


# ---------------------------------------------------------------------------
# §2.3 Correlated weakness
# ---------------------------------------------------------------------------

class WeaknessPrevalence(_Base):
    control: str                     # dmarc | spf | dnssec | caa | internal_ip_leak | dangling_subdomain
    label: str = ""
    n_affected: int = 0
    n_assessed: int = 0
    pct: float = 0.0                 # 0..1 across the assessed estate
    per_segment: dict[str, int] = Field(default_factory=dict)        # segment -> affected
    per_segment_total: dict[str, int] = Field(default_factory=dict)  # segment -> assessed
    systemic: bool = False           # estate-wide pct >= systemic threshold
    systemic_segments: list[str] = Field(default_factory=list)       # segments at/over the threshold
    remediation: str = ""            # class-level fix (used by the oversight fixable-weakness rollup)


# ---------------------------------------------------------------------------
# §2.4 Posture variance / drift / M&A gap
# ---------------------------------------------------------------------------

class ScoreStats(_Base):
    count: int = 0
    mean: float = 0.0
    median: float = 0.0
    min: int = 0
    max: int = 0
    grade: str = "?"                 # grade of the median score


class SegmentPosture(_Base):
    segment: str
    stats: ScoreStats = Field(default_factory=ScoreStats)
    grade_distribution: dict[str, int] = Field(default_factory=dict)
    is_outlier: bool = False
    bands_below_baseline: int = 0    # positive == worse than the estate baseline


class VarianceBlock(_Base):
    estate_baseline_score: float = 0.0
    estate_baseline_grade: str = "?"
    per_segment: list[SegmentPosture] = Field(default_factory=list)
    grade_distribution: dict[str, int] = Field(default_factory=dict)
    outlier_segments: list[str] = Field(default_factory=list)
    unassessed: int = 0              # domains with has_intelligence=False (excluded from baseline)


# ---------------------------------------------------------------------------
# §2.5 Active exposure rollup (EXACT impersonation only)
# ---------------------------------------------------------------------------

class TargetedPlatform(_Base):
    platform: str
    count_7d: int = 0
    count_30d: int = 0
    targeted_domains: int = 0        # estate domains seeing this platform impersonated
    sample_domains: list[str] = Field(default_factory=list)


class ExposureRollup(_Base):
    total_7d: int = 0
    total_30d: int = 0
    by_platform: list[TargetedPlatform] = Field(default_factory=list)
    by_segment: dict[str, int] = Field(default_factory=dict)        # segment -> count_30d
    sample_domains: list[str] = Field(default_factory=list)
    targeting_concentration: float = 0.0                            # top platform share of total_30d
    # Lower-confidence typosquat candidates — carried PARALLEL, never summed into
    # the totals (mirrors the single-report headline discipline).
    lookalike_total_30d: int = 0


# ---------------------------------------------------------------------------
# §2.6 Operational calendar
# ---------------------------------------------------------------------------

class CalendarItem(_Base):
    domain: str
    segment: str = ""
    kind: str                        # domain_expiry | unlocked | cert_expiring | cert_expired | missed_renewal
    date: Optional[str] = None
    days_left: Optional[int] = None  # negative == overdue
    severity: str = "info"
    detail: str = ""


class CalendarBlock(_Base):
    items: list[CalendarItem] = Field(default_factory=list)
    next_30d: int = 0
    next_90d: int = 0
    overdue: int = 0


# ---------------------------------------------------------------------------
# §2.1 Estate completeness — STUB (see crossestate/discovery.py)
# ---------------------------------------------------------------------------

class CompletenessBlock(_Base):
    available: bool = False          # True only when a real DiscoveryProvider ran
    declared_n: int = 0
    discovered_n: int = 0
    delta: list[dict] = Field(default_factory=list)        # orphan/shadow domains (owned lane)
    candidates: list[dict] = Field(default_factory=list)   # low-confidence, held separate
    note: str = ""


# ---------------------------------------------------------------------------
# Exception register — rule-based, finding-dict-shaped (see findings_rules.py)
# ---------------------------------------------------------------------------

class EstateException(_Base):
    finding: str
    severity: str                    # critical | high | elevated | medium | low | info
    title: str
    evidence: str = ""
    detail: str = ""
    remediation: str = ""            # suppressed from the oversight human render (never from JSON)
    category: str = ""
    scope: str = "estate"            # estate | segment | domain
    members: list[str] = Field(default_factory=list)       # affected segments/domains


# ---------------------------------------------------------------------------
# The estate hierarchy
# ---------------------------------------------------------------------------

class DomainRef(BaseModel):
    """One domain in the estate: its resolved segment + the loaded per-domain
    view-model. `vm` is an arbitrary (Pydantic) type from another module."""
    domain: str
    segment: str
    segment_source: str = "supplied"     # supplied | inferred:<signal> | default
    segment_disagreement: bool = False   # supplied tag disagrees with inference
    vm: ReportViewModel
    contract_path: Optional[str] = None
    load_error: Optional[str] = None     # non-fatal load failure; counted, not assessed

    model_config = ConfigDict(arbitrary_types_allowed=True)


class Segment(BaseModel):
    key: str
    n_domains: int = 0
    domains: list[DomainRef] = Field(default_factory=list)
    posture: SegmentPosture = Field(default_factory=lambda: SegmentPosture(segment=""))

    model_config = ConfigDict(arbitrary_types_allowed=True)


class EstateViewModel(BaseModel):
    """The complete cross-estate payload. `model_dump()` is the JSON feed
    (always complete); the human render selects/suppresses via a CutConfig."""
    group: str
    generated_at: Optional[str] = None
    thresholds: EstateThresholds = Field(default_factory=EstateThresholds)

    domain_count: int = 0            # rows in the manifest
    assessed_count: int = 0          # vms with has_intelligence
    declared_n: int = 0              # domains the customer declared (== manifest rows)

    estate_score: int = 0            # mean composite over assessed domains (0..100, higher=worse)
    estate_grade: str = "?"
    grade_distribution: dict[str, int] = Field(default_factory=dict)

    segments: list[Segment] = Field(default_factory=list)

    concentration: list[ConcentrationDim] = Field(default_factory=list)
    correlated_weakness: list[WeaknessPrevalence] = Field(default_factory=list)
    variance: VarianceBlock = Field(default_factory=VarianceBlock)
    exposure: ExposureRollup = Field(default_factory=ExposureRollup)
    calendar: CalendarBlock = Field(default_factory=CalendarBlock)
    completeness: CompletenessBlock = Field(default_factory=CompletenessBlock)
    exceptions: list[EstateException] = Field(default_factory=list)

    model_config = ConfigDict(arbitrary_types_allowed=True)
