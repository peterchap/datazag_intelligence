"""TeaserViewModel — the WU20 teaser data contract (doc §Pipeline)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from scopeteaser.bands import PriceBand

MAX_PROOF_DOMAINS = 3
TEASER_TTL_DAYS = 30


@dataclass
class ProofDomain:
    domain: str
    evidence_line: str              # one-line connection evidence, house canon


@dataclass
class TeaserViewModel:
    declared_count: int
    tier_counts: dict[str, int]     # declared/strong/possible/defensive -> count
    proof_domains: list[ProofDomain] = field(default_factory=list)  # <=3, strong tier ONLY
    band: Optional[PriceBand] = None
    expires: Optional[date] = None
    requested_by: str = ""          # watermark — the teaser carries its origin
    src: Optional[str] = None       # attribution, carried seam -> scope -> checkout/booking

    @property
    def evidenced_count(self) -> int:
        """The M in "You told us N. We can evidence M." — the graded estate."""
        return self.tier_counts.get("declared", 0) + self.tier_counts.get("strong", 0)

    @property
    def delta(self) -> int:
        return self.evidenced_count - self.declared_count
