"""WU20 price-band table — the single source consumed by pipeline AND portal.

The portal reads the generated `price_bands.json` (vendored copy checked
against this table by tests) — band logic is never duplicated in TypeScript.

Band boundaries/prices are COMMERCIAL PLACEHOLDERS pending sign-off: Band A is
the WU20 doc's worked example; B–D are seeded for the flow to be testable.
Bands are computed on the graded estate (declared + strongly associated);
possible-tier counts are shown but never banded.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

BANDS_JSON = Path(__file__).resolve().parent / "price_bands.json"

# Partner-discount route: partners (MSSP/ESP/reseller) get band pricing under a
# separate agreement. Surfaced beside the band on the teaser + result page.
PARTNER_DISCOUNT_URL = "https://www.datazag.com/contact?enquiry=partner"


@dataclass(frozen=True)
class PriceBand:
    min_domains: int
    max_domains: Optional[int]        # None -> open-ended top band
    label: str
    from_price_gbp: Optional[int]     # one-off "from" price; None -> priced on confirmation
    from_price_sub_gbp: Optional[int] # subscription (annual, continuous monitoring) "from"
                                      # price; None -> "subscription on request"
    self_serve: bool                  # True -> Stripe checkout; else book-a-call


# One-off boundaries + prices are SIGNED OFF (2026-07-07). Subscription "from"
# prices are pending commercial figures — None renders "subscription on request"
# rather than inventing a number; drop the values in here and regenerate.
BANDS: tuple[PriceBand, ...] = (
    PriceBand(1, 15, "Band A", 3500, None, True),
    PriceBand(16, 50, "Band B", 7500, None, False),
    PriceBand(51, 150, "Band C", 15000, None, False),
    PriceBand(151, None, "Band D", None, None, False),
)


def band_for(graded_count: int) -> PriceBand:
    for band in BANDS:
        if graded_count >= band.min_domains and (band.max_domains is None or graded_count <= band.max_domains):
            return band
    return BANDS[0]


def band_range_label(band: PriceBand) -> str:
    """e.g. 'Band A · up to 15 domains · from £3,500' (the WU20 teaser format)."""
    if band.max_domains is None:
        size = f"{band.min_domains}+ domains"
    else:
        size = f"up to {band.max_domains} domains"
    price = f"from £{band.from_price_gbp:,}" if band.from_price_gbp else "priced on scope confirmation"
    return f"{band.label} · {size} · {price}"


def band_subscription_label(band: PriceBand) -> str:
    """The subscription (continuous monitoring) line shown under the one-off."""
    if band.from_price_sub_gbp:
        return f"or from £{band.from_price_sub_gbp:,}/year with continuous monitoring"
    return "continuous-monitoring subscription available on request"


def export_json() -> str:
    return json.dumps([asdict(b) for b in BANDS], indent=2) + "\n"


def main() -> None:
    BANDS_JSON.write_text(export_json(), encoding="utf-8", newline="\n")
    print(f"Wrote {BANDS_JSON}")


if __name__ == "__main__":
    main()
