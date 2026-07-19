# Kids Planet run — what the reports actually found

*2026-07-19. 25 domains, collected via `estate_collect.py --local --no-certs`
(live DNS + medallion + lake/RDAP enrichment; CT-log cert intel skipped — see
below). Graded against [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md), which was
recorded from direct observation BEFORE any report ran.*

Estate result: **grade C (30/100)**, 25/25 assessed, 10 exceptions.

## What worked

**Systemic weakness detection.** DMARC not enforced on 23/25 (92%), CAA missing
25/25, DNSSEC absent 25/25. Accurate, and exactly the "one fix, whole estate"
finding the correlated-weakness analytic exists to produce.

**Concentration.** Fasthosts 59% of registrars (22 known), AS39572 Advanced
Hosting 40% of the ASN spread (25 known). Both real and both material — a single
registrar holding 59% of an acquired estate is a genuine operational risk.

**Calendar — the standout.** Real dates, correctly ranked:

| domain | event | date | days |
|---|---|---|---|
| `gigglesandwiggles.co.uk` | domain expiry | 2026-07-21 | **1** |
| `carringtondaynursery.co.uk` | domain expiry | 2026-08-13 | 24 |
| `kinderhaven.co.uk` | domain expiry | 2026-08-23 | 34 |
| `thelearningjourneynursery.co.uk` | domain expiry | 2026-09-17 | 59 |

Plus 10+ domains with **no registrar lock**. A nursery-brand domain expiring in
one day, unnoticed, is precisely the diligence finding that justifies the
product — and it is exactly the takeover-window class `remediation.py` already
ranks as Fix 1.

**Variance computed cleanly**: acquired n=15 median 31, core n=3 median 32,
legacy n=7 median 28, against a 30.0 baseline.

## What it missed — all nine ground-truth defects

| domain | observed defect | in register? |
|---|---|---|
| `poppyandjacks.co.uk` | live M365 MX, dead website | ✗ |
| `wavertondaynurseries.co.uk` | live Google MX, dead website | ✗ |
| `thehunnypot.co.uk` | still on seller's hosting/mail | ✗ |
| `tiptoes.co.uk` | expired TLS certificate | ✗ (certs off) |
| `lindenhousedaynursery.co.uk` | TLS misconfiguration | ✗ (certs off) |
| `lawleyvillagedaynursery.co.uk` | registrar parking page | ✗ |
| `gigglesandwiggles.co.uk` | registrar parking page | ✗ (caught via expiry) |
| `highbanknursery.co.uk` | registrar parking page | ✗ |
| `earlybirdsdaynursery.co.uk` | registrar parking page | ✗ |

Two are fair — cert intel was disabled. The other seven are the finding.

**The register describes patterns, never problems.** Every entry is estate-level
("92% lack DMARC", "Fasthosts holds 59%"). Not one names a specific broken
domain. A buyer's question is "what did we acquire and what's wrong with it?" —
the report answers "your estate has systemic DMARC weakness."

**Root cause: the contract carries configuration, not operational state.**
`poppyandjacks.co.uk` has `mx_type=unknown` despite live Microsoft 365 MX
records, so "live mail on a dead brand" is invisible. Nothing in the contract
records whether the site *responds at all*, or whether it serves a parking page.
Those are the three highest-value diligence signals in this estate and none is
representable in the current model.

## Two defects to fix before this is shown to a customer

**1. The impersonation rollup is wrong by ~3 orders of magnitude.**
`exposure.total_30d = 15,638` for a 25-domain nursery group. The per-domain
finding reads *"70 lookalike domains impersonating Microsoft 365 (30d)"* — that
is the global count of lookalikes targeting **Microsoft 365**, not Kids Planet.
Summed across 25 domains it becomes a 15,638-impersonation headline. It leads
the exception register at `high`. In front of a client this is a credibility
event, not a rounding error.

**2. Concentration percentages hide their denominators.**
"GoDaddy handles **100%** of the estate's nameserver / DNS provider" is computed
over `denom=5` — five of 25 domains had a resolved `ns_provider`. Likewise "aws
handles 100% of hosting provider" over `denom=3`. Both render as `high`-severity
single points of failure. They should either state coverage ("100% of the 5
domains where the provider is known — 20% of the estate") or be suppressed below
a coverage threshold. As written they overstate, which is the failure direction
that matters.

## The neglect paradox — worth a product decision

The `legacy` segment (parked, superseded brands) scored a **better** median (28)
than `acquired` (31) and `core` (32). Neglect scores well: a dead domain has no
mail to misconfigure, no services to expose, less surface to be wrong about.

For M&A this inverts the signal. The domains a buyer should worry about most
grade best. Any materiality or ranking work on the diligence cut has to account
for this, or the report will systematically point the buyer away from the
neglected tail — which is the whole reason they commissioned it.

## Coverage limits of this run

- **`--no-certs`.** CertSpotter's free tier rate-limits by sleeping (321s, 359s
  observed per domain), so it blocks rather than degrades. Cost: no CA-issuer
  concentration, no certificate expiry, no cross-domain-SAN discovery.
- **`events.certstream_events` cannot substitute yet.** 4,016,737 rows, but
  `san_domains` is NULL in **every** row (the ingest never maps it, though
  `san_count` is populated), and the data is a 3-day seed (28–30 May 2026) with
  zero overlap with these 25 domains. Two fixable gaps — populate `san_domains`
  in the ingest, and wire the live landing prefix — after which it replaces
  CertSpotter for issuer breakdown and expiry at minimum.
- **Mailbox concentration is always empty** — `mx_type` is `unknown` on every domain,
  so that dimension never populates.
- Reporting snapshot is dated 26 May, ~8 weeks stale.
