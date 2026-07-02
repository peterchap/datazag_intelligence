# Cross-Estate Domain Risk Report (v2.2) — handover

*Written 2026-07-02. The paid-tier report built to `cross_estate_report_build_spec_1.md`
(v2.2) from the reference render `cross_estate_v2.html`. It fulfils the free
report's page-5 seam (discovery + systemic risk) in the same visual grammar.*

## What this is

A design-continuous **6 core pages + Appendix A** print report. It is a
**transformation over the committed `crossestate` MVP** — the MVP's manifest
loader, segment resolver and five deterministic analytics are reused UNCHANGED;
this package adds the v2.2 layers and the design-continuous renderer. Nothing in
`crossestate/` or `freereport/` is mutated (the earlier "fresh build alongside"
decision).

## Module map (`estatereport/`)

| file | role |
|---|---|
| `resilience.py` | §4a resilience model: `ref.provider_resilience` (starter in-repo table) + the share×tier severity matrix. Share stays uncoloured; resilience drives HIGH/ELEVATED/WATCH. Unknown → commodity + "not assessed". |
| `contract.py` | v2.2 Pydantic models (EstateReport + discovery/concentration/variance/correlated/calendar/exceptions/remediation). |
| `discovery.py` | 4-tier discovery interface + `NullDiscoveryProvider` (declared-only + honest "not enabled" note; structure never disappears). |
| `transform.py` | enriches the MVP analytics into v2.2 shapes (resilience join, severity, MX-masking, variance, correlated `segment_isolated`, calendar, exposure, grade). |
| `exceptions2.py` | exception collapse to 5–7 (correlated → one entry; concentration → one entry; `collapsed_from`). |
| `remediation.py` | Appendix A worksheet: pattern-grouped, dedup on `pattern_id`, admin-point-ordered, tier-priced (baseline=Now/advanced=Soon/gold=Maturity), recovery is Fix 1. |
| `build.py` | orchestrates: MVP estate → enrich → EstateReport + cover composition. |
| `renderer.py` | `EstateReportRenderer` + `ESTATE_TEMPLATE` (CSS verbatim from `cross_estate_v2.html`) + to_html/markdown/json. |
| `../estate_report_run.py` | CLI. |

## The §4a model (the point of the report)

Severity is resilience-weighted, not share-thresholded. Verified worked contrast:
**Let's Encrypt 75% (hyperscale CA) → WATCH** vs **GoDaddy 62% (commodity
registrar, high exit) → HIGH**. The biggest bar is not the biggest finding. Rules
implemented: share ≥ 50% always registers (tier sets severity); `exit_friction=high`
bumps one level at ≥ 50%; `surface_diversity_masking` bumps one level and leads.
The bar renders neutral (cyan-deep); the severity PILL carries the colour.

## Editorial rules honoured (spec §3 + acceptance checklist)

Discovery leads (page 2), four tiers render even when disabled; grade scope stated;
exception register ≤ 7 with `collapsed_from`; impersonation exact-only with the
`confidence = "exact"` provenance line; corpus = single constant `340M`; severity
vocab HIGH/ELEVATED/WATCH; worksheet priorities from maturity tiers (no BIMI/MTA-STS
at Now); recovery/lock work is Fix 1; `Now:` strings are formatted evidence, never
raw field names.

## Verify

- Local: `python tests/test_estate_report_v2.py` (15 tests — §4a matrix, collapse,
  worksheet, discovery, render). Full family: 53 tests across free + estate MVP + v2.2.
- End-to-end: `python estate_report_run.py --manifest tests/fixtures/estate/manifest.json
  --skip-pdf` → `output/estate/<group>/estate_report.{html,md,json}`.
- Visual fidelity verified via static-server screenshots (page 3 concentration/severity
  pills + variance; Appendix A worksheet). **PDF (Playwright) verified on the master.**
- jinja2 lazy-imported; local env has pydantic (jinja pip-installed to verify HTML).

## Not yet built (real discovery)

`NullDiscoveryProvider` is the stub. The real `DiscoveryProvider` needs the 340M
corpus + Companies House CRN + connected-domain inference (SAN/MX-SPF/redirect/
registrar/NS/lexical) producing the four tiers with evidence + the active check
(DNS → website → CV/screenshot) for the hostile/ambiguous lanes. When it lands it
drops in behind the same interface; page 2 (funnel, tiers, disc-table, deltas) and
the concentration pre/post-discovery deltas populate automatically.
