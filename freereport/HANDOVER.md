# Free Single-Domain report — handover

*Written 2026-07-02. Renderer for the Free Single-Domain Cyber Exposure Report,
built to `free_report_build_spec.md` from the approved prototype
`free_report_v1_3.html`. Reads the existing per-domain `ReportViewModel`; the
per-domain pipeline is unchanged.*

## What this is

A **5-page, fixed** lead-magnet report in the shared Datazag design system. Its
page-5 seam promises the two things a single domain can't show — estate discovery
(four confidence tiers) and systemic risk — which the Cross-Estate Report fulfils
in the same visual grammar.

## Module map (`freereport/`)

| file | role |
|---|---|
| `maturity.py` | the `email_control_maturity` reference as data (baseline/advanced/gold + absent-severity + fix priority). Enforces the house rule: **only baseline gaps are negatives.** |
| `compose.py` | pure `ReportViewModel → context`: org name, dashboard states, synthesis, insurer lens, confirmed platforms, observed-event line, 3 surfaces, balance, fixes, monitor note, empty-states. |
| `renderer.py` | `FreeReportRenderer` + `FREE_REPORT_TEMPLATE` (Jinja port; CSS **verbatim** from the prototype) + `to_html`/`to_markdown`/`to_dict`. |
| `../free_run.py` | CLI (mirrors `run.py`): `--input_json` (vm dump / medallion) or `--domain` (live). |

## House-style rules enforced (spec §"House style" + Guards)

- Describe the mechanism, hedge the universal — generated copy avoids
  guaranteed/the-only/any-CA (test `test_no_absolute_risk_claims_in_generated_copy`).
- Empty/unknown → explicit honest state ("not determined"), never a blank.
- Only BASELINE email-control gaps are red; advanced/gold render cyan/amber as
  opportunities, never red (`maturity.absent_controls`, colour ≠ bad).
- **Guards:** exact-match impersonation only (lookalikes excluded from the
  headline); ownership-proof TXT tokens (`google-site-verification`, `MS=`) are
  NOT platform evidence (`compose.confirmed_platforms`); no platform-global
  counts bound to a per-domain claim.

## Contract note

Everything the report needs is on `ReportViewModel` (hygiene / registration /
annotation / subdomains / cert_analysis / external_threat / trust). The only
referenced field NOT on the contract is `registration.registrant_org` — the org
name falls back to a cleaned apex, per the spec.

## Verify / conventions

- Local env has **pydantic but not jinja2/playwright** by default (jinja2 was
  installed in the venv to verify HTML; declared in requirements.txt). `to_html`
  imports jinja lazily; `to_markdown`/`to_dict` need neither.
- No pytest locally → `python tests/test_free_report.py` (`_run_all` runner).
  12 tests cover the spec's branch matrix (strong/weak email, no-impersonation,
  Google-Workspace classifier vs token trap, clean domain, null geo) + the guards.
- End-to-end: `python free_run.py --input_json tests/fixtures/free_qbeeurope.json
  --skip-pdf` → `output/qbeeurope_com/free.{html,md,json}`. Visual fidelity to the
  prototype confirmed via a static-server screenshot (cover + page-4 fixes).
  **PDF (Playwright) verified on the master.**
- Preview helper: `.claude/launch.json` runs a static server (`venv` python) for
  screenshotting `output/**/*.html`.

## Next

The Cross-Estate Report v2.2 (`cross_estate_report_build_spec_1.md`) reuses this
design system verbatim — same `:root` tokens, `.page/.runner/.foot`, tier cards,
seam, CTA. Build it next as the paid tier that fulfils the page-5 seam.
