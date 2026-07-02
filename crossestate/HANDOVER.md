# Cross-estate (portfolio) report — handover

*Written 2026-07-02. The Analytics-MVP build of the cross-estate report:
an aggregation layer over the per-domain `ReportViewModel`. The per-domain
pipeline is unchanged.*

## What this is

`crossestate/` consumes N per-domain contracts and computes the findings that
only exist at N>1, then renders an exception-first "summary-of-summaries".
Governing principle: **aggregation, not concatenation** — lead with the
aggregate and the exceptions; per-domain detail is a drill-down appendix.
Findings are rule-based, never LLM-invented (same discipline as the single
report).

Spec: the "Cross-Estate Report Specification" (portfolio product). This build
covers the 5 deterministic analytics (§2.2–2.6); estate completeness (§2.1) and
discovery triage (§2.7) are stubbed (`discovery.NullDiscoveryProvider`) — they
need a 330M-corpus + Companies House CRN + connected-domain infra not in this
repo.

## Data flow

    manifest (JSON/CSV) ──load_manifest──▶ ManifestEntry[]
        └─ load_contract(path) ▶ ReportViewModel   (view-model dump; medallion fallback)
    resolve_segments(tags + inference) ▶ DomainRef[]
    5 analytics ▶ blocks ─▶ EstateViewModel ─▶ derive_estate_exceptions
    CrossEstateRenderer(estate, cut) ▶ to_json / to_markdown / to_html

## Module map

| file | role |
|---|---|
| `contract.py` | `EstateViewModel` + analytics blocks + `EstateThresholds` (Pydantic) |
| `manifest.py` | JSON/CSV manifest loader + `load_contract` (view-model dump / medallion fallback) |
| `segments.py` | `resolve_segments` — supplied tag wins, gaps inferred (apex → ns/registrar/asn), disagreement flagged not overridden |
| `analytics.py` | `compute_concentration / _correlated / _variance / _exposure / _calendar` — pure, defensive |
| `exceptions.py` | `derive_estate_exceptions` — rule-based, finding-dict-shaped |
| `discovery.py` | `DiscoveryProvider` protocol + `NullDiscoveryProvider` (§2.1/§2.7 stub) |
| `cuts.py` | `CutConfig` + `CUTS={operator,oversight}` (mirrors `healthreport/audiences.py`) |
| `renderer.py` | `CrossEstateRenderer` + `CROSS_ESTATE_TEMPLATE` (sibling of `HealthReportRenderer`) |
| `build.py` | `build_estate_view_model` / `build_estate_from_manifest` — the engine |
| `../estate_run.py` | CLI (mirrors `run.py`) |

## The operator | oversight cut

The cut parameterises the HUMAN render only. **JSON is always complete and
cut-independent** (`model_dump`), including per-domain remediation.
- **operator** — leads with the exception register + calendar; per-domain fixes
  shown; appendix = per-domain drill-down.
- **oversight** (insurer/board) — leads with concentration/variance/exposure;
  per-domain fix instructions **suppressed** (liability artefact); appendix =
  **fixable-weakness rollup** ("62% of the estate shares this fixable weakness").
Suppression is render-time (`show_per_domain_fixes`), never mutates the model.

## Verify / conventions

- Local env: **pydantic present, jinja2 + playwright absent** by default
  (jinja2 was installed in the venv during this build to verify HTML; it is a
  declared `requirements.txt` dep). The loader + analytics + build are decoupled
  from the render stack, so they import and test without jinja.
- No pytest locally — each `tests/test_estate_*.py` has a `_run_all()` runner:
  `python tests/test_estate_<x>.py`. Shared builders in `tests/estate_helpers.py`;
  fixture estate in `tests/fixtures/estate/` (manifest + per-domain contracts).
- End-to-end: `python estate_run.py --manifest tests/fixtures/estate/manifest.json
  --cut all --format json,html,markdown [--skip-pdf]`. **PDF (Playwright) verified
  on the master** — same pattern as `run.py`.
- 26 unit tests green: analytics (7), segments (6), manifest (4), exceptions (4),
  cuts (5).

## Next (not in this MVP)

- §2.1/§2.7: a real `DiscoveryProvider` over the corpus + CRN + connected-domain
  inference (owned / hostile / ambiguous lanes + active check).
- The insurer instance = this engine with `SEGMENT=insured` + limit-weighting
  (manifest already carries an optional per-domain `limit`).
- Refresh cadence / drift-delta alerts; MSSP multi-tenancy; customer-tunable
  thresholds beyond the `--thresholds` JSON.
