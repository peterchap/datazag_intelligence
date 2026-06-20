# Brand-Funnel — Producer Contract (`output["brand_funnel"]`)

**Status:** Consumer built (datazag branch `claude/nifty-shirley-f9c066`); producer to wire on the dnsproject scan.
**Companion to:** [brand_page_data_contract.md](brand_page_data_contract.md) — that doc defines *what may be read*; this doc defines *the JSON the report consumes*.

The free Health Report's brand page (variant `health`, always `--tier teaser`) renders the active-scan funnel from a single typed block, `BrandFunnel`. It is computed **by the dnsproject live scan** — where pattern generation, `gold.dns_wide`, `events.certstream_events`, `intel.domain_rdap` and the DGA cross-check all live — and carried in the scan output as `output["brand_funnel"]`, exactly like `output["annotation"]`. The report has no DuckDB / lake access; the must-not-read columns simply never appear in this block.

## Where it's produced / consumed

- **Producer:** the dnsproject scan (`scripts/compile_intelligence.py`) sets `output["brand_funnel"]` from the active-scan computation (pattern-gen → corpus resolution → DGA cross-check → passive certs → near-miss + monitored flag).
- **Consumer:** `report_pipeline.build_view_model` reads `live_output["brand_funnel"]` → `BrandFunnel.model_validate(...)` → `vm.external_threat.brand_funnel`. Absent → the report renders the empty-state framing (§6 of the data contract). Never fatal.

## Block JSON (maps 1:1 to `intelligence_contract.BrandFunnel`)

```jsonc
{
  "monitored": false,            // true only if a registered brand_id exists (paid Watch active)
  "candidates_generated": 120,   // §3.1 pattern generation total
  "checked": 50,                 // how many were resolution-checked (the priority cap, e.g. 50)
  "registered": 8,               // of checked: resolving OR parked (gold.dns_wide)
  "resolving": 3,                // of checked: resolving to live infra (has_a / has_mx)
  "dga_flagged": 1,              // of resolving: DGA/entropy attack signature (gold.scenario_domain_intel.dga_risk)
  "near_miss": {                 // the single highlighted example; null if none
    "domain": "qbeurope.com",
    "status": "nxdomain",        // generated | nxdomain | parked | resolving
    "registered": false
  },
  "samples": [                   // a handful of generated candidates (report shows up to 8)
    {
      "domain": "qbe-support.com",
      "status": "resolving",
      "registered": true,
      "has_a": true,
      "has_mx": false,
      "domain_age_days": 12,     // via intel.domain_rdap; null if unknown
      "dga_risk": 0.0,           // 0..1; clamped report-side
      "has_cert": true,          // passively-observed cert ONLY (events.certstream_events); never triggers a fetch
      "priority": 1
    }
  ]
}
```

All fields optional — omit any the producer can't yet supply; the report defaults them. Unknown extra keys are ignored.

## Invariants the producer MUST honour (from the data contract)

1. **Brand-scoped only.** Never populate any field from `ref.platform_impersonation` (platform-global — the "157" bug). `monitored`/retrospective history come from the customer's `brand_id` brand-match layer; the funnel comes from report-time pattern-gen + cheap corpus resolution.
2. **Cheap-only.** Never include capture-derived columns (`scenario_weaponization.*`, `served_content/served_form_fields/served_brand_assets`). `has_cert` is the *passive* "a cert was already observed" flag — it must not trigger a page fetch.
3. **Cost cap.** Resolve at most the top-N candidates by priority (recommended 50); report the remainder via `candidates_generated > checked` (the report renders "top N checked, remainder generated but not yet resolved").

## Open algorithmic decisions for the producer (data contract §8)

- **Brand-stem derivation** — how candidate stems come from the domain (apex label minus TLD? curated per known brand?).
- **Pattern families** — typo / omission / homoglyph / hyphen / vertical-context / curated-TLD, each with a priority rank.
- **DGA threshold** — which `gold.scenario_domain_intel.dga_risk` value counts as an "attack signature" for `dga_flagged`.
- **Near-miss selection** — the single forward-looking example (e.g. highest-priority NXDOMAIN-but-registrable).

## Consumer wiring (already built)

- `report_pipeline.build_view_model` reads `live_output["brand_funnel"]`.
- `vm.external_threat.brand_funnel` (typed `BrandFunnel`); `redact_for_teaser` keeps counts + the near-miss, masks other sample domains.
- `HealthReportRenderer._build_brand_funnel()` renders the page; `_assert_brand_not_platform()` is the §7 guard.
