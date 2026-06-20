# Brand-Funnel Endpoint — Producer Contract

**Status:** Consumer built (datazag branch `claude/nifty-shirley-f9c066`); producer to wire on riskscore.
**Companion to:** [brand_page_data_contract.md](brand_page_data_contract.md) — that doc defines *what may be read*; this doc defines *the JSON the report consumes*.

The free Health Report's brand page (variant `health`, always `--tier teaser`) renders the active-scan funnel from a single typed block, `BrandFunnel`, fetched over HTTP from a new riskscore endpoint. The report has **no DuckDB / lake access** — all of §3/§4 of the data contract runs producer-side, and the must-not-read columns simply never appear in this payload.

## Endpoint

```
GET /brand-funnel?domain=<domain>
Auth: X-Datazag-Key  (same as /intelligence and /platform-impersonations)
```

The report calls this best-effort: any non-200 / timeout → empty funnel → the report renders the **empty-state framing** (§6 of the data contract). Never fatal.

## Response JSON (maps 1:1 to `intelligence_contract.BrandFunnel`)

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

## Invariants the endpoint MUST honour (from the data contract)

1. **Brand-scoped only.** Never populate any field from `ref.platform_impersonation` (platform-global — the "157" bug). `monitored`/retrospective history come from the customer's `brand_id` brand-match layer; the funnel comes from report-time pattern-gen + cheap corpus resolution.
2. **Cheap-only.** Never include capture-derived columns (`scenario_weaponization.*`, `served_content/served_form_fields/served_brand_assets`). `has_cert` is the *passive* "a cert was already observed" flag — it must not trigger a page fetch.
3. **Cost cap.** Resolve at most the top-N candidates by priority (recommended 50); report the remainder via `candidates_generated > checked` (the report renders "top N checked, remainder generated but not yet resolved").

## Consumer wiring (already built)

- `intelligence_client.fetch_brand_funnel(domain)` → `BrandFunnel` (empty on failure).
- `report_pipeline.build_view_model` fetches it and threads it into `build_view_models(..., brand_funnel=...)` → `vm.external_threat.brand_funnel`.
- `HealthReportRenderer._build_brand_funnel()` renders the funnel page; `_assert_brand_not_platform()` is the §7 guard (raises if a brand count equals a platform-global total with no brand-scoped evidence).
