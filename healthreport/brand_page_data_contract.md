# Brand Page — Data Contract (Free Health Report)

**Status:** Draft for engineering review
**Scope:** The brand-impersonation page(s) of the *free* Datazag Health Report only. The paid Brand Impersonation Watch and the flagship/detailed reports are out of scope except where this document defines the free→paid boundary.
**Purpose:** Define exactly which data-lake columns the free brand page may read, which it must never read, where the cost boundary sits, and how empty states are handled — so the renderer is wired to real columns and the platform-vs-brand conflation cannot recur.

---

## 1. The two bugs this contract exists to prevent

**Bug 1 — platform/brand conflation (the "157").**
`ref.platform_impersonation` is a *reference* table keyed by `platform` (e.g. "Google Workspace"). Its `impersonating_domains` column is a **global** count of domains impersonating that platform across the entire corpus. It is **not** customer- or brand-specific. The flagship cover appears to have read this value and presented it as the customer's brand-lookalike count. For QBE — whose one detected platform is Google Workspace — this surfaced a global Google Workspace figure as if it were QBE brand impersonation.

**Rule:** The brand page must **never** read `ref.platform_impersonation.impersonating_domains` (or `.hits`) into any brand-level claim. That table feeds the *platform* page only. Brand claims come exclusively from the brand-matching layer defined in §3.

**Bug 2 — capture cost on free reports.**
Weaponization detection (fetching the suspected page, screenshotting, classifying credential-capture forms and brand assets) has a real per-domain cost. It is run for paying brand-alert customers on their monitored patterns. It must **not** be triggered by free-report generation.

**Rule:** The free brand page must not read any capture-dependent column (§4) in a way that triggers a fetch, and must not present per-domain weaponization verdicts. It may *describe* the capability as part of the paid-tier pitch.

---

## 2. The free→paid boundary

| Layer | Cost to produce | Free report | Paid Watch |
|---|---|---|---|
| Pattern generation | Compute only | ✅ shows | ✅ |
| DNS resolution state | DNS lookup (cheap, capped) | ✅ shows | ✅ |
| DGA / entropy cross-check | Compute only | ✅ shows | ✅ |
| Certificate existence (passive) | Free when already observed | ✅ shows if present | ✅ |
| Continuous certstream matching | Infra (always-on) | ❌ describes only | ✅ delivers |
| Weaponization capture | Real per-domain cost | ❌ describes only | ✅ delivers |
| Takedown intelligence | Derived, but tied to monitored set | ❌ describes only | ✅ delivers |

The boundary is the **cost line**: the free tier gives away what is cheap to produce; the paid tier delivers what is expensive to produce. No artificial gating.

---

## 3. What the free brand page READS

### 3.1 Pattern generation (to be built)
Input: brand stem(s) derived from the report's domain (e.g. `qbe`, `qbeeurope`).
Output: ranked candidate set — typo-squats, single-char omissions, homoglyph variants, hyphenated lures, vertical-context patterns, curated-TLD variants. Each candidate carries a priority rank.

This is the script described in conversation. It is pure computation; no cost.

### 3.2 Resolution state — corpus first, then capped live resolve
For each candidate, **check `gold.dns_wide` first** (already-collected, zero marginal cost):

| Column | Use |
|---|---|
| `domain` / `apex` | match the candidate |
| `is_parked` | parked vs active |
| `resolution_status` | resolving / NXDOMAIN / other |
| `has_a`, `has_mx` | live infrastructure indicators |
| `registered_date` (via `intel.domain_rdap`) | how new the registration is |
| `domain_age_days` | recency signal — newly registered lookalikes are higher risk |
| `tls_issuer`, `tls_not_before` | certificate exists (free when already in corpus) |

For candidates **not** found in `gold.dns_wide`: live-resolve the **top N by priority only** (recommended cap: 50). Remaining candidates are reported as "generated, not yet checked." Rationale: caps cost and avoids mass-resolution that could resemble reconnaissance scanning.

### 3.3 DGA / entropy cross-check
| Table.column | Use |
|---|---|
| `gold.scenario_domain_intel.dga_risk` | flag resolving candidates whose string carries algorithmic-generation signature |

Used as a **confidence cross-check** on candidates that resolved — not as a pre-resolution filter (well-designed brand lookalikes look natural to a DGA classifier, so filtering pre-resolution would discard real threats).

### 3.4 Certificate existence (passive, free when present)
| Table.column | Use |
|---|---|
| `events.certstream_events.primary_domain` / `san_domains` | a cert was already observed for this candidate |
| `events.certstream_events.not_before` / `ca_issuer` | when, by whom |

Only read when the candidate already appears in `certstream_events` from normal passive collection. **Do not** trigger any fetch. If absent, the candidate simply has no observed cert — not an error.

### 3.5 The funnel the free page renders
From the above, the free brand page presents an honest point-in-time funnel:

```
N candidate patterns generated
  → X registered (resolving or parked)
    → Y resolving to live infrastructure
      → Z carrying DGA/entropy attack signature
```

Plus the single highlighted **near-miss** (e.g. `qbeurope.com` — NXDOMAIN today, registrable now) as the concrete forward-looking example.

---

## 4. What the free brand page MUST NOT READ

These are **paid-tier / capture-dependent** and must not be read by the free renderer, nor presented as per-domain verdicts:

| Table.column | Why excluded |
|---|---|
| `gold.scenario_weaponization.weaponization_score` | capture-derived |
| `gold.scenario_weaponization.threat_intent` | capture-derived |
| `gold.scenario_weaponization.evasion_tactic` | capture-derived |
| `gold.scenario_weaponization.is_live` (weaponization sense) | capture-derived |
| `events.certstream_events.served_content` | requires page fetch |
| `events.certstream_events.served_form_fields` | requires page fetch |
| `events.certstream_events.served_brand_assets` | requires page fetch |
| `alerts.composite_alerts.delivery_payload` | paid alerting only |
| `ref.platform_impersonation.impersonating_domains` | **platform-global, not brand — the 157 bug** |
| `ref.platform_impersonation.hits` | platform-global, not brand |

The free page may **describe** the weaponization and takedown capabilities (§5) as the paid-tier differentiator, in prose — but must not surface any per-domain value from these columns.

---

## 5. What the free page DESCRIBES (paid-tier pitch, prose only)

The free brand page closes by describing what Brand Impersonation Watch adds — sourced from these capabilities, described generically, **no per-domain data**:

- **Continuous detection:** new lookalike certs matched within 5–10s via `events.certstream_events` passive matching against the customer's registered `brand_id`.
- **Weaponization verdict:** for each live lookalike, whether it serves a credential-capture form using the brand's assets (`served_form_fields`, `served_brand_assets`, `weaponization_score`, `threat_intent`).
- **Takedown intelligence:** for the hosting ASN, `intel.asn_intel.median_takedown_hours` and `abuse_responsive` — how long takedown typically takes and whether the host acts.

These are capability descriptions that justify the subscription. They are true of the system; they are not run for the free prospect.

---

## 6. Empty-state handling (the QBE case today)

QBE has **no registered `brand_id`** and is **not** monitored. Therefore `events.certstream_events` has no rows with a QBE `matched_brand_id`, and there is no retrospective brand-lookalike history to show.

The free brand page in this state must:

1. **Not** fabricate a count, and **not** borrow `ref.platform_impersonation` figures.
2. Render the **active-scan funnel** from §3 (pattern generation + capped resolution + DGA cross-check) — this works for any domain regardless of monitoring status, because it generates and checks candidates at report time.
3. Lead with the **forward-looking framing**: "Brand monitoring is not yet active for your domain. Here is the candidate attack surface we generated and checked at report time — and here is what continuous monitoring would add."
4. Highlight the **near-miss** example.
5. Describe the paid Watch (§5).

This is the honest Option-C framing: the free report demonstrates live capability via the active scan, not retrospective monitoring the prospect never consented to.

---

## 7. Renderer guard (must implement)

A hard guard in the renderer:

```
IF data source for any brand-level count == ref.platform_impersonation:
    RAISE — platform-global data may not populate a brand claim.
```

And a smoke test asserting that a domain with no `matched_brand_id` rows renders the empty-state funnel (§6), never a non-zero retrospective lookalike count.

---

## 8. Open items for engineering

1. **Pattern generation script** — owner + location in pipeline (report-time function vs. pre-computed job). Determines candidate-set size and priority ranking.
2. **Corpus-first resolution** — confirm `gold.dns_wide` lookup by candidate is fast enough at report time; confirm the live-resolve cap (proposed 50).
3. **DGA threshold** — what `gold.scenario_domain_intel.dga_risk` value constitutes "attack signature" for display purposes.
4. **Brand stem derivation** — how the report derives stems from the input domain (apex minus TLD? curated per known brand? both?).
5. **Confirm the 157 root cause** — verify `ref.platform_impersonation` has a Google Workspace row ≈157 and that `events.certstream_events` has zero QBE `matched_brand_id` rows, to close the investigation definitively.
