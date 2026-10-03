# Persona editions — Phase 0 plan

Brief: *Persona editions of the Cross-Estate Domain Risk Report* (Peter, 3 Oct 2026).
Status: **plan for review. No code has changed.**
Branch: `feat/report-editions`, cut from `origin/master` @ `8357b4c`.

---

## 0. Two things found before planning

1. **The local checkout was 15 PRs behind.** `feat/technographic-dimension` (where this
   session started) predates PRs #15–#26, all merged on 2–3 Oct. The baseline fixture
   (`fixtures/cyber-startups/`) was rendered by the newer code: its "platform lookalikes
   (30d, internet-wide)" wording and `info` exception severity exist only on master. All
   work below is planned against `origin/master`.
2. **`feat/certstream-cert-intel` (948f16c) is not merged.** It replaces CertSpotter with
   Datazag's own CT archive on R2 (one query per estate, no 148–358 s rate-limit sleeps).
   Subdomains, certificate issues and cross-domain-SAN discovery all depend on cert intel,
   so the Osney run needs it. **Recommendation:** merge it as its own PR before Phase 6.
   See question Q1.

Test baseline on master: **251 pass, 1 fail.** The failure
(`test_no_licensed_feeds::test_the_source_tree_keeps_no_feed_lookups`) is environmental. It
scans a stale copy of the repo under `.claude/worktrees/competent-sutherland-56ac09/`, not
the code. Fix: exclude `.claude/` from that scan (one line, Phase 1).

---

## 1. Current architecture

```
domains.csv
  └─ estate_collect.py ──────────────── runs on .2 (needs lake + R2; workstation .env has neither)
       phase 1: batched live DNS (canonical_collect → dns_module.DNSFetcher, in-process)
       phase 2: per domain report_pipeline.build_view_model()
                  medallion + lake_enrich (labels, RDAP, platform_signals, impersonation rollup)
                  + cert intel (CertSpotter today; CT archive on the unmerged branch)
       → estates/<x>/contracts/<domain>.json   (ReportViewModel, one per domain)
       → estates/<x>/manifest.json             ({group, domains:[{domain, segment?, contract_path}]})

manifest.json
  └─ crossestate.build.build_estate_view_model()              "the MVP engine"
       load contracts → resolve_segments (infers ns:/reg: segments when none given)
       → analytics: concentration · correlated · variance · exposure · calendar
       → discovery (cert SAN + optional corpus stem-sweep) → EstateViewModel
  └─ estatereport.build.build_estate_report()                 "v2.2"
       transform.*  (resilience join, severity, masking)
       discovery tiers · exceptions2 (collapse) · remediation (Appendix A)
       _synthesis / _dash / _lens  ← cover copy, hard-coded insurer wording
       → EstateReport (pydantic)
  └─ estatereport.renderer.EstateReportRenderer
       to_json  = model_dump
       to_markdown = hand-written, separate logic
       to_html  = ONE Jinja string (ESTATE_TEMPLATE): 6 fixed pages + Appendix A
  └─ estate_report_run.py → output/estate/<group>/estate_report.{json,md,html,pdf}
       PDF = Playwright print of the HTML
```

Where the per-entity data already lives (it is on each contract; nothing aggregates it per
domain today):

| Entity field | Source on `ReportViewModel` | Quality |
|---|---|---|
| grade, score | `grade.letter`, `composite_score` | good |
| controls | `hygiene.{dmarc_policy, spf_record, caa_present, dnssec, mta_sts_mode, bimi_present}`, `registration.{dnssec, status}` | good when the live scan finished; `scan_incomplete` → unknown |
| subdomains | `subdomains[]` (from cert intel) | CT only; archive coverage starts 2026-07-23 |
| saas | `annotation.platform_signals[]` (SPF include / TXT / MX / CNAME fingerprints) + `crossestate/technographic.signals_for` | mailbox/CDN good, SaaS thin (as briefed) |
| email_gateway | `annotation.mailbox_provider` / `mailbox_role`, MX | good |
| cert_issues | `cert_analysis.{expired, expiring_soon, missed_renewals}` | see defect 5 |
| brand_lookalikes | **nothing suitable on the contract.** `external_threat.own_brand` is the rollup's brand kind (watched brands only); `brand_funnel` is the free report's generated-candidate funnel. Needs the corpus index (§4, Phase 2) | to build |
| linked_domains | discovery result (`ConnectedDomainDiscoveryProvider`) | cert SAN works; corpus sweep needs `CORPUS_INDEX_DIR` |
| corpus size | `observatory.py` stat `corpus_domains` (364,175,633 in the 2026-09-08 snapshot) | live, already used by the health report |

---

## 2. Target architecture

One data model, one module library, lenses as config.

```
fixtures/osney/estate.yaml  (owner + entities)
  └─ estate_collect.py --estate estate.yaml        (accepts YAML; writes role into the manifest)
  └─ crossestate (analytics, with Phase 1 fixes; owner excluded from estate aggregates)
  └─ estatereport.build → EstateReport
        + owner, entities[], peer_cohort=None, corpus{size, as_of} | None
        + headlines{}          ← every headline number computed ONCE, here
  └─ editions/                                       NEW package
        lens.py        load + validate report_lenses/<id>.yaml (pydantic)
        modules/       M1–M11, T1: each = accessor(report, lens, tier) → ModuleData | Omitted(reason)
        templates/     base.html.j2 (CSS from ESTATE_TEMPLATE, verbatim) + one partial per
                       module, in HTML and in Markdown
        render.py      compose the pages in lens order → html / md / json / pdf
        tearoff.py     per-entity packs + tearoffs/manifest.json
        checks.py      the acceptance checks (also run as tests)
  └─ edition_run.py --estate … --lens vc --tier free|paid [--entity ploy.io]
report_lenses/vc.yaml · insurer_single.yaml · mssp.yaml
```

Rules the structure enforces:

- **Templates hold no persona wording.** Every string a reader sees comes from the lens
  (`copy`, `glossary`, `severity_map`) or from data. A test loads each template and fails on
  any literal sentence outside an allow-list of structural labels.
- **Renderers bind; they do not compute.** HTML and Markdown read the same `headlines` and
  module data. JSON carries them verbatim, plus `edition: {lens, tier, modules_rendered,
  modules_omitted:[{id, reason}]}`. That is how "HTML, MD, JSON and PDF agree" becomes testable.
- **A module with no data is omitted and logged**, never padded. The omission reason goes
  into the JSON and into REVIEW.md.
- **The existing v2.2 renderer stays working.** `estate_report_run.py` keeps rendering
  until the insurer lens covers what it does, and the Phase 1 data fixes flow into it too.
  Its tests get updated where a fix changes an output on purpose. Retire it in a later PR.
- **`out/` is gitignored.** Only the golden JSON is copied into `tests/fixtures/golden/osney/`.

---

## 3. Phase 1 — where each data fix lands

| # | Fix | Lands in | Test |
|---|---|---|---|
| 1 | `entities[]` | Phase 2 (below) | — |
| 2 | Shared-CDN hosts out of discovery; headline = declared + strong | `crossestate/discovery.py::_cross_domain_sans` filters against a data file `crossestate/shared_platform_suffixes.json` (`sni.cloudflaressl.com`, `cloudflaressl.com`, `cloudfront.net`, `fastly.net`/`fastlylb.net`, `akamaiedge.net`/`edgekey.net`/`akamaized.net`, `azureedge.net`, `herokuapp.com`, `vercel.app`, `netlify.app`, …), matched on the registrable suffix. `estatereport` gets `estate_count = declared + strong`; `total_found` is no longer used for any headline | the fixture's 5 `*.sni.cloudflaressl.com` candidates produce 0 rows; a regex over every rendered output finds no listed suffix |
| 3 | Empty DNS snippets | `estatereport/remediation.py`: `record_template` becomes structured lines `[{kind: comment\|record, text: "_dmarc.{domain}. TXT …"}]`, with no HTML in the data. Substituted per entity at render; any other `<…>` placeholder renders escaped (`&lt;your-ca&gt;`). The main report shows records for the affected domains; tear-offs show only their own | regex over HTML, MD and PDF text: no `_dmarc\.\.`, `@"`, `^\.\s+IN\s+CAA` |
| 4 | Lookalike totals, `.ph` | **Root cause is upstream.** `ref.platform_impersonation` counts are built by riskscore's `compute_platform_impersonation_rollup.py` from raw CT hits, with no per-TLD split, so the report cannot remove `.ph` from a count it never sees broken down. Fix: (a) **riskscore**: exclude a configurable suffix list (`.ph` now, `ref.zone_wildcards` when built) from counts and samples, and stamp `excluded_suffixes` on the rollup; (b) **report**: drop `.ph` samples defensively, and render a platform count **only** when the rollup carries that stamp. Otherwise omit the line and log why. (c) Reconcile: `lookalike_total` sums per-domain fuzzy candidates (so it is inflated by estate size), and it leaves customer output. One total remains: `platform_lookalikes_30d`. (d) The sample table's `detail` column is relabelled "Platform total (30d)" and shown once per platform, not on every sample row | one exposure total in JSON; no `.ph` row; header text matches content. See Q3 |
| 5 | Calendar double-count | `crossestate/analytics.py::_cert_calendar_items`. **Root cause:** dnsproject `CertAnalysis.missed_renewals()` flags `not_after − 60d < today`, which is the same test as `expiring_soon(60)`, so every expiring cert gets a twin. Merge per `dns_name` into one row (`kind=cert_expiring`; `renewal_window_passed` as an attribute). Set `date = not_after` so `due` is populated. Drop rows whose host is wildcard-covered by a newer cert (CertAnalysis does this already; keep it). Domain-expiry/unlock rows stay one per domain | no host twice; every cert row has `due` |
| 5b | (found while planning) **"Expiring soon" is mostly normal ACME renewal.** A 90-day Let's Encrypt cert sits inside 30 days for a third of its life, and the archive has gaps (2026-08-07..15), so a renewed cert can go unseen. Proposal: for short-lived ACME certs, flag only when ≤ 7 days or expired; others at ≤ 30 days. Optionally confirm each flagged host with a live TLS handshake (stdlib `ssl`, 3 s timeout) and drop it if the served cert is newer | see Q5 |
| 6 | Lapses KPI = distinct hosts | `estatereport/build.py::_dash` → reads `headlines.live_lapses_hosts` | KPI == `len({host for overdue∪soon})` |
| 7 | `n of N` on every share | `estatereport/contract.Concentration` gains `n` (top provider count, from `dim.shares[0].count`) and `N` (`dim.denom`); same on correlated rows (already `affected`/`estate_size`). Partials render "6 of 11 (55%)" | every rendered `%` inside a share element has an adjacent `n of N` |
| 8 | Signed variance | `estatereport/contract.SegmentVariance.bands_below_baseline` → `bands_vs_baseline` (signed; crossestate already computes it signed). Renders `+1` / `−1` / `baseline` | Cloudflare segment in the fixture renders `−1`, not "baseline" |
| 9 | Stale/hard-coded text | `corpus_label` removed from the contract; `corpus = {size, as_of}` from `observatory.load().get("corpus_domains")`, formatted (`364M`). If unavailable, the sentence is omitted. `_synthesis/_dash/_lens` wording moves to the lens `copy`. The free report's own "340M" literal (`freereport/renderer.py:491`) gets the same treatment | grep templates and `estatereport/` for `\d{3}M`; no persona string in any `.py` |
| — | Internal field names | `evidence_line` strings (`calendar.overdue × 0`, `external_threat.impersonations · confidence = "exact"`) move to a JSON-only `provenance` field and are never rendered. Segment keys get human labels via one function (`ns:AWS` → "DNS hosted on AWS", `reg:X` → "Registered with X"). In the VC lens the segment column does not render (segments are inferred NS groups; they mean nothing across independent companies) | regex over HTML/MD: no `\b[a-z]+_[a-z_]+\b`-style field tokens from a known list, no `ns:`/`reg:`, no `confidence =` |
| — | Test env | exclude `.claude/` from `test_no_licensed_feeds` | suite green |

---

## 4. Phase 2 — entity model

- **Input.** `estate.yaml` (owner + entities) loads to the same `ManifestEntry` list with
  `role` and `entity` set; CSV manifests keep working (every row is its own `portfolio`
  entity, no owner).
- **Owner.** The owner's contract is collected and graded like any other, but is
  **excluded** from `_assessed()` for every estate aggregate (grade, distribution,
  concentration, correlated, variance, calendar, exposure). It appears only in `owner` +
  its entity record, rendered by M3. Done with one predicate in `crossestate/analytics.py`,
  so no analytic can forget it.
- **`entities[]`** built in a new `estatereport/entities.py`:
  - `controls`: fixed vocabularies, documented in `docs/report-editions/controls.md`.
    Draft:
    `dmarc` reject|quarantine|monitor|missing|invalid ·
    `spf` hardfail|softfail|neutral|permissive|missing ·
    `caa` present|missing · `dnssec` signed|unsigned ·
    `mta_sts` enforce|testing|none|missing · `bimi` present|missing ·
    `registrar_lock` locked|unlocked.
    Plus `unknown` on every control when the scan did not finish. Never a default value.
  - `top_issue`: the first weak control in remediation-urgency order
    (lock → DMARC → SPF → CAA → DNSSEC), as a lens-neutral phrase.
  - `subdomains`: from `vm.subdomains`, labelled "observed in CT". `notable` uses the
    pattern list auth|login|sso|admin|staging|stage|dev|test|demo|vpn|api.
  - `saas` / `email_gateway`: from `platform_signals` + mailbox labels. Ownership-proof
    tokens (`google-site-verification`, `MS=`) do not count as platform evidence (the free
    report's existing house rule).
  - `linked_domains`: discovery `strong` tier attributed to the entity whose cert or infra
    produced it. `possible` stays out of entity records.
  - `brand_lookalikes`: exact-label matches across TLDs from the tailored corpus index
    (`crossestate/corpus_index.py`, `stem_matches(label)`), excluding the entity's own
    linked domains. Each one is scored for confidence (registered < 1y, MX present, cert
    observed, DGA/typosquat signature, NS/MX unrelated to the entity). The top 5 above the
    threshold are shown; the rule is logged in JSON `provenance`. **Named in copy as
    "same-name registrations", not "impersonation".** For labels like *ploy*, *refute* or
    *aisy* most matches will be unrelated businesses, and calling them lookalikes is the
    credibility failure this brief exists to remove. Needs `CORPUS_INDEX_DIR` on the
    collection host (Q2). If it is absent, the field is `null` (not measured), never `[]`.
  - `prev_grade`: `null` until a prior run exists. `insurer_signals`: `{}` until the
    insurer lens needs them.
- `peer_cohort: null`. M5 degrades to portfolio percentages. The Observatory already
  publishes internet-wide control prevalence (`dmarc_enforced`, `caa_present`,
  `dnssec_present`, `mta_sts_enforce`, …, each with its denominator), so M5 could also show
  "portfolio vs the internet" with no cohort. Offered as an option, not assumed.

---

## 5. Phase 3 — lens system

`report_lenses/{vc,insurer_single,mssp}.yaml`, validated by a pydantic `Lens` model, so a
typo in a module id fails at load, not at render. Keys as briefed: `modules`, `tier` rules
per module, `glossary`, `severity_map`, `cover_kpis`, `copy`, `branding`, plus:

- `forbidden_terms`: the acceptance leak check, kept with the lens it protects. Matched
  as whole words or phrases, because a bare `hold` would hit "threshold" and "held for
  review". VC: `underwriter`, `group standard`, `over the hold`, `accumulation risk`.
  Insurer: `portfolio company`.
- `links`: CTA URL, tear-off base URL (`…/t/{token}`), free Health Report URL pattern.

Module ids M1–M11 and T1 as in the brief. Each accessor returns typed data or
`Omitted(reason)`. M2's three takeaways are **deterministic rules over M4–M9 output** (worst
control by prevalence; worst-graded entities; largest correlated exposure), with no LLM.
The fix-effort line stays off until Peter supplies hours.

---

## 6. Phases 4–5 — VC edition and tear-offs

- Free = each entity's `primary_domain` only. Everything beyond it renders as **exact
  counts**. Paid = `entity.domains`.
- **"At least one actionable finding per company."** This comes from the entity's weakest
  primary-domain control, with its record populated. If a company has no gap on its
  primary domain, the rule cannot be met honestly. The tear-off then says so ("no gaps
  found on the website domain"), and REVIEW.md lists the company for Peter. Nothing is
  invented.
- Cover verdict generated from `headlines` (for example "4 of 13 portfolio companies fall
  below the email-security baseline"). The "Active exposure" and discovery KPIs are absent
  from `vc.yaml`'s `cover_kpis`.
- Tear-offs: `out/{owner_slug}/{tier}/tearoffs/{entity_slug}.{pdf,html}` +
  `tearoffs/manifest.json` `[{entity, primary_domain, token, tier, generated_at, url}]`.
  Tokens are `secrets.token_urlsafe(16)` and **idempotent**: a re-render reuses the
  existing token for the same (entity, tier), so links already sent keep working (§10
  hand-off). Built from the entity record only, so another entity's data cannot reach
  it; a test renders all 13 and asserts no foreign domain string appears.
- Remediation order in paid packs: recovery/locks → DMARC → SPF → CAA → DNSSEC (→ MTA-STS
  → BIMI as "maturity").

Output paths: `out/osney/free/`, `out/osney/paid/` exactly as briefed for the VC lens.
Other lenses: `out/osney/insurer_single/`, `out/osney/mssp/` (Q9).

---

## 7. Phase 6 — Osney run

1. `fixtures/osney/estate.yaml` as briefed.
2. Collect on .2 (`estate_collect.py --estate … --local`, CT archive certs, fresh live DNS
   for all 14 domains).
3. Render: VC free, VC paid, insurer single (`--entity ploy.io`), MSSP (placeholder
   white-label: "Your Security Partner", neutral palette, no Datazag mark), tear-offs ×2
   tiers.
4. `editions/checks.py` runs the 14 acceptance items → `out/osney/ACCEPTANCE.md`. The same
   checks run as pytest against the golden JSON.
   - PDF agreement: the PDF is printed from the shipped HTML; the check asserts the bytes
     match and compares extracted PDF text with the HTML headlines (needs `pypdf`, Q6).
   - PDF clipping: Playwright measures every `.page` panel before printing
     (`scrollHeight > clientHeight` or content past the A4 box → fail).
5. Golden JSON → `tests/fixtures/golden/osney/`. `test_golden_osney.py` fails when a
   headline number changes unless the golden is regenerated with a flag.
6. `out/osney/REVIEW.md`: rendered / omitted (with reasons) / counts per module.

---

## 8. Risks

- **Thin estate data for seed-stage companies.** Cyber-startups found 0 owned undeclared
  domains, so paid may cover almost exactly what free covers, and M7 may be mostly zeros.
  That is honest and fine, but the paid upgrade will look smaller than the brief imagines.
  REVIEW.md will say so.
- **Brand lookalikes for generic labels** (see §4). The default rule may yield zero
  qualifying matches for several companies. That is preferable to a noisy list.
- **The `.ph` fix is cross-repo** (riskscore extractor, deployed on .2 as a Phase-4
  extractor). Until it lands, platform lookalike counts are omitted, not shown inflated.
  The `.ph` wildcard finding is **embargoed** (hub `registry-wildcard-sweep.md`), so no
  customer-facing text may name the cause (Q3).
- **Refactor size.** The 566-line single-template renderer becomes ~12 partials. The CSS is
  carried verbatim, and the design-token tests (`test_design_tokens.py`) cover the shared
  `:root`.
- **Golden files hold third-party domain intelligence.** `estates/.gitignore` currently
  keeps contracts out of git for that reason. The brief asks for the report JSON to be
  committed; I will commit report JSON only, never contracts (Q8).

---

## 9. Phases and commits

| Phase | Commit(s) | Gate |
|---|---|---|
| 1 | `.claude/` scan fix; one commit per defect 2–9 + internal-labels, each with its test | suite green; fixture regression shows each defect gone |
| 2 | estate.yaml loader + owner exclusion; `entities.py` + `controls.md`; brand-lookalike rule | — |
| 3 | `editions/` skeleton, lens model, base template + partials, three lens files | old v2.2 output unchanged except intended fixes |
| 4 | VC free/paid | — |
| 5 | tear-offs + manifest | — |
| 6 | Osney collect + renders + ACCEPTANCE/REVIEW + golden tests | **stop for Peter's review before anything is sent** |

Riskscore rollup change: separate PR in `riskscore` after Q3. The hub workstream doc
(`datazag-pipeline/work/report-editions.md` + ACTIVE row) is opened when this plan is approved.

---

## 10. Questions for Peter

Blocking a phase is marked ⛔. The rest have a default I will use if you don't say otherwise.

1. ⛔ (Phase 6) **Merge `feat/certstream-cert-intel` first?** Default: yes, as its own PR.
2. ⛔ (Phase 6) **Collection host.** Workstation `.env` has no lake/R2 credentials, so the
   collect runs on .2 with `--local`. Shall I run it there over SSH and pull the contracts
   back, or will you? Is a corpus index built there (`CORPUS_INDEX_DIR`)? Without one,
   brand lookalikes and corpus discovery are `null`.
3. ⛔ (Phase 1 #4) **`.ph`**: OK to change the riskscore rollup (cross-repo, deployed)?
   And the customer wording while embargoed. Default: a neutral method note, "Counts
   exclude names under registry-level wildcard DNS", with no TLD named.
4. **Corpus figure.** Observatory `corpus_domains` = resolving and enriched (364.2M on
   2026-09-08). The brief says 385M+. Is that a newer snapshot of the same stat, or rows
   tracked (404.2M)? Default: `corpus_domains`, live.
5. **ACME expiry threshold** (5b) and the live TLS confirmation. Default: both on.
6. **Dependencies.** `PyYAML` (pure-Python, small) for the lens and estate files, and
   `pypdf` (pure-Python) for the PDF-text agreement check. Default: add both. Fallback:
   TOML via stdlib `tomllib`, and the PDF check limited to same-source-HTML plus layout.
7. **Tear-off links.** Base URL for `?t={token}` and the free Health Report link.
   Default: `https://www.datazag.com/t/{token}` as a placeholder in `vc.yaml`, for the
   portal brief to make real.
8. **Golden files.** Commit the Osney report JSON (not contracts)? Default: yes.
9. **Output paths** for the non-VC lenses (§6). Default as written.
10. **M5 Observatory benchmark** (portfolio vs the internet, no cohort needed). Default:
    off until you say.

Brief open questions, defaults accepted: no peer cohort; exact label + threshold + top 5;
no owner grade on the cover; effort line omitted.
