# Estate discovery — sources, the tailored corpus index, and how to build it

*The real (passive) discovery engine behind estate completeness (§2.1) and the
v2.2 four tiers (§2.7). One pass, multiple sources, in `crossestate/discovery.py`.*

## Sources (each a signal, combined by the corroboration/gate stack)

| Source | Where | Finds | Lane |
|---|---|---|---|
| **Cross-domain cert SANs** | `cert_analysis.cross_domain_sans` on each contract (CertStream/CT, populated upstream) | domains sharing a certificate with the estate | owned (a shared cert = one controller) |
| **Corpus stem-sweep** | the tailored index (below) | brand-family domains (`stem.*`, `stem-*`) | owned / ambiguous / hostile — decided by corroboration |
| **Entropy / DGA** | `crossestate/entropy.py` | whether a candidate is a clean extension or a lookalike | splits owned vs hostile |
| **Companies House CRN** | *hook* (UK-only, downloadable DB) | CRN→domain ownership links | owned (not yet wired) |

**The gate rule:** a brand/lexical string-match *qualifies* a candidate for scoring;
corroboration (shared cert SAN, shared NS/MX/registrar/ASN, exact stem + low DGA)
decides the lane. A brand-family domain with no corroboration is held as a
low-confidence `possible` candidate; a DGA/typosquat lookalike goes to the
`hostile` lane (alert/feed-delivered, mapped to the v2.2 `defensive` tier), never
headlined as owned.

## The tailored corpus index (`crossestate/corpus_index.py`)

Scanning the 323M-row `domains.parquet` per run gives neither predictable latency
nor stable results, so discovery reads a **stem-prefix-partitioned** index:

```
index_dir/stem_prefix=ac/*.parquet   # every domain whose registrable stem starts "ac"
index_dir/stem_prefix=ex/*.parquet
```
Each row: `domain · stem · suffix · stem_prefix` + the DNS match-columns carried
through from the source when present (`ns_domain`/`mx_domain`/`registrar`/`asn`/
`ip`). A stem lookup reads ONE partition → flat latency at any corpus size
(measured ~8–10ms warm). The sweep is bounded to `stem` + `stem-*` (same
partition) — broad "contains brand" is unpredictable *and* FP-heavy.

**Build it** (once, refreshed on a cadence; run on the enriched gold parquet once
DNS columns are added — the builder carries through whatever DNS columns exist):
```
python -m crossestate.corpus_index --source /path/domains.parquet --out /path/discovery_index
```
Then point the reports at it:
```
export CORPUS_INDEX_DIR=/path/discovery_index      # default_discovery() wires it automatically
```
Without `CORPUS_INDEX_DIR`, discovery runs cert-SAN-only (no corpus needed locally
or in tests).

## Verify

- `python tests/test_discovery_corpus.py` — index build + bounded lookup, entropy/
  DGA ordering, typosquat, and the corpus-backed classification (owned / held
  candidate / hostile) on a synthetic corpus. Needs duckdb (in the venv).
- On the real corpus: 323M scanned in ~1.4s to build a brand-family subset;
  per-stem lookups read one partition.

## Not yet wired (hooks)

- **Live CertStream pull** — cert SANs come from the contract today; a live pull
  per declared domain (extend `cert_pipeline`) would catch certs issued since the
  last scan.
- **Companies House CRN** (UK) — inject as an ownership corroborator.
- **Active check** — DNS→website→CV for the hostile/ambiguous lanes:
  `ConnectedDomainDiscoveryProvider(active_check=…)`.
