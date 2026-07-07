# ADR 0001 — DuckLake data-plane hub

**Status:** Proposed (design seed for a dedicated build session)
**Date:** 2026-07-07
**Context owners:** infra / data platform

## Context

The DuckLake lakehouse (catalog on Postgres; data in Cloudflare R2 at
`r2://datazag-lake/data/`) is consumed by several modules — **riskscore,
dnsproject, certstream** — plus the report pipeline (`lake_enrich.py`,
`healthreport`). Today the DuckLake catalog is on Neon, which bills by
compute-active-time; the pipeline attaching the catalog keeps that endpoint
from ever autosuspending (see `docs/SELFHOST_POSTGRES.md`).

We want a **dedicated server** that: (1) hosts the DuckLake catalog Postgres,
(2) runs the heavy DuckDB transform compute (gold rollups; **Iceberg + Delta**
marketplace dataset builds over **340M domains**, with big joins), and (3) acts
as the central data node for the analytical modules.

All analytical consumers are on the **same private network** and already use
**Arrow Flight**; DuckDB-to-DuckDB ("Quack") node communication is coming.
The Iceberg + Delta datasets are consumed by **cloud marketplaces**
(Snowflake / Databricks / BigQuery). The transactional website/portal Postgres
is a **separate** concern (its consumer is the Vercel serverless portal) and is
explicitly out of scope for this hub.

## Decision

Stand up a **DuckLake data-plane hub** with three roles, and a hard rule:

> **The big joins run once, on the hub, and materialise to gold. Consumers read
> gold — they never re-run the 340M joins.**

```
                         ┌──────────────────────────────────────────┐
                         │            DuckLake HUB (private)         │
   R2 (data, durable) ◀──┤  • DuckLake catalog Postgres (local)      │
   r2://datazag-lake/    │  • DuckDB transform compute (bronze→gold) │
        │                │  • Marketplace export: Iceberg + Delta    │
        │                │  • Arrow Flight SQL serving endpoint       │
        ▼                └───────────────┬──────────────────────────┘
   Iceberg tables ──▶ R2 Data Catalog ──▶│ private net
   Delta tables   ──▶ (_delta_log / Unity)│
                                          ▼
                    riskscore · dnsproject · certstream · report pipeline
                    (read GOLD via direct catalog attach [baseline]
                     or Arrow Flight SQL [centralised compute])
```

### Roles

1. **Catalog** — DuckLake metadata Postgres, local to the hub (the writer).
   Small, transactional, low volume. Kills the Neon cost; readers reach it over
   the private net.
2. **Compute** — DuckDB running the scheduled transforms and the marketplace
   exports. The hungry part; sized below.
3. **Serving** — two paths, deliberately:
   - **Direct catalog attach = baseline.** Co-located modules attach the
     DuckLake catalog + R2 and read gold snapshots. Survives hub-compute
     downtime (only needs the catalog Postgres up). This is what
     `lake_enrich.py` / `dnsproject/scripts/ducklake_conn` already do.
   - **Arrow Flight SQL = optimisation.** A Flight SQL endpoint on the hub
     centralises compute and streams Arrow results — good for modules that want
     the hub to do the work rather than pull inputs. Additive, not required for
     correctness.

## The 340M-join strategy (the crux)

DuckDB does larger-than-memory joins well, but it is **not** an MPP engine —
"Quack" / DuckDB-to-DuckDB is for **serving and federating result sets**, not
for splitting one giant join across nodes. So:

- **One fat node with fast NVMe spill** is the model for a monolithic join.
- **When a join outgrows the box, partition — don't distribute.** Shard by
  **`stem_prefix`** (the corpus index is already partitioned this way —
  `crossestate/corpus_index.py`), run the join per partition (each a fraction of
  340M → fits in RAM → little spill), union the outputs. Embarrassingly
  parallel, reuses existing layout.

### Box sizing vs the proposed 12 vCPU / 48 GB / 250 GB NVMe

Workable as a **starting point**, but **48 GB RAM is the binding constraint** for
a *monolithic* 340M join: a full materialised side at ~300 B/row ≈ ~100 GB, so a
340M×340M hash join spills heavily to NVMe. That is fine by design — but it makes
NVMe speed/size the bottleneck and slows big transforms.

Guidance:
- **Partitioned joins make 48 GB comfortable** — each `stem_prefix` shard is
  small enough to stay in memory. **Recommend building the transforms
  partitioned from day one**; then this spec is fine and scales by adding cores.
- **For monolithic joins, RAM is the highest-leverage upgrade** — 96–128 GB
  dramatically cuts spilling. If the export jobs must do whole-corpus joins
  un-partitioned, size RAM up before anything else.
- **NVMe: 250 GB is tight.** Big-join spill + Iceberg/Delta export staging +
  DuckDB temp can approach that. Prefer **500 GB–1 TB** NVMe scratch.
- **12 vCPU** is fine (DuckDB uses all cores); more cores speed transforms
  linearly-ish on big joins.
- DuckDB knobs: `SET memory_limit='36GB'` (~75% RAM), `SET
  temp_directory='<nvme>'`, `SET max_temp_directory_size='<nvme headroom>'`,
  `SET threads=12`. (`lake_enrich._tune_memory` already does this class of
  tuning — extend it for the hub.)

**Recommendation:** keep 12 vCPU, go **NVMe 500 GB+**, and either commit to
**partitioned transforms** (then 48 GB is fine) or bump RAM to **96 GB** if any
export needs an un-partitioned whole-corpus join.

## Marketplace exports: Iceberg is easy, Delta is the gotcha

- **Iceberg** — writable from DuckDB (iceberg extension write support is
  maturing; `pyiceberg` is the safe path for catalog-registered writes). Pair
  with **Cloudflare R2 Data Catalog** (managed Iceberg REST) so Snowflake /
  BigQuery / Trino discover tables without us running a catalog. Strong fit —
  we are already on R2.
- **Delta** — DuckDB's `delta` extension is effectively **read-only**
  (delta-kernel-rs). To *produce* Delta, go through **delta-rs / the `deltalake`
  Python lib**: DuckDB does the join → hand the Arrow result to
  `deltalake.write_deltalake()` → Delta table in R2. Databricks reads it
  natively; discovery leans on `_delta_log` or a Unity/Glue registration
  depending on the consumer. **Budget the Delta path as separate work** — it is
  not a DuckDB `COPY TO`.
- **Consider Delta UniForm** (Delta tables that also expose Iceberg metadata):
  may let us ship **one** table format and satisfy both marketplaces, saving the
  dual write path. Depends on which marketplaces are in scope.

So the export stage is two code paths: `DuckDB→Iceberg (+R2 Data Catalog)` and
`DuckDB→Arrow→delta-rs→Delta`. UniForm could collapse them — decide by target.

## Concurrency & availability

- **Many readers + a single transform writer** against the catalog is the clean
  model — DuckLake snapshot isolation gives readers a consistent view while the
  writer commits new snapshots. Keep the catalog Postgres local to the writer.
- **SPOF:** everything analytical depends on the hub. Because **direct attach is
  the baseline read path**, consumers keep reading gold even if the hub's
  *compute* (Flight) is down — they only need the catalog Postgres. Back up the
  catalog Postgres religiously (nightly `pg_dump`); the R2 data is already
  durable. Flight is the part whose downtime degrades to "direct attach".

## Out of scope

- **Website/portal transactional Postgres** — different consumer (Vercel
  serverless), different migration (PgBouncer + tunnel). See
  `docs/SELFHOST_POSTGRES.md`. Do **not** co-tenant its RAM with DuckLake
  transforms on the same box.

## Open questions (resolve at build time)

1. **Marketplaces in scope** — Snowflake / Databricks / BigQuery? Decides
   Iceberg-only vs genuinely-need-Delta, and whether UniForm removes a path.
2. **Flight SQL serving** — is a Flight SQL endpoint already built in dnsproject
   (`scripts/ducklake_conn`), or new? Determines serving-layer effort.
3. **Transform shape** — can the big joins be expressed **partitioned by
   `stem_prefix`** (then 48 GB is fine), or is a whole-corpus un-partitioned join
   unavoidable (then RAM → 96 GB)?
4. **Refresh cadence** of the marketplace datasets (drives scheduling + how much
   NVMe staging headroom).

## Phased build (proposed)

1. **Catalog migration** — DuckLake catalog Neon → local Postgres on the hub
   (`docs/SELFHOST_POSTGRES.md` §A). Immediate Neon-cost win, low risk.
2. **Transform harness** — partitioned-by-`stem_prefix` gold build on the hub;
   extend `_tune_memory`; land gold snapshots in DuckLake.
3. **Iceberg export + R2 Data Catalog** — spike first (smallest marketplace
   slice), prove Snowflake/BigQuery can read it.
4. **Delta export** via delta-rs (or UniForm if it collapses the paths).
5. **Arrow Flight SQL serving** — only if a consumer needs centralised compute
   beyond direct attach.

## References

- `lake_enrich.py::lake_connect` — the self-contained DuckLake attach (env:
  `DUCKLAKE_NEON_DSN`, `DUCKLAKE_DATA_PATH`, `R2_*`).
- `crossestate/corpus_index.py` — the `stem_prefix` partitioning to reuse.
- `dnsproject/scripts/ducklake_conn` — the shared connection helper.
- `docs/SELFHOST_POSTGRES.md` — the catalog + portal DB migration runbook.
