# Moving off Neon → self-hosted Postgres

Two Neon databases, two very different migrations. **The DuckLake catalog is an
easy win; the website DB carries the Vercel-connectivity burden.** Recommend
doing them separately.

## What you have

| DB | Neon env var | Consumers | Data | Serverless? |
|---|---|---|---|---|
| DuckLake catalog | `DUCKLAKE_NEON_DSN` | pipeline on the master (lake_enrich, healthreport, collection) | **metadata only** — actual lake data is in R2 (`r2://datazag-lake/data/`) | No — master processes |
| Website / portal | `DATABASE_URL` / `PORTAL_DATABASE_URL` | 4 master workers **+ the Vercel portal** (`pg.Pool`) | tables (incl. `pdf` bytea) | Portal is serverless |

The compute cost is the pollers (workers) + the pipeline attaching the DuckLake
catalog, keeping both Neon endpoints from ever autosuspending.

---

## Recommendation

1. **DuckLake catalog → self-host on the master now.** Localhost, no PgBouncer,
   R2 data untouched. Low risk, kills that endpoint's cost, and speeds every
   catalog op (no Neon round-trip). Do this first.
2. **Website DB → decide on appetite for exposing Postgres to Vercel.** The
   workers love localhost, but the Vercel portal must reach it over the internet
   through a pooler. See the caveat below; if that friction isn't worth it, keep
   the website DB on Neon at **0.25 CU min** + the Redis-signal worker fix.

---

## A. DuckLake catalog → local Postgres (easy)

Runs on the master where the pipeline lives.

```bash
# 1. Local Postgres (once)
sudo apt install postgresql
sudo -u postgres createdb ducklake_catalog

# 2. Copy the catalog out of Neon (metadata only — small)
pg_dump "$DUCKLAKE_NEON_DSN_AS_URL" --no-owner --no-privileges \
  | sudo -u postgres psql ducklake_catalog

# 3. Repoint. In /root/datazag_intelligence/.env:
#    DUCKLAKE_NEON_DSN="dbname=ducklake_catalog host=/var/run/postgresql"
#    (unix socket = no TLS, no password; or host=127.0.0.1 sslmode=disable)
#    R2_* and DUCKLAKE_DATA_PATH stay exactly as they are — data doesn't move.

# 4. Verify
python -c "from lake_enrich import lake_connect; c=lake_connect(); \
  print(c.execute('SELECT count(*) FROM ducklake_snapshot').fetchone())"
```

Nothing in R2 changes; the catalog's stored parquet paths are R2 URIs and remain
valid. `lake_connect()` reads `DUCKLAKE_NEON_DSN` — the name stays, the value now
points local.

## B. Website / portal DB → local Postgres (+ PgBouncer for Vercel)

```bash
# 1. DB + user
sudo -u postgres createdb datazag_portal
sudo -u postgres createuser portal --pwprompt

# 2. Migrate (has bytea pdf columns — pg_dump handles them)
pg_dump "$NEON_PORTAL_URL" --no-owner --no-privileges \
  | sudo -u postgres psql datazag_portal

# 3. Workers (on the master → localhost, direct, no pooler needed):
#    PORTAL_DATABASE_URL / DATABASE_URL =
#      postgres://portal:pw@127.0.0.1:5432/datazag_portal
#    in /root/datazag_intelligence/.env (all four *_worker services read this).

# 4. Vercel portal → MUST go through PgBouncer (transaction mode). The portal
#    opens a pg.Pool (max:10) per serverless instance; without pooling, many
#    concurrent instances exhaust max_connections.
```

PgBouncer (`/etc/pgbouncer/pgbouncer.ini`):
```
[databases]
datazag_portal = host=127.0.0.1 port=5432 dbname=datazag_portal
[pgbouncer]
pool_mode = transaction
max_client_conn = 500
default_pool_size = 20
```
Then set Vercel's `DATABASE_URL` to the PgBouncer endpoint (port 6432) over TLS.

**⚠️ The real friction — reaching your server from Vercel.** Vercel serverless
has **no stable egress IPs** on Hobby/Pro, so you can't cleanly firewall
Postgres to "just Vercel". Options, least-effort first:
- **Cloudflare Tunnel** to PgBouncer (you already use Cloudflare/R2) — no open
  inbound port, auth at the edge. Cleanest.
- Vercel **Secure Compute** (Enterprise) for static egress IPs to allowlist.
- Expose PgBouncer on a port with **TLS + strong creds**, accept it's
  internet-reachable, fail2ban/allowlist what you can.
- Transaction pool mode note: keep the Drizzle/pg usage prepared-statement-free
  or set `statement_cache` off — transaction pooling doesn't support session
  prepared statements.

If none of these are appealing, **keep the website DB on Neon** (0.25 CU +
Redis-signal workers) and only self-host the DuckLake catalog.

## Rollback / safety

- Keep both Neon DBs live until each cutover is verified; the change is only env
  vars, so reverting is instant.
- Cut over the **workers first** (localhost, trivial), confirm reports still
  render, then the Vercel portal last.
- Take a `pg_dump` snapshot immediately before flipping Vercel.

## After cutover

- Both Neon endpoints go cold → suspend → ~zero compute. Delete the Neon
  projects once you're confident (keep a final `pg_dump` archived).
- The polling workers are now free (local Postgres bills nothing at idle) — no
  Redis change needed.
