# WU20 "Scope my estate" — deploy runbook

Two moving parts, same transport as the free report (portal Neon table + a
master worker that polls it). Ship order: **migration → worker → portal env →
site CTA flip**.

## 1. Portal DB migration (Customer_Portal, Neon)

Apply the scope tables:

```
node scripts/apply-sql.cjs drizzle/0007_scope_requests.sql
```

Creates `scope_requests` + `scope_events` (idempotent). The Drizzle model in
`shared/schema.ts` maps every column except `teaser_html` (polling never pulls
the artefact).

## 2. Scope worker (datazag_intelligence, on the master)

```
sudo cp scope_worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scope_worker
journalctl -u scope_worker -f      # confirm "polling every 10s"
```

Env comes from `/root/datazag_intelligence/.env` — same file the free report
worker uses; `DATABASE_URL` must be the **portal** Neon DSN. Optional
`CORPUS_INDEX_DIR` turns on the corpus stem-sweep (see `crossestate/DISCOVERY.md`);
without it, discovery runs cert-SAN-only.

## 3. Portal env (Customer_Portal deployment)

| Var | Purpose | Until set |
|---|---|---|
| `SCOPE_BOOKING_URL` | book-a-call calendar (COO's). Scope token appended as `?scope=<token>`. | falls back to `https://www.datazag.com/contact` |
| `SCOPE_CHECKOUT_URL` | WU16 report-SKU checkout for the self-serve bottom band. | **checkout CTA hidden** — every band books a call until this exists |

The bottom-band "Buy now" CTA renders **only** when `SCOPE_CHECKOUT_URL` is set
AND the band is `self_serve` — no dead checkout link before WU16.

## 4. Site CTA flip (DZ-Site)

Set on the marketing deployment once the above is live:

```
NEXT_PUBLIC_SCOPE_LIVE=true
# optional override; default https://portal.datazag.com/scope?src=reports
NEXT_PUBLIC_SCOPE_URL=https://portal.datazag.com/scope?src=reports
```

Flips the /reports Cross-Estate CTA from "Talk to us about your estate" →
"Scope my estate". Also update the free-report renderer seam if desired
(`SEAM_CROSS_ESTATE_URL` already targets `/reports?src=free-report#cross-estate`,
which carries the reader into the scope flow via the page CTA).

## 5. Price bands

`scopeteaser/bands.py` is the single source; `scopeteaser/price_bands.json` is
generated from it (`python -m scopeteaser.bands`) and vendored into the portal
(`shared/price-bands.json`). **Values are commercial placeholders pending
sign-off** — update `BANDS`, regenerate, re-vendor, and the teaser + portal move
together.

## Smoke test

1. `POST /api/scope` with 1–3 domains + work email → `{token}`.
2. Worker logs `teaser_ready: declared N → evidenced M (Band X)`.
3. `GET /scope/result/<token>` shows counts, ≤3 proofs, band; book-a-call
   redirects through `/api/scope/go` (records a `scope_events` row).
4. Re-submit the same estate within 14 days → 429 dedupe (returns the existing
   teaser token if ready).
