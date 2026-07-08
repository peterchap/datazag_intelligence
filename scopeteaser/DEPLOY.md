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
| `SCOPE_BOOKING_URL` | book-a-call calendar (COO's). The teaser link rides as a prefilled note. | falls back to `https://www.datazag.com/contact?scope=<token>` |
| `SCOPE_BOOKING_NOTE_PARAM` | the calendar's prefill field name (provider-specific — see table). | `notes` |
| `SCOPE_CHECKOUT_URL` | WU16 report-SKU checkout for the self-serve bottom band. | **checkout CTA hidden** — every band books a call until this exists |

The bottom-band "Buy now" CTA renders **only** when `SCOPE_CHECKOUT_URL` is set
AND the band is `self_serve` — no dead checkout link before WU16.

**Booking note prefill.** `/api/scope/go?kind=book_call` records the event, then
302s to `SCOPE_BOOKING_URL` with `?<SCOPE_BOOKING_NOTE_PARAM>=Datazag estate
scope: <teaser url>` so the call opens on the artefact, plus `utm_content=<src>`
for attribution. Set `SCOPE_BOOKING_NOTE_PARAM` to match the provider:

| Provider | Note field param |
|---|---|
| Cal.com | `notes` (default) |
| Calendly | `a1` (first custom question) |
| SavvyCal | `notes` |
| Google Appointment Schedules | no prefill support — use the fallback or a wrapper |

## 4. WU16 paid-report checkout (Customer_Portal)

Apply the report-orders migration (also adds `scope_requests.set_hash` and seeds
the two paid SKUs):

```
node scripts/apply-sql.cjs drizzle/0008_report_orders.sql
```

Portal env for checkout:

| Var | Purpose |
|---|---|
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | already set for existing products |
| `SCOPE_CHECKOUT_URL` | `https://portal.datazag.com/scope/checkout` — the scope teaser's bottom-band "Buy now" target (auth-gated, freezes scope). Until set, the checkout CTA stays hidden. |

Checkout is **org-scoped**: both entry pages (`/scope/checkout?scope=<token>`
for Cross-Estate, `/reports/buy` for Domain Risk) redirect to `/login` first,
then create a Stripe session and, on `checkout.session.completed`, a **pending
`report_orders` row**. Cross-estate orders freeze `declared`+`strong` counts and
the `set_hash` so delivery matches purchase.

**Delivery worker (on the master).** `report_order_worker.py` claims pending
`report_orders` and renders each:
- `domain_risk_report` → `python -m healthreport.run --domain <d>` (the paid
  single-domain assessment).
- `cross_estate_report` → collects the scope's declared domains into contracts,
  builds the estate manifest, renders the v2.2 report to PDF, and recomputes the
  set hash — a mismatch vs the frozen hash is surfaced in the summary, not
  delivered silently.

```
sudo cp report_order_worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now report_order_worker
journalctl -u report_order_worker -f
```

The portal serves the finished PDF from `GET /api/reports/orders/<id>/download`
(org-scoped, ready-only). **Limitation:** cross-estate delivery currently loads
only the *declared* domains' contracts; discovered-domain contracts (for full
pre/post-discovery concentration deltas) are a follow-up — discovery tiers still
render from cert-SAN evidence.

## 5. Site CTA flips (DZ-Site)

Set on the marketing deployment once the above is live:

```
NEXT_PUBLIC_SCOPE_LIVE=true                 # Cross-Estate CTA → portal /scope
NEXT_PUBLIC_SCOPE_URL=https://portal.datazag.com/scope?src=reports        # optional override
NEXT_PUBLIC_REPORTS_CHECKOUT_LIVE=true      # Domain Risk Report CTA → portal /reports/buy
NEXT_PUBLIC_DRR_BUY_URL=https://portal.datazag.com/reports/buy?src=reports  # optional override
```

`NEXT_PUBLIC_SCOPE_LIVE` flips the Cross-Estate CTA from "Talk to us about your
estate" → "Scope my estate"; `NEXT_PUBLIC_REPORTS_CHECKOUT_LIVE` flips the
Domain Risk Report CTA from "Contact us" → "Buy the Domain Risk Report". The
free-report renderer seam already targets `/reports?src=free-report#cross-estate`.

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
