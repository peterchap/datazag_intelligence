# Cross-Estate programme — consolidated deploy runbook

Covers WU19 (site /reports), WU20 (scope teaser), WU16 (paid checkout +
delivery) and WU21 (design tokens + logo). Three repos, stacked PRs. Merge
**bottom-up per stack**, then run migrations → workers → env flags.

## 1. Merge order (bottom-up per stack)

GitHub retargets a stacked PR's base to master automatically as each base
merges. Merge in this order:

**datazag_intelligence** (pipeline) — linear stack:
1. #1 `wu21-design-tokens` → master  (tokens + :root extraction)
2. #2 `report-engine-seam-links`     (report engine verify + real CTA/seam links)
3. #3 `wu20-scope-teaser`            (teaser engine, bands+subscription, set_hash, delivery worker, booking, DEPLOY docs)
4. #4 `wu21-logo-lockup`             (logo namespace, two-tone renderers, Dz mark) — rebased over #3

**dzsite-vercel** (site) — linear stack:
1. #1 `wu19-reports-cross-estate` → master  (WU19 /reports, WU16/WU20 env-gated CTAs)
2. #2 `wu21-site-adoption`                  (tokens.css, lockup, navbar, Dz mark) — rebased over #1

**datazag_vercel** (portal) — one base + two siblings:
1. #9  `wu20-scope-teaser` → master   (scope flow, bands, booking prefill)
2. #11 `wu16-report-checkout`         (paid checkout, report_orders, download route) — sibling on wu20
3. #10 `wu21-portal-adoption`         (tokens, navy accent, lockup, pills, Dz mark) — sibling on wu20

#11 and #10 are independent siblings (no shared files); merge #11 then #10 (or
either order), rebasing the second onto master. Portal PR #3 (copilot API-key
work) is unrelated to this programme.

## 2. Database migrations (Customer_Portal → Neon)

```
node scripts/apply-sql.cjs drizzle/0007_scope_requests.sql   # WU20 scope_requests + scope_events
node scripts/apply-sql.cjs drizzle/0008_report_orders.sql    # WU16 report_orders + scope_requests.set_hash + SKU seed
```

Both idempotent. 0008 also seeds the two paid SKUs (Domain Risk Report £495,
Cross-Estate Band A £3,500).

## 3. Workers (on the master, systemd)

```
sudo cp scope_worker.service report_order_worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scope_worker report_order_worker
journalctl -u scope_worker -u report_order_worker -f
```

Both take the portal Neon DSN via `/root/datazag_intelligence/.env` and need the
pipeline API keys + Chromium (Playwright). `scope_worker` also honours optional
`CORPUS_INDEX_DIR`.

## 4. Email logo assets (on the master)

```
python design/generate_logo_assets.py    # bakes logo-dark/light@2x.png + dz-mark@2x.png
```

Re-run whenever `design/tokens.json` logo.* values change (the SVGs are
drift-guarded; the PNGs are baked separately since they need Chromium).

## 5. Env — go-live flags

**Portal (datazag_vercel):**
| Var | Effect |
|---|---|
| `SCOPE_CHECKOUT_URL` = `https://portal.datazag.com/scope/checkout` | shows the bottom-band "Buy now"; unset = every band books a call |
| `SCOPE_BOOKING_URL` | COO calendar; unset = `/contact` fallback |
| `SCOPE_BOOKING_NOTE_PARAM` | prefill field (Cal.com/SavvyCal `notes`, Calendly `a1`) |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | already set |

**Site (dzsite-vercel):**
```
NEXT_PUBLIC_SCOPE_LIVE=true                # Cross-Estate CTA → portal /scope
NEXT_PUBLIC_REPORTS_CHECKOUT_LIVE=true     # Domain Risk Report CTA → portal /reports/buy
# optional overrides: NEXT_PUBLIC_SCOPE_URL, NEXT_PUBLIC_DRR_BUY_URL
```

Leave the flags unset to soft-launch (CTAs fall back to Contact us / Talk to us).

## 6. Post-deploy verification

- Scope smoke test (DEPLOY.md §Smoke test): POST /api/scope → worker teaser_ready → /scope/result/<token> → book-a-call redirect records a scope_events row.
- Checkout smoke test: /reports/buy (login) → Stripe test payment → webhook creates a pending report_order → report_order_worker renders → download route serves the PDF.
- **Seam-continuity screenshot review** (WU21 acceptance): free report PDF → /reports → scope → teaser → portal — confirm one brand (lockup, tokens, pills) with no mismatch.

## 7. Decisions still open (don't block soft-launch)

- **Subscription "from" prices** per band — currently render "on request".
- **healthreport ↔ Domain Risk Report** renderer mapping — the delivery worker renders `domain_risk_report` via `healthreport.run`; confirm that's the intended paid single-domain report, else swap the CLI in `report_order_worker.render_domain_risk`.
- **Cross-estate delivery** loads only declared-domain contracts (discovered-contract expansion for full concentration deltas is a follow-up).
