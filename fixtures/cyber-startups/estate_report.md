# Cross-Estate Domain Risk Report — cyber-startups

Starting from 11 declared domains, Datazag found 16 across the estate. The estate grades B (24/100). It is single-threaded on Google for email / mailbox platform (55%). 44,522 new lookalike domains impersonating the estate's platforms (30d, internet-wide): they target every organization on those platforms, not this estate specifically.

## Estate discovery
Declared 11; 16 found.

## Concentration & posture variance

Estate grade **B** (24/100).

- Email / mailbox platform: **Google** 55% (hyperscale, exit medium) [WATCH] — verify account-level controls (MFA, admin recovery); concentration acceptable if deliberate
- Nameserver / DNS provider: **Cloudflare** 60% (hyperscale, exit low) [WATCH] — verify account-level controls (MFA, admin recovery); concentration acceptable if deliberate
- Registrar: **GoDaddy.com, LLC** 44% (commodity, exit high) [ELEVATED] — plan to reduce before it grows
- Hosting network (ASN): **AS13335 Cloudflare** 45% (hyperscale, exit low) — 
- Hosting provider: **cloudflare** 83% (hyperscale, exit low) [WATCH] — verify account-level controls (MFA, admin recovery); concentration acceptable if deliberate
- Third-party vendor (SPF-observed): **Google Workspace** 55% (commodity, exit medium) [HIGH] — reduce: migrate the weakest segment to the group-standard provider

### Variance
- ns:AWS: median C
- ns:Cloudflare: median A
- ns:Namecheap: median C
- reg:HOSTINGER operations, UAB: median B

## Correlated weakness & active exposure

- CAA record missing: 11/11 (100%)
- DNSSEC not enabled: 9/11 (82%)
- DMARC not enforced: 4/11 (36%)
- SPF not strict: 4/11 (36%)

**Platform exposure:** 44,522 new lookalikes of the estate's platforms, internet-wide (external_threat.impersonations · confidence = "exact").

## Exception register

1. **[HIGH]** 1 domain(s) expired or unlocked — recover before anything else
   - `calendar.overdue × 0 · registrar_lock = none × 1`
2. **[HIGH]** Provider concentration across the estate — 5 single points of failure
   - collapsed from concentration × 5
   - `technographic=Google Workspace 55% [commodity] · registrar=GoDaddy.com, LLC 44% [commodity/high-exit] · mailbox=Google 55% [hyperscale] · ns=Cloudflare 60% [hyperscale]`
3. **[ELEVATED]** Systemic misconfiguration repeats across the estate — fix as a standard
   - collapsed from correlated_weakness × 4
   - `correlated_weakness × 4 · see page 4 rollup`
4. **[INFO]** 44,522 new lookalike domains impersonating the estate's platforms (30d, internet-wide)
   - `external_threat.impersonations · confidence = "exact"`

## Appendix A — remediation worksheet

### Recover expired / unlocked domains — Now
- [ ] osneycapital.com (Amazon Registrar, Inc.) · now: no registrar lock → renew + set registrar locks

### Enforce DMARC — Now
- [ ] osneycapital.com (AWS) · now: p=none (monitor only) → p=quarantine
- [ ] ploy.io (AWS) · now: p=none (monitor only) → p=quarantine
- [ ] refute.com (Cloudflare) · now: p=none (monitor only) → p=quarantine
- [ ] ossprey.com (Namecheap) · now: p=none (monitor only) → p=quarantine

### Tighten SPF to hard-fail — Now
- [ ] ploy.io (AWS) · now: soft-fail (~all) → -all after DMARC confirms senders
- [ ] overmindlab.ai (Cloudflare) · now: soft-fail (~all) → -all after DMARC confirms senders
- [ ] strandintelligence.com (Cloudflare) · now: soft-fail (~all) → -all after DMARC confirms senders
- [ ] aviel.tech (DNS zone host) · now: soft-fail (~all) → -all after DMARC confirms senders

### Publish CAA records — Soon
- [ ] osneycapital.com (AWS) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] ploy.io (AWS) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] sitehop.com (AWS) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] aisy.ai (Cloudflare) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] huntbase.io (Cloudflare) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] mindgard.ai (Cloudflare) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] overmindlab.ai (Cloudflare) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] refute.com (Cloudflare) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] strandintelligence.com (Cloudflare) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] aviel.tech (DNS zone host) · now: no CAA record → issue "&lt;your-ca&gt;"
- [ ] ossprey.com (Namecheap) · now: no CAA record → issue "&lt;your-ca&gt;"

### Enable DNSSEC — Maturity
- [ ] osneycapital.com (AWS) · now: zone unsigned → sign zone + DS at registry
- [ ] ploy.io (AWS) · now: zone unsigned → sign zone + DS at registry
- [ ] sitehop.com (AWS) · now: zone unsigned → sign zone + DS at registry
- [ ] aisy.ai (Cloudflare) · now: zone unsigned → sign zone + DS at registry
- [ ] mindgard.ai (Cloudflare) · now: zone unsigned → sign zone + DS at registry
- [ ] overmindlab.ai (Cloudflare) · now: zone unsigned → sign zone + DS at registry
- [ ] strandintelligence.com (Cloudflare) · now: zone unsigned → sign zone + DS at registry
- [ ] aviel.tech (DNS zone host) · now: zone unsigned → sign zone + DS at registry
- [ ] ossprey.com (Namecheap) · now: zone unsigned → sign zone + DS at registry
