# Kids Planet — expected findings (ground truth)

*Recorded 2026-07-18, from direct DNS/HTTP/TLS observation during domain
verification — BEFORE any report was run. This is a check on the report, not
output from it. If the reports miss these, that is a finding about the reports.*

Use this to grade the run: for each row, did the report surface it, at what
severity, and in which section?

## Should definitely appear

| domain | observed | why it matters in diligence |
|---|---|---|
| `poppyandjacks.co.uk` | resolves, **live MX (Microsoft 365)**, web server does not respond | Live mail on a dead brand. Mailboxes may still receive parent/child correspondence with nobody monitoring them — inherited data-protection exposure. |
| `wavertondaynurseries.co.uk` | resolves, **live MX (Google Workspace)**, web server does not respond | Same pattern, different provider — so it is not a one-off misconfiguration but a repeated post-acquisition habit. |
| `thehunnypot.co.uk` | still on the **previous owner's** hosting and mail (`megamailservers.eu`) | Not migrated. The seller's infrastructure still carries the acquired brand's mail — a live control gap at close. |
| `tiptoes.co.uk` | **expired TLS certificate** | Straightforward neglect; cheap to fix, and a visible one. |
| `lindenhousedaynursery.co.uk` | TLS misconfiguration (internal alert / subject-name mismatch) | |
| `lawleyvillagedaynursery.co.uk` | registrar **parking / lander** page | |
| `gigglesandwiggles.co.uk` | registrar **parking / lander** page | |
| `highbanknursery.co.uk` | registrar **parking / lander** page | |
| `earlybirdsdaynursery.co.uk` | registrar **parking / lander** page | |

Four parked domains out of 25 is a concentration of neglect the `legacy`
segment should show clearly in the variance block.

## Cannot appear, and that is the point

- **`fledglingsnurseries.co.uk`** — Fledglings Ltd, acquired Jan 2024. Now
  **NXDOMAIN**, no NS records, but its pages remain search-indexed. The cleanest
  example of post-integration domain decay in the set.
- **~45 further acquired brands** (Bonney Babies, Horn End, Kinderbear, Sunbeams,
  Do Re Mi, Nook Barn, Tender Years, Squirrels Childcare, Hillside Childcare,
  Church House, …) have no resolving domain under any plausible apex.

None of these can appear in a manifest-driven run, because a manifest only
contains what someone typed into it. A buyer asking "what did we just acquire,
and what happened to it?" cannot be answered by this report as it stands. That
is the argument for discovery leading the diligence cut — and note that a
dropped domain is not automatically benign: a lapsed name that a third party
re-registers becomes an impersonation vector against a childcare brand, which
is the hostile lane in `DiscoveryResult`.

## Method note that bears on discovery design

Nine domains were excluded as **name collisions** — real nurseries with the same
name in different towns (`rompersnursery.co.uk` is Montrose, not Liverpool;
`happydaysnurseries.com` is Partou-owned, a competitor). Generic nursery names
collide badly.

This independently confirms why `ConnectedDomainDiscoveryProvider` corroborates
candidates on shared NS/MX/registrar/ASN/IP rather than on stem match alone, and
why `corpus_index.py` bounds its sweep to `stem` and `stem-*` rather than
"contains brand". In this sector, stem-matching alone produces a materially
wrong estate — and wrongly attributing a competitor's nursery to the target
would be a serious diligence error.

Encouragingly, the ownership signal that did work here — ten acquired domains
sharing the redirect host `88.208.252.9` — is exactly the shared-IP
corroboration the corpus index already carries as a match column.

## Watch items (not defects)

- `kidsplanetdaynurseries.com` / `kidsplanetnurseries.com` are IONOS-registered
  and parked; defensive registration is the strong reading but RDAP redacts the
  registrant, so ownership is inferred. If the report treats these as neglected
  estate rather than defensive holdings, that is a false positive worth noting.
- `earlydaysnursery.co.uk`, `littletreasuresacademy.co.uk` resolve but showed no
  ownership evidence and are excluded. If discovery later proposes them as
  candidates, that is a useful precision test.
