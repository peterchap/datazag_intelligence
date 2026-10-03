# Entity controls: the fixed vocabulary

Every entity record (`entities[].controls`, and `entities[].records[].controls`
per declared domain) carries seven controls. Each control takes exactly one value
from its own list below. The source of truth is `estatereport/controls.py`
(`VOCAB`); `tests/test_estate_entities.py` fails if this page and the code drift.

`unknown` appears on **every** control when a domain was not assessed: its live
DNS scan did not finish, its contract failed to load, or there was no
intelligence for it. It is never used for a measured absence. A domain we scanned
that publishes no DMARC record is `missing`, not `unknown`.

## `dmarc`

| Value | Meaning |
|---|---|
| `reject` | `p=reject`: spoofed mail is refused. |
| `quarantine` | `p=quarantine`: spoofed mail goes to spam. |
| `monitor` | `p=none`: reports only, no enforcement. |
| `missing` | No DMARC record at `_dmarc.<domain>`. |
| `invalid` | A record exists but carries no readable policy. |
| `unknown` | Not assessed. |

## `spf`

| Value | Meaning |
|---|---|
| `hardfail` | Ends in `-all`: unlisted senders fail. |
| `softfail` | Ends in `~all`: unlisted senders are marked, not failed. |
| `neutral` | `?all`, or no `all` mechanism: unlisted senders are not failed. |
| `permissive` | `+all` (or a bare `all`): any sender passes. |
| `delegated` | `redirect=` to another domain's policy, no `all` of its own. |
| `missing` | No SPF record. |
| `unknown` | Not assessed. |

## `caa`

| Value | Meaning |
|---|---|
| `present` | At least one CAA record limits which CAs may issue. |
| `missing` | No CAA record. |
| `unknown` | Not assessed. |

## `dnssec`

| Value | Meaning |
|---|---|
| `signed` | The zone is signed and a DS is published at the registry. |
| `unsigned` | No DNSSEC. |
| `unknown` | Not assessed. |

## `mta_sts`

| Value | Meaning |
|---|---|
| `enforce` | Policy mode `enforce`: sending servers must use TLS. |
| `testing` | Policy mode `testing`: failures are reported, not enforced. |
| `none` | Policy mode `none`. |
| `invalid` | An `_mta-sts` record is published but no readable policy mode was found. |
| `missing` | No MTA-STS. |
| `unknown` | Not assessed. |

## `bimi`

| Value | Meaning |
|---|---|
| `present` | A BIMI record is published. |
| `missing` | No BIMI record. |
| `unknown` | Not assessed. |

## `registrar_lock`

| Value | Meaning |
|---|---|
| `locked` | RDAP status includes a transfer/delete/update prohibition or a hold. |
| `unlocked` | RDAP returned a status with no lock. |
| `unknown` | Not assessed, or RDAP returned no status (not measured). |

## Gaps and order

`estatereport.controls.GAPS` maps each weak value to the sentence a reader sees
(for example `dmarc: monitor` → "DMARC at p=none (monitor only)"). `top_issue` is
the first gap in fix-urgency order: `registrar_lock`, `dmarc`, `spf`, `caa`,
`dnssec`, then the maturity controls `mta_sts` and `bimi`. Maturity gaps are listed
but never a headline finding on their own.
