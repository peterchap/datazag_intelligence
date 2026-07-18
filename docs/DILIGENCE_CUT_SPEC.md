# The `diligence` cut — spec

*Draft for review, 2026-07-18. A third `CutConfig` alongside operator/oversight,
plus the materiality weighting the manifest was already designed for. No new
report package: the five analytics, the segment resolver, discovery and the
remediation worksheet are all reused unchanged.*

## Who holds it

The **buyer** — M&A diligence, VC/PE portfolio review, or the acquirer's
integration lead post-close. Distinct from both existing cuts:

| | operator | oversight | **diligence** |
|---|---|---|---|
| holder | runs the estate | insurer / board | **buying or holding equity in it** |
| per-domain fixes | shown | **suppressed** (liability artefact) | **shown** (it's the cost estimate) |
| leads with | exception register | concentration / accumulation | **undeclared assets** |
| ranking | severity | severity | **severity band, then materiality** |

The pivot: oversight suppresses per-domain remediation because a fix list in an
underwriting file is a liability artefact. In diligence that same list is the
deliverable — it's the remediation cost you price into the offer. So
`show_per_domain_fixes = True`, and Appendix A (the pattern-grouped worksheet)
becomes a headline artefact rather than a drill-down.

## Why discovery leads

For a going-concern estate the declared list is broadly right, and the analytics
are the finding. Diligence inverts that: the target hands you 40 domains, and the
question worth paying for is what the other 15 are — the forgotten acquisition,
the shadow-IT portal, the lapsed brand a third party now holds.

`ConnectedDomainDiscoveryProvider` already produces exactly the three lanes this
needs (`crossestate/discovery.py`): `discovered` (corroborated owned),
`candidates` (low-confidence, held separate), `hostile` (lookalike/typosquat).
The hostile lane is a diligence finding in its own right — active impersonation
of the target's brand is a liability the buyer inherits at close.

This section renders honestly when discovery is off: `NullDiscoveryProvider`
returns `available=False` with a note, and the structure never disappears.

## Proposed section order

Canonical order lives in `cuts.py:SECTION_ORDER`; a cut selects and reorders.

```
cover           executive aggregate — size, grade distribution, RED domains
completeness    §2.1 UNDECLARED ASSETS + hostile lane      ← the headline
exceptions      materiality-ranked register — the negotiating list
variance        §2.4 which companies/segments are the outliers
calendar        §2.6 lapses = takeover windows (see below)
concentration   §2.2 systemic / accumulation
correlated      §2.3 shared fixable weaknesses = integration cost
exposure        §2.5 impersonation rollup
appendix        per-domain drill-down + remediation worksheet (fixes ON)
```

Calendar sits unusually high deliberately, and consistently with the codebase's
own priority rule: `estatereport/remediation.py` already locks "recovery /
registrar work (expired names, locks) is Fix 1, always — takeover windows precede
DNS hygiene." An expired domain or unlocked registrar at a target is a
pre-close liability with a clock on it, not routine hygiene.

## Materiality weighting

### The rule

**Severity bands lead; materiality orders within a band.**

```python
out.sort(key=lambda e: (_SEV_ORDER[e.severity], -e.materiality_pct, e.finding))
```

Rationale: severity is a claim about the *defect*; materiality is a claim about
the *stake*. A `low` data-quality finding on the largest position must not
outrank a `high` systemic weakness — that would make the register untrustworthy.
But within `high`, the finding touching 70% of portfolio value goes first.

The rejected alternative is a blended numeric score (`severity_weight ×
materiality`). It reorders across bands, which produces exactly the inversion
above, and it's opaque — a buyer cannot audit why item 3 outranks item 4. The
current register is deterministic and explainable; that property is worth more
than resolution.

### Computing it

`materiality` = sum of `limit` over the exception's affected members:

- `scope="domain"` → sum of `limit` over `members`
- `scope="segment"` → sum of `limit` over all domains in those segments
- `scope="estate"` → the estate total (so estate-wide findings sort by severity
  alone, as they always tie at 100%)

`materiality_pct` = that sum ÷ estate total, and it becomes a rendered evidence
line — *"affects 62% of portfolio value (£412M of £665M)"* — which is the
portfolio-legible sentence the current register cannot produce.

### Degradation (important)

If **no** `limit` values are supplied, materiality is `None` throughout and the
sort falls back to the present `(severity, finding)` ordering, with no
materiality line rendered. If **some** are supplied, unvalued domains contribute
zero and the render states the covered share explicitly
(*"materiality known for 31 of 44 domains"*). Never impute a missing value —
same discipline as the analytics, where an unscanned domain is excluded from the
denominator rather than scored as a pass.

## Code changes

| file | change |
|---|---|
| `crossestate/contract.py` | `DomainRef.limit: Optional[float]`; `Segment.limit_total`; `EstateViewModel.limit_total` + `limit_known_count`; `EstateException.materiality` + `materiality_pct` |
| `crossestate/build.py` | carry `e.limit` → `DomainRef` (parse `str`→`float`, junk → `None`, never raise); aggregate per segment + estate |
| `crossestate/exceptions.py` | compute materiality per exception from `members`; new sort key; materiality evidence line |
| `crossestate/cuts.py` | the `diligence` `CutConfig` |
| `crossestate/renderer.py` | render the materiality line where present; masthead label |
| `estate_run.py` | none — `--cut` choices derive from `CUT_KEYS`, and `--cut all` iterates it |

`limit` stays the field name for insurer-instance compatibility, documented as a
generic materiality value; `materiality` is accepted as an input alias in the
manifest loader.

### Tests

`tests/test_estate_cuts.py` (currently 5) gains diligence section-order and
`show_per_domain_fixes` cases. New `tests/test_estate_materiality.py`: sum by
scope, the no-limits fallback, the partial-coverage statement, junk-value
tolerance, and that severity never inverts across bands.

## Deliberately out of scope

- **Trend / drift.** Diligence wants trajectory ("neglected for two years, or
  broke last month?") and post-close wants "did they actually fix it". Needs
  stored prior runs + refresh cadence — listed as not-in-MVP in the crossestate
  handover, and it's a bigger piece of infrastructure than this cut.
- **CRN / Companies House entity resolution.** The largest single lever for M&A
  discovery — resolving a target's *corporate* identity to its domain estate,
  rather than inferring from cert SANs and brand stems. Called out in
  `DISCOVERY.md`. Should be its own piece of work.
- **A hierarchy axis.** `segment` is one level, so a VC portfolio must spend it
  on company, losing intra-company segmentation. Acceptable for v1; a genuine
  `group → company → segment → domain` model is a contract change.

## Open decisions

1. Ranking rule — severity-bands-then-materiality as proposed, or blended?
2. Section order — discovery first, and is calendar too high?
3. What `limit` means for VC — enterprise value, check size, or
   ownership-adjusted position? Changes only documentation, not code.
4. Does diligence need its own masthead/cover composition, or is reordering the
   existing sections enough for v1?
