"""WU20 — "Scope my estate" discovery teaser.

Portal /scope form inserts a `scope_requests` row; `scope_worker.py` claims it,
runs the discovery walk in counts mode, composes a TeaserViewModel and renders
the teaser artefact. Commercial guardrails live in compose.py: tier COUNTS are
public, possible/defensive-tier NAMES are the paid deliverable and never leave
the pipeline; at most 3 strongly-associated domains ship as proof.
"""
from scopeteaser.bands import BANDS, PriceBand, band_for
from scopeteaser.contract import ProofDomain, TeaserViewModel
from scopeteaser.compose import build_teaser
