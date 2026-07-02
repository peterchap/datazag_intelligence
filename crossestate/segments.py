"""
crossestate/segments.py
-----------------------
Resolve every domain to a SEGMENT — the one grouping dimension that changes
between buyer types (subsidiary / client / insured / portco / brand).

Rules (per the locked scope):
  1. A customer-supplied tag (manifest `segment`) is AUTHORITATIVE.
  2. Untagged domains are inferred from signals ALREADY on the contract — no
     external corpus needed:
       a. shared registrable apex with a *tagged* sibling → adopt that tag;
       b. else a cohort label from ns_provider / registrar / asn;
       c. else "unassigned".
  3. Reconciliation: the tag always wins. Where a tagged domain shares its apex
     with a sibling carrying a *different* tag, we FLAG the disagreement
     (`segment_disagreement`) — the estate exception register surfaces it — but
     never silently override the customer's tag.

`infer_from_discovery` is a hook for a future CRN / connected-domain provider;
in the MVP it is a no-op.
"""

from __future__ import annotations

from typing import Optional

from crossestate.manifest import ManifestEntry
from intelligence_contract import ReportViewModel

# Common two-label public suffixes so `a.co.uk` → registrable `a.co.uk`, not
# `co.uk`. Not a full PSL (no dependency); covers the frequent cases. Estate
# manifests usually list apex domains already, so this is a light safety net.
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "gov.au", "co.nz", "com.br", "co.jp", "co.za",
    "com.sg", "co.in", "com.mx", "com.tr",
}


class Assignment:
    """Resolved segment for one domain (a plain object; not persisted)."""
    __slots__ = ("domain", "segment", "source", "disagreement", "inferred_candidate")

    def __init__(self, domain: str, segment: str, source: str,
                 disagreement: bool = False, inferred_candidate: Optional[str] = None):
        self.domain = domain
        self.segment = segment
        self.source = source                       # supplied | inferred:apex | inferred:ns | inferred:reg | inferred:asn | default
        self.disagreement = disagreement
        self.inferred_candidate = inferred_candidate


def registrable(domain: str) -> str:
    """Best-effort registrable domain (apex). Heuristic, no PSL dependency."""
    d = (domain or "").strip().lower().rstrip(".")
    labels = [p for p in d.split(".") if p]
    if len(labels) <= 2:
        return d
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _cohort_label(vm: ReportViewModel) -> tuple[Optional[str], str]:
    """A fallback segment label from in-contract signals, strongest first.
    Returns (label, source_suffix)."""
    ann = vm.annotation
    if ann.ns_provider:
        return f"ns:{ann.ns_provider}", "inferred:ns"
    if vm.registration.registrar:
        return f"reg:{vm.registration.registrar}", "inferred:reg"
    if vm.trust.asn:
        return f"asn:{vm.trust.asn}", "inferred:asn"
    return None, "default"


def resolve_segments(
    entries: list[ManifestEntry],
    vms: dict[str, ReportViewModel],
) -> dict[str, Assignment]:
    """Map domain → Assignment. `vms` holds the loaded view-model per domain
    (a domain with a load error may be absent; it still gets a supplied/default
    assignment)."""
    # Apex → the set of distinct supplied tags seen on that apex (for reconciliation)
    apex_tags: dict[str, set[str]] = {}
    for e in entries:
        if e.segment:
            apex_tags.setdefault(registrable(e.domain), set()).add(e.segment)

    out: dict[str, Assignment] = {}
    for e in entries:
        apex = registrable(e.domain)
        if e.segment:
            # Supplied tag wins. Flag if a sibling on the same apex carries a
            # different tag (a registrable domain shouldn't span segments).
            siblings = apex_tags.get(apex, set())
            disagreement = len(siblings - {e.segment}) > 0
            out[e.domain] = Assignment(e.domain, e.segment, "supplied", disagreement)
            continue

        # Untagged → infer. (a) adopt a tagged apex-sibling's tag.
        sibling_tags = apex_tags.get(apex, set())
        if len(sibling_tags) == 1:
            tag = next(iter(sibling_tags))
            out[e.domain] = Assignment(e.domain, tag, "inferred:apex", inferred_candidate=tag)
            continue
        # (b) cohort label from contract signals; (c) else unassigned.
        vm = vms.get(e.domain)
        label, source = (_cohort_label(vm) if vm is not None else (None, "default"))
        if label:
            out[e.domain] = Assignment(e.domain, label, source, inferred_candidate=label)
        else:
            out[e.domain] = Assignment(e.domain, "unassigned", "default")
    return out


def infer_from_discovery(entries, vms, discovery=None):  # pragma: no cover - future hook
    """Extension point: reconcile segments against CRN / connected-domain
    discovery once a real DiscoveryProvider exists. No-op in the MVP."""
    return {}
