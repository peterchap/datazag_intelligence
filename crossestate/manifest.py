"""
crossestate/manifest.py
-----------------------
Load the estate manifest and the per-domain contract JSON files it points at.

The MVP input is a manifest (JSON or CSV) mapping `domain → segment (→ optional
metadata)` and pointing at pre-built per-domain contract JSON on disk — no live
scanning. Each contract file is either:
  * a `ReportViewModel.model_dump()` (preferred), or
  * a riskscore medallion payload (fallback → report_pipeline.view_model_from_medallion).

A per-file load failure is NON-FATAL: the domain is kept with a `load_error`
(counted in the estate size, excluded from the assessed analytics) so one bad
file never sinks the whole estate.

JSON manifest shape:
    {"group": "Acme Group",
     "domains": [
       {"domain": "acme.com", "segment": "corp", "contract_path": "contracts/acme.com.json",
        "limit": "5000000", "metadata": {...}},
       ...]}

CSV manifest shape (header row required):
    domain,segment,contract_path[,limit,...]
    acme.com,corp,contracts/acme.com.json,5000000
The group is taken from a leading `# group: <name>` comment line, else the
manifest filename stem.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from intelligence_contract import ReportViewModel


class ManifestEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    domain: str
    segment: Optional[str] = None            # authoritative customer tag when present
    contract_path: str
    limit: Optional[str] = None              # reserved for the insurer instance (limit-weighting)
    metadata: dict = Field(default_factory=dict)


def load_manifest(path: str) -> tuple[str, list[ManifestEntry]]:
    """Parse a JSON or CSV manifest → (group_name, entries). Paths in the
    manifest are resolved relative to the manifest file's directory."""
    ext = os.path.splitext(path)[1].lower()
    base = os.path.dirname(os.path.abspath(path))
    if ext == ".csv":
        group, rows = _load_csv(path)
    else:
        group, rows = _load_json(path)

    entries: list[ManifestEntry] = []
    for row in rows:
        e = ManifestEntry.model_validate(row)
        # Resolve contract_path relative to the manifest unless already absolute.
        if e.contract_path and not os.path.isabs(e.contract_path):
            e = e.model_copy(update={"contract_path": os.path.normpath(os.path.join(base, e.contract_path))})
        entries.append(e)
    return group, entries


def _load_json(path: str) -> tuple[str, list[dict]]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    group = doc.get("group") or os.path.splitext(os.path.basename(path))[0]
    rows = doc.get("domains") or doc.get("entries") or []
    return group, rows


def _load_csv(path: str) -> tuple[str, list[dict]]:
    group = os.path.splitext(os.path.basename(path))[0]
    rows: list[dict] = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lines = fh.readlines()
    # Optional leading `# group: <name>` directive(s); strip comment lines.
    data_lines: list[str] = []
    for ln in lines:
        s = ln.strip()
        if s.startswith("#"):
            if ":" in s:
                key, _, val = s.lstrip("#").strip().partition(":")
                if key.strip().lower() == "group" and val.strip():
                    group = val.strip()
            continue
        data_lines.append(ln)
    for row in csv.DictReader(data_lines):
        rows.append({k: (v.strip() if isinstance(v, str) else v)
                     for k, v in row.items() if k})
    return group, rows


# ---------------------------------------------------------------------------
# Contract loading (view-model dump preferred; medallion payload as fallback)
# ---------------------------------------------------------------------------

def load_contract(path: str) -> ReportViewModel:
    """Load one per-domain contract file into a ReportViewModel.

    Preferred: a `ReportViewModel.model_dump()`. Fallback: a riskscore medallion
    payload (detected by the `risk_assessment` + `schema_version` keys), rebuilt
    via report_pipeline.view_model_from_medallion. Raises on unreadable/unknown
    shapes — the caller turns that into a non-fatal `load_error`."""
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"contract {path!r} is not a JSON object")
    return contract_from_payload(payload)


def contract_from_payload(payload: dict) -> ReportViewModel:
    """Turn a loaded dict into a ReportViewModel. A medallion payload is rebuilt
    from the contract primitives; anything else is validated as a ReportViewModel
    dump. The rebuild deliberately uses intelligence_contract + findings_rules
    directly (not report_pipeline.view_model_from_medallion) so the loader never
    pulls in the render stack — it stays importable and testable on its own."""
    if _is_medallion(payload):
        from findings_rules import derive_findings
        from intelligence_contract import DomainIntelligence, build_view_models
        di = DomainIntelligence.model_validate(payload)
        return build_view_models(di, findings=derive_findings(di, []))
    return ReportViewModel.model_validate(payload)


def _is_medallion(payload: dict) -> bool:
    """A riskscore medallion payload (vs a ReportViewModel dump). Mirrors
    report_pipeline.is_medallion_payload."""
    return "risk_assessment" in payload and "schema_version" in payload
