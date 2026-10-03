"""
crossestate/estate_spec.py
--------------------------
The estate as the customer describes it: an owner (the sponsor: a VC, an
insurer's insured, an MSSP's client) and the entities in its estate, each with a
primary (website) domain and optionally more declared domains.

    owner:
      name: Osney Capital
      domain: osneycapital.com
    entities:
      - { name: Ploy, domain: ploy.io }
      - { name: Refute, domain: refute.com, domains: [refute.io] }

`manifest_rows()` turns it into the manifest rows estate_collect writes. Every row
carries `role` (owner | portfolio) and `entity` (the entity name), which the
analytics use to keep the owner out of every estate aggregate and the report
uses to build `entities[]`.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

ROLES = ("owner", "portfolio", "insured", "client")
_DOMAIN_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def _norm_domain(d: str) -> str:
    d = (d or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"not a domain name: {d!r}")
    return d


class EntitySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    domain: str                                   # primary (website) domain
    domains: list[str] = Field(default_factory=list)   # further declared domains

    @field_validator("domain")
    @classmethod
    def _d(cls, v):
        return _norm_domain(v)

    @field_validator("domains")
    @classmethod
    def _ds(cls, v):
        return [_norm_domain(x) for x in v]

    @property
    def all_domains(self) -> list[str]:
        out = [self.domain]
        out += [d for d in self.domains if d not in out]
        return out


class EstateSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group: Optional[str] = None
    owner: Optional[EntitySpec] = None
    entities: list[EntitySpec]
    entity_role: str = "portfolio"                # owner's estate members' role

    @field_validator("entity_role")
    @classmethod
    def _role(cls, v):
        if v not in ROLES or v == "owner":
            raise ValueError(f"entity_role must be one of {ROLES[1:]}")
        return v

    def model_post_init(self, _ctx) -> None:
        seen: dict[str, str] = {}
        everyone = ([self.owner] if self.owner else []) + list(self.entities)
        for e in everyone:
            for d in e.all_domains:
                if d in seen:
                    raise ValueError(f"{d} is declared for both {seen[d]!r} and {e.name!r}")
                seen[d] = e.name

    @property
    def group_name(self) -> str:
        return self.group or (self.owner.name if self.owner else "estate")

    def manifest_rows(self, contracts_dir: str = "contracts") -> list[dict]:
        rows = []
        if self.owner:
            for d in self.owner.all_domains:
                rows.append({"domain": d, "entity": self.owner.name, "role": "owner",
                             "primary": d == self.owner.domain,
                             "contract_path": f"{contracts_dir}/{d}.json"})
        for e in self.entities:
            for d in e.all_domains:
                rows.append({"domain": d, "entity": e.name, "role": self.entity_role,
                             "primary": d == e.domain,
                             "contract_path": f"{contracts_dir}/{d}.json"})
        return rows

    def owner_block(self) -> Optional[dict]:
        return ({"name": self.owner.name, "domain": self.owner.domain}
                if self.owner else None)


def load_estate_spec(path: str) -> EstateSpec:
    """Load an estate spec from YAML (.yaml/.yml) or JSON."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if os.path.splitext(path)[1].lower() in (".yaml", ".yml"):
        import yaml
        doc = yaml.safe_load(text) or {}
    else:
        doc = json.loads(text)
    return EstateSpec.model_validate(doc)
