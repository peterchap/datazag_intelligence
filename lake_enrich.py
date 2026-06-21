"""
lake_enrich.py
--------------
Canonical per-domain enrichment from DuckLake — the SAME tables the alerting
system and analytics read, so every pane of glass agrees. One connection, a
handful of keyed lookups; no re-implemented join logic where a view exists.

    bundle = enrich(domain, rec)   # rec = celery DNSRecords-as-dict (live DNS)

Returns a dict:
    {
      "labels": {...},          # v_annotated (or parameterized fallback for new domains)
      "domain_risk": {...},     # gold.gold_risk_domain
      "scenario": {...},        # gold.scenario_domain_intel / scenario_weaponization / scenario_mx_intel
      "rdap": {...},            # intel.domain_rdap
      "impersonation": [...],   # ref.platform_impersonation for detected platforms
      "abuse": {...},           # intel.tld_registrar_abuse_contacts / asn_abuse_contacts
    }

Connection: dnsproject/scripts/ducklake_conn.connect() by default (the catalog
with gold.*/intel.*/ref.*/main.v_annotated). Override via LAKE_CONNECT if the
report should bind a different attachment.

Env:
    DNSPROJECT_PATH   path to dnsproject (default /root/dnsproject)
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional


def _connect():
    dns_path = os.environ.get("DNSPROJECT_PATH", "/root/dnsproject")
    if dns_path not in sys.path:
        sys.path.insert(0, dns_path)
    from scripts.ducklake_conn import connect  # type: ignore
    return connect()


def _one(con, sql: str, params: list) -> Optional[dict]:
    cur = con.execute(sql, params)
    cols = [d[0] for d in cur.description]
    row = cur.fetchone()
    return dict(zip(cols, row)) if row else None


def _all(con, sql: str, params: list) -> list[dict]:
    cur = con.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _platform_terms(platforms: list[str]) -> list[str]:
    return sorted({p.strip().lower() for p in (platforms or []) if p and p.strip()})


def enrich(domain: str, rec: dict | None = None, platforms: Optional[list[str]] = None) -> dict:
    rec = rec or {}
    d = domain.strip().lower()
    con = _connect()
    out: dict[str, Any] = {}
    try:
        # --- Labels / fronting (canonical view; fallback for non-corpus domains) ---
        labels = _one(con, """
            SELECT mailbox_provider, mailbox_category, mailbox_role,
                   ns_provider, ns_category, cloud_provider, cloud_class,
                   cname_provider, hosting_provider, hosting_class,
                   is_fronted, ip_score_confidence, infra_asn, prefix_infra_score,
                   infra_core_risk, infra_core_effective, ip_risk_score, ip_risk_reason,
                   tld_risk_level, is_parked, trust_label, mailbox_label, hosting_label
            FROM main.v_annotated WHERE domain = ? LIMIT 1
        """, [d])
        out["labels"] = labels or _labels_fallback(con, d, rec)
        out["labels_source"] = "v_annotated" if labels else "live"

        # --- Domain risk + verdict ---
        gr = _one(con, "SELECT domain_risk_score, domain_risk_context FROM gold.gold_risk_domain WHERE domain = ?", [d])
        if gr and isinstance(gr.get("domain_risk_context"), str):
            try: gr["domain_risk_context"] = json.loads(gr["domain_risk_context"])
            except Exception: pass
        out["domain_risk"] = gr

        # --- Threat decomposition / liveness ---
        out["scenario"] = {
            "domain_intel": _one(con, """
                SELECT dangling_cname_risk, fast_flux_risk, tld_registrar_risk, dga_risk,
                       concentration_risk, certstream_risk, combined_risk, details
                FROM gold.scenario_domain_intel WHERE domain = ?""", [d]),
            "weaponization": _one(con, """
                SELECT weaponization_score, threat_intent, evasion_tactic, is_live
                FROM gold.scenario_weaponization WHERE domain = ?""", [d]),
            "mx_intel": _one(con, "SELECT mx_risk_score, mx_risk_context FROM gold.scenario_mx_intel WHERE domain = ?", [d]),
        }

        # --- Registration / age ---
        out["rdap"] = _one(con, """
            SELECT registrar, registered_date, expires_date, dnssec, status, rdap_risk_score, abuse_email
            FROM intel.domain_rdap WHERE domain = ?""", [d])

        # --- Platform impersonation (current rollup: hits + distinct impersonating domains) ---
        terms = _platform_terms(platforms or [])
        out["impersonation"] = _all(con, """
            SELECT platform, category, hits, impersonating_domains, loaded_at
            FROM ref.platform_impersonation WHERE lower(platform) = ANY(?)
            ORDER BY impersonating_domains DESC""", [terms]) if terms else []

        # --- Abuse contacts (remediation routing) ---
        tld = (out.get("rdap") or {}).get("tld") or d.rsplit(".", 1)[-1]
        registrar = (out.get("rdap") or {}).get("registrar")
        out["abuse"] = {
            "tld_registrar": _one(con, """
                SELECT abuse_email, abuse_url FROM intel.tld_registrar_abuse_contacts
                WHERE tld = ? AND (registrar = ? OR ? IS NULL) LIMIT 1""", [tld, registrar, registrar]),
        }
        infra_asn = (out.get("labels") or {}).get("infra_asn")
        if infra_asn:
            out["abuse"]["asn"] = _one(con, """
                SELECT abuse_email, abuse_phone FROM intel.asn_abuse_contacts WHERE asn_number = ? LIMIT 1""", [int(infra_asn)])
    finally:
        con.close()
    return out


def _labels_fallback(con, domain: str, rec: dict) -> dict:
    """Parameterized labelling for domains not in the corpus, from the live DNS —
    same ref tables v_annotated uses. Best-effort; mailbox/NS/TLD are the high-value ones."""
    mx_host = (rec.get("mx_host_final") or rec.get("mx") or "").lower()
    mx_regdom = (rec.get("mx_regdom_final") or "").lower()
    ns = (rec.get("ns1") or "").lower()
    tld = domain.rsplit(".", 1)[-1]
    out: dict[str, Any] = {"_fallback": True}

    mbx = _one(con, """
        SELECT provider, category, provider_role FROM ref.provider_catalog
        WHERE (match_type='host' AND ((match_kind='exact' AND lower(?)=key)
              OR (match_kind IN ('suffix','regex') AND ends_with(lower(?), key))))
           OR (match_type='regdom' AND lower(?)=key)
        ORDER BY CASE match_type WHEN 'host' THEN 0 ELSE 1 END,
                 CASE match_kind WHEN 'exact' THEN 0 ELSE 1 END LIMIT 1
    """, [mx_host, mx_host, mx_regdom]) if mx_host or mx_regdom else None
    if mbx:
        out["mailbox_provider"], out["mailbox_category"], out["mailbox_role"] = mbx["provider"], mbx["category"], mbx.get("provider_role")

    nsb = _one(con, """
        SELECT provider, category FROM ref.provider_catalog
        WHERE match_type='ns_brand' AND ? <> '' AND lower(?) LIKE '%' || key || '%'
        ORDER BY length(key) DESC LIMIT 1""", [ns, ns]) if ns else None
    if nsb:
        out["ns_provider"], out["ns_category"] = nsb["provider"], nsb["category"]

    tr = _one(con, "SELECT tld_risk_level FROM ref.tld_risk WHERE tld = ? LIMIT 1", [tld])
    if tr:
        out["tld_risk_level"] = tr["tld_risk_level"]
    return out


# ---------------------------------------------------------------------------
# Map the lake bundle (+ live celery DNS) into intelligence_contract models so
# report_pipeline can pass them straight into build_view_models().
# ---------------------------------------------------------------------------

def to_view_models(rec: dict, bundle: dict) -> dict:
    """Returns {annotation, registration, hygiene, abuse, impersonations, weaponization}
    ready to splat into build_view_models()."""
    from intelligence_contract import (  # local import: contract lives alongside
        Annotation, Registration, DnsHygiene, AbuseContacts, PlatformImpersonation,
    )

    rec = rec or {}
    labels = bundle.get("labels") or {}
    rdap = bundle.get("rdap") or {}
    abuse = bundle.get("abuse") or {}
    scen = (bundle.get("scenario") or {})
    weap = scen.get("weaponization") or {}

    annotation = Annotation(domain=rec.get("domain", ""), **labels)

    reg_in = dict(rdap)
    reg_in["domain_age_days"] = _age_days(rdap.get("registered_date"))
    # dates → iso strings for the model
    for k in ("registered_date", "expires_date"):
        if reg_in.get(k) is not None:
            reg_in[k] = str(reg_in[k])
    registration = Registration(**reg_in)

    spf = (rec.get("spf") or "")
    dmarc = (rec.get("dmarc") or "")
    hygiene = DnsHygiene(
        spf_record=rec.get("spf") or None,
        spf_strict="-all" in spf.lower(),
        dmarc_record=rec.get("dmarc") or None,
        dmarc_policy=_dmarc_policy(dmarc),
        dnssec=bool(rec.get("dnssec")),
        mta_sts_mode=rec.get("mta_sts_mode") or None,
        tlsrpt_present=bool(rec.get("tlsrpt_rua")),
        bimi_present=bool(rec.get("bimi")),
        caa_present=bool(rec.get("caa")),
        tls_issuer=rec.get("https_cert_issuer"),
        tls_days_left=rec.get("https_cert_days_left"),
        has_security_txt=bool(rec.get("has_security_txt")),
    )

    tldr = abuse.get("tld_registrar") or {}
    asnc = abuse.get("asn") or {}
    abuse_model = AbuseContacts(
        registrar_abuse_email=tldr.get("abuse_email"),
        registrar_abuse_url=tldr.get("abuse_url"),
        asn_abuse_email=asnc.get("abuse_email"),
        asn_abuse_phone=asnc.get("abuse_phone"),
    )

    imps = [
        PlatformImpersonation(
            platform=r.get("platform", ""),
            category=r.get("category") or "",
            impersonating_domains=int(r.get("impersonating_domains") or 0),
            hits=int(r.get("hits") or 0),
            count_30d=int(r.get("impersonating_domains") or 0),  # current proxy until windowed
        )
        for r in (bundle.get("impersonation") or [])
    ]

    return {
        "annotation": annotation,
        "registration": registration,
        "hygiene": hygiene,
        "abuse": abuse_model,
        "impersonations": imps,
        "weaponization": weap,
    }


def _dmarc_policy(dmarc: str) -> Optional[str]:
    for part in (dmarc or "").lower().split(";"):
        part = part.strip()
        if part.startswith("p="):
            return part[2:].strip() or None
    return None


def _age_days(registered_date) -> Optional[int]:
    if not registered_date:
        return None
    try:
        from datetime import date, datetime
        if isinstance(registered_date, str):
            d = datetime.fromisoformat(registered_date[:10]).date()
        elif isinstance(registered_date, datetime):
            d = registered_date.date()
        elif isinstance(registered_date, date):
            d = registered_date
        else:
            return None
        return (date.today() - d).days
    except Exception:
        return None
