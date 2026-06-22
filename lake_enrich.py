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

import ipaddress
import json
import os
import sys
from typing import Any, Optional

import duckdb

LAKE = "datazag_lake2"


def _add_s3_over_r2_secret(con) -> None:
    """Some managed tables in this catalog record their parquet paths with the s3://
    scheme even though the data lives in the Cloudflare R2 bucket. A TYPE R2 secret
    only matches r2:// URLs, so s3://<bucket>/... misses it and falls back to AWS S3
    (datazag-lake.s3.amazonaws.com) and 404s. Add a TYPE S3 secret pointing at the R2
    endpoint, scoped to the bucket, so those s3:// reads resolve to R2. Accepts either
    credential naming (R2_ACCESS_KEY_ID/.. or R2_ACCESS_KEY/..)."""
    account = os.environ.get("R2_ACCOUNT_ID")
    key = os.environ.get("R2_ACCESS_KEY_ID") or os.environ.get("R2_ACCESS_KEY")
    secret = os.environ.get("R2_SECRET_ACCESS_KEY") or os.environ.get("R2_SECRET_KEY")
    if not (account and key and secret):
        return
    bucket = os.environ.get("DUCKLAKE_S3_BUCKET", "datazag-lake")
    endpoint = f"{account}.r2.cloudflarestorage.com"
    try:
        con.execute(
            """CREATE OR REPLACE SECRET s3_over_r2 (
                   TYPE S3, KEY_ID ?, SECRET ?, ENDPOINT ?,
                   URL_STYLE 'path', REGION 'auto', SCOPE ?
               );""",
            [key, secret, endpoint, f"s3://{bucket}"],
        )
    except duckdb.Error as e:
        print(f"  lake: could not add s3-over-r2 secret - {str(e).splitlines()[0]}")


def lake_connect():
    """Self-contained DuckLake connection: install/load the extensions, add the R2
    secret, ATTACH the catalog, USE it. Mirrors the dnsproject ducklake_conn so the
    report doesn't depend on dnsproject being importable.

    Env:
      DUCKLAKE_NEON_DSN   postgres conninfo (the string after 'ducklake:postgres:'),
                          e.g. "dbname=neondb host=... user=... password=... sslmode=require"
      DUCKLAKE_DATA_PATH  R2 data path (default r2://datazag-lake/data/)
      R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY / R2_ACCOUNT_ID   R2 credentials

    Falls back to dnsproject's ducklake_conn.connect() if DUCKLAKE_NEON_DSN is unset.
    """
    dsn = os.environ.get("DUCKLAKE_NEON_DSN")
    if not dsn:
        dns_path = os.environ.get("DNSPROJECT_PATH", "/root/dnsproject")
        if dns_path not in sys.path:
            sys.path.insert(0, dns_path)
        from scripts.ducklake_conn import connect  # type: ignore
        con = connect()  # loads .env (sets R2_* in os.environ) + creates the r2:// secret
        _add_s3_over_r2_secret(con)
        return con

    data_path = os.environ.get("DUCKLAKE_DATA_PATH", "r2://datazag-lake/data/")
    con = duckdb.connect(":memory:")
    for ext in ("ducklake", "postgres", "httpfs"):
        con.execute(f"INSTALL {ext};")
        con.execute(f"LOAD {ext};")

    # Accept both credential namings: the report's own (R2_ACCESS_KEY_ID/
    # R2_SECRET_ACCESS_KEY) and dnsproject's .env (R2_ACCESS_KEY/R2_SECRET_KEY).
    # Without this the TYPE R2 secret silently isn't created and r2:// reads fall
    # back to the AWS S3 endpoint (datazag-lake.s3.amazonaws.com) -> 404.
    key_id = os.environ.get("R2_ACCESS_KEY_ID") or os.environ.get("R2_ACCESS_KEY")
    secret = os.environ.get("R2_SECRET_ACCESS_KEY") or os.environ.get("R2_SECRET_KEY")
    account = os.environ.get("R2_ACCOUNT_ID")
    if key_id and secret and account:
        con.execute(
            "CREATE OR REPLACE SECRET r2_lake (TYPE R2, KEY_ID ?, SECRET ?, ACCOUNT_ID ?);",
            [key_id, secret, account],
        )
    # Belt-and-suspenders: also resolve any s3://<bucket>/... path to the R2 endpoint.
    _add_s3_over_r2_secret(con)

    con.execute(f"ATTACH 'ducklake:postgres:{dsn}' AS {LAKE} (DATA_PATH '{data_path}');")
    con.execute(f"USE {LAKE};")
    return con


def _one(con, sql: str, params: list) -> Optional[dict]:
    cur = con.execute(sql, params)
    cols = [d[0] for d in cur.description]
    row = cur.fetchone()
    return dict(zip(cols, row)) if row else None


def _all(con, sql: str, params: list) -> list[dict]:
    cur = con.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _safe(label: str, fn, default=None):
    """Run a lake-query thunk, degrading to `default` if the schema/table is missing
    in the attached catalog (e.g. ref/intel/gold not yet loaded). Keeps one missing
    feature from aborting the whole enrichment bundle; real errors still surface."""
    try:
        return fn()
    except duckdb.Error as e:
        # Any lake-side failure (missing schema/table, or a dead R2 data path /
        # HTTP 404 on a table's parquet files) degrades this section, not the run.
        msg = str(e).splitlines()[0] if str(e) else e.__class__.__name__
        print(f"  lake: '{label}' unavailable - {msg}")
        return default


def _platform_terms(platforms: list[str]) -> list[str]:
    return sorted({p.strip().lower() for p in (platforms or []) if p and p.strip()})


def _first_ip(rec: dict) -> Optional[str]:
    a = rec.get("a") or rec.get("a_list")
    if isinstance(a, list):
        return a[0] if a else None
    return (str(a).split(",")[0].strip() or None) if a else None


def _ip_int(ip: str) -> Optional[int]:
    try:
        addr = ipaddress.ip_address(ip)
        return int(addr) if addr.version == 4 else None
    except ValueError:
        return None


def _resolve_infra(con, rec: dict) -> Optional[dict]:
    """Hosting network facts for the domain's primary web IP — the lake fallback
    for ASN / country / prefix when the medallion's facts are sparse."""
    ip = _first_ip(rec)
    if not ip:
        return None
    n = _ip_int(ip)
    if n is None:
        return None
    try:
        return _one(con, """
            SELECT a.asn, a.isp, a.isp_country, a.asn_risk_level, a.prefix, ai.asn_name
            FROM gold.asn_ip4 a
            LEFT JOIN intel.asn_intel ai ON ai.asn_number = a.asn
            WHERE ? BETWEEN a.start_int AND a.end_int
            LIMIT 1
        """, [n])
    except Exception:
        return None


def enrich(domain: str, rec: dict | None = None, platforms: Optional[list[str]] = None) -> dict:
    rec = rec or {}
    d = domain.strip().lower()
    con = lake_connect()
    out: dict[str, Any] = {}
    try:
        # --- Labels / fronting (corpus view; parameterized fallback otherwise) ---
        # main.v_annotated is a view over the dns_expanded corpus; it may be absent,
        # or present but unreadable (its parquet files on a dead/old R2 path). Either
        # way, degrade to the live parameterized fallback rather than aborting the run.
        labels = None
        try:
            labels = _one(con, """
                SELECT mailbox_provider, mailbox_category, mailbox_role,
                       ns_provider, ns_category, cloud_provider, cloud_class,
                       cname_provider, hosting_provider, hosting_class,
                       is_fronted, ip_score_confidence, infra_asn, prefix_infra_score,
                       infra_core_risk, infra_core_effective, ip_risk_score, ip_risk_reason,
                       tld_risk_level, is_parked, trust_label, mailbox_label, hosting_label
                FROM main.v_annotated WHERE domain = ? LIMIT 1
            """, [d])
        except duckdb.Error:
            pass
        # The fallback reads ref.* heavily; if the ref schema isn't loaded in this
        # catalog, degrade labels to empty rather than aborting the whole bundle.
        out["labels"] = labels or _safe("labels", lambda: _labels_fallback(con, d, rec), {})
        out["labels_source"] = "v_annotated" if labels else "live"

        # --- Hosting network facts (ASN/country/prefix) from the routing table ---
        out["infra"] = _resolve_infra(con, rec)

        # --- Domain risk + verdict ---
        gr = _safe("domain_risk", lambda: _one(con,
            "SELECT domain_risk_score, domain_risk_context FROM gold.gold_risk_domain WHERE domain = ?", [d]))
        if gr and isinstance(gr.get("domain_risk_context"), str):
            try: gr["domain_risk_context"] = json.loads(gr["domain_risk_context"])
            except Exception: pass
        out["domain_risk"] = gr

        # --- Threat decomposition / liveness ---
        out["scenario"] = {
            "domain_intel": _safe("scenario_domain_intel", lambda: _one(con, """
                SELECT dangling_cname_risk, fast_flux_risk, tld_registrar_risk, dga_risk,
                       concentration_risk, certstream_risk, combined_risk, details
                FROM gold.scenario_domain_intel WHERE domain = ?""", [d])),
            "weaponization": _safe("scenario_weaponization", lambda: _one(con, """
                SELECT weaponization_score, threat_intent, evasion_tactic, is_live
                FROM gold.scenario_weaponization WHERE domain = ?""", [d])),
            "mx_intel": _safe("scenario_mx_intel", lambda: _one(con,
                "SELECT mx_risk_score, mx_risk_context FROM gold.scenario_mx_intel WHERE domain = ?", [d])),
        }

        # --- Registration / age ---
        out["rdap"] = _safe("domain_rdap", lambda: _one(con, """
            SELECT registrar, registered_date, expires_date, dnssec, status, rdap_risk_score, abuse_email
            FROM intel.domain_rdap WHERE domain = ?""", [d]))

        # --- Platform impersonation (current rollup: hits + distinct impersonating domains) ---
        terms = _platform_terms(platforms or [])
        out["impersonation"] = _safe("platform_impersonation", lambda: _all(con, """
            SELECT platform, category, hits, impersonating_domains, loaded_at
            FROM ref.platform_impersonation WHERE lower(platform) = ANY(?)
            ORDER BY impersonating_domains DESC""", [terms]), []) if terms else []

        # --- Abuse contacts (remediation routing) ---
        tld = (out.get("rdap") or {}).get("tld") or d.rsplit(".", 1)[-1]
        registrar = (out.get("rdap") or {}).get("registrar")
        out["abuse"] = {
            "tld_registrar": _safe("tld_registrar_abuse_contacts", lambda: _one(con, """
                SELECT abuse_email, abuse_url FROM intel.tld_registrar_abuse_contacts
                WHERE tld = ? AND (registrar = ? OR ? IS NULL) LIMIT 1""", [tld, registrar, registrar])),
        }
        infra_asn = (out.get("labels") or {}).get("infra_asn")
        if infra_asn:
            out["abuse"]["asn"] = _safe("asn_abuse_contacts", lambda: _one(con, """
                SELECT abuse_email, abuse_phone FROM intel.asn_abuse_contacts WHERE asn_number = ? LIMIT 1""", [int(infra_asn)]))
    finally:
        con.close()
    return out


def _labels_fallback(con, domain: str, rec: dict) -> dict:
    """Parameterized labelling from the live DNS, computed over the same ref/gold base
    tables that v_enriched/v_annotated join — so the report gets the FULL label set
    (hosting / fronting / IP reputation / taxonomy display labels / trust verdict) for
    any domain, not just mailbox/NS/TLD. This is the authoritative path here: v_annotated
    is a scan-time view over a bound live `src`, not a persistent per-domain lake table,
    so we reproduce its joins per-domain rather than SELECT from it. Mirrors
    dnsproject/scripts/annotation_views.py (enriched_sql / annotated_sql)."""
    mx_host = (rec.get("mx_host_final") or rec.get("mx") or "").lower()
    mx_regdom = (rec.get("mx_regdom_final") or "").lower()
    ns = (rec.get("ns1") or rec.get("ns") or "").lower()
    cname = (rec.get("cname") or "").lower()
    tld = domain.rsplit(".", 1)[-1]
    out: dict[str, Any] = {"_fallback": True}

    # --- mailbox provider: MX host (exact > suffix) beats MX regdom (provider_catalog) ---
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

    # --- nameserver brand: substring of the brand slug in the NS host ---
    nsb = _one(con, """
        SELECT provider, category FROM ref.provider_catalog
        WHERE match_type='ns_brand' AND ? <> '' AND lower(?) LIKE '%' || key || '%'
        ORDER BY length(key) DESC LIMIT 1""", [ns, ns]) if ns else None
    if nsb:
        out["ns_provider"], out["ns_category"] = nsb["provider"], nsb["category"]

    # --- TLD risk ---
    tr = _one(con, "SELECT tld_risk_level FROM ref.tld_risk WHERE tld = ? LIMIT 1", [tld])
    if tr:
        out["tld_risk_level"] = tr["tld_risk_level"]

    # --- IP-derived signals (mirrors ip_attributes_sql: cloud range, ASN/prefix, IP risk) ---
    ip = _first_ip(rec)
    n = _ip_int(ip) if ip else None
    cloud = asnmap = iprisk = None
    if n is not None:
        cloud = _one(con, """
            SELECT provider, class FROM ref.cloud_ranges
            WHERE family=4 AND ? BETWEEN start_int AND end_int
            ORDER BY (class='cdn') DESC, (end_int - start_int) ASC LIMIT 1""", [n])
        asnmap = _one(con, """
            SELECT asn, prefix, asn_risk_level FROM gold.asn_ip4
            WHERE ? BETWEEN start_int AND end_int
            ORDER BY (end_int - start_int) ASC LIMIT 1""", [n])
        iprisk = _one(con, """
            SELECT risk_score, risk_reason FROM ref.ip_risk
            WHERE ? BETWEEN start_int AND end_int
            ORDER BY (end_int - start_int) ASC LIMIT 1""", [n])

    if cloud:
        out["cloud_provider"], out["cloud_class"] = cloud["provider"], cloud["class"]
    if iprisk:
        out["ip_risk_score"], out["ip_risk_reason"] = iprisk.get("risk_score"), iprisk.get("risk_reason")

    infra_core_risk = None
    if asnmap:
        out["infra_asn"] = asnmap.get("asn")
        out["asn_risk_level"] = asnmap.get("asn_risk_level")
        if asnmap.get("prefix"):
            gp = _one(con, "SELECT infra_score FROM gold.gold_risk_prefix WHERE prefix = ? LIMIT 1", [asnmap["prefix"]])
            if gp:
                out["prefix_infra_score"] = gp.get("infra_score")
        if asnmap.get("asn") is not None:
            ga = _one(con, "SELECT core_risk FROM gold.gold_risk_asn WHERE asn = ? LIMIT 1", [int(asnmap["asn"])])
            if ga:
                infra_core_risk = ga.get("core_risk")
                out["infra_core_risk"] = infra_core_risk

    # --- CNAME fronting (ref.cdn_cnames; cname already lowercased) ---
    cn = _one(con, """
        SELECT provider, class FROM ref.cdn_cnames
        WHERE ends_with(?, cname_suffix)
        ORDER BY length(cname_suffix) DESC LIMIT 1""", [cname]) if cname else None
    if cn:
        out["cname_provider"], out["cname_class"] = cn["provider"], cn["class"]

    # --- hosting = cloud first, else CNAME; SCORE-2 fronting/confidence ---
    out["hosting_provider"] = (cloud or {}).get("provider") or (cn or {}).get("provider")
    out["hosting_class"] = (cloud or {}).get("class") or (cn or {}).get("class")
    is_fronted = ((cloud or {}).get("class") == "cdn") or ((cn or {}).get("class") == "cdn")
    out["is_fronted"] = is_fronted
    out["ip_score_confidence"] = "low" if is_fronted else "high"
    # behind a CDN the A-record IP is the CDN's, not the actor's -> drop the infra signal
    out["infra_core_effective"] = None if is_fronted else infra_core_risk

    # --- parked: NS/CNAME indicators OR the NS resolves to a parking brand ---
    is_parked = (out.get("ns_category") or "").lower() == "parking"
    if not is_parked and (ns or cname):
        pk = _one(con, """
            SELECT 1 FROM ref.parked_indicators
            WHERE (indicator_type='NS' AND ? <> '' AND (
                      (match_type='exact' AND ? = lower(pattern)) OR
                      (match_type='like'  AND ? LIKE lower(pattern))))
               OR (indicator_type='CNAME' AND ? <> '' AND (
                      (match_type='exact' AND ? = lower(pattern)) OR
                      (match_type='like'  AND ? LIKE lower(pattern))))
            LIMIT 1""", [ns, ns, ns, cname, cname, cname])
        is_parked = bool(pk)
    out["is_parked"] = is_parked

    # --- taxonomy display labels + trust hints (ref.taxonomy_map / category_alias) ---
    hosting_trust = mailbox_trust = 0
    hclass = out.get("hosting_class")
    if hclass:
        ti = _one(con, """
            SELECT display_label, trust_hint FROM ref.taxonomy_map
            WHERE key_type='infra' AND internal_key = ? LIMIT 1""", [hclass])
        if ti:
            out["hosting_label"] = ti.get("display_label")
            hosting_trust = ti.get("trust_hint") or 0
    mcat = out.get("mailbox_category")
    if mcat:
        tm = _one(con, """
            SELECT tm.display_label, tm.trust_hint
            FROM ref.category_alias ca
            JOIN ref.taxonomy_map tm
              ON tm.key_type = ca.key_type AND tm.internal_key = ca.internal_key
            WHERE ca.raw_category = lower(trim(?)) LIMIT 1""", [mcat])
        if tm:
            out["mailbox_label"] = tm.get("display_label")
            mailbox_trust = tm.get("trust_hint") or 0

    # --- headline verdict (mirrors annotated_sql.trust_label) ---
    ip_risk_score = (iprisk or {}).get("risk_score") or 0
    trust = (hosting_trust or 0) + (mailbox_trust or 0)
    if is_parked:
        out["trust_label"] = "Parked"
    elif ip_risk_score >= 80:
        out["trust_label"] = "High Risk"
    elif out.get("tld_risk_level") == "critical":
        out["trust_label"] = "Suspicious TLD"
    elif trust >= 5:
        out["trust_label"] = "Trusted"
    elif trust <= -5:
        out["trust_label"] = "High Risk"
    else:
        out["trust_label"] = "Unverified"

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
    infra = bundle.get("infra") or {}
    rdap = bundle.get("rdap") or {}
    abuse = bundle.get("abuse") or {}
    scen = (bundle.get("scenario") or {})
    weap = scen.get("weaponization") or {}

    # Merge hosting-network facts (asn_ip4) onto the annotation so the infra block
    # populates from the lake when the medallion is sparse.
    ann_in = dict(labels)
    ann_in["asn"] = infra.get("asn") or labels.get("infra_asn")
    ann_in["asn_name"] = infra.get("asn_name") or infra.get("isp")
    ann_in["isp_country"] = infra.get("isp_country")
    ann_in["prefix"] = infra.get("prefix")
    ann_in.setdefault("asn_risk_level", infra.get("asn_risk_level"))
    annotation = Annotation(domain=rec.get("domain", ""), **ann_in)

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
