"""
crossestate/analytics.py
------------------------
The five cross-estate analytics (spec §2.2–2.6) as pure, deterministic
aggregations over the loaded per-domain view-models. Each function takes the
estate's `DomainRef` list plus `EstateThresholds` and returns a typed block.

Every read is defensive: the per-domain contract fields are all Optional/
defaulted, so a missing value is skipped or bucketed as "unknown" — never
raised, and never fabricated into a finding. Only domains with
`vm.has_intelligence` are counted in the assessed denominators (an unscanned
domain must not read as a great grade or a passing control).
"""

from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Iterable, Optional

from crossestate.contract import (
    CalendarBlock,
    CalendarItem,
    ConcentrationDim,
    EstateThresholds,
    ExposureRollup,
    ProviderShare,
    ScoreStats,
    SegmentPosture,
    TargetedPlatform,
    VarianceBlock,
    WeaknessPrevalence,
)
from crossestate.contract import DomainRef
from healthreport.grade import score_to_grade

_GRADE_INDEX = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5}


def _assessed(refs: Iterable[DomainRef]) -> list[DomainRef]:
    return [r for r in refs if getattr(r.vm, "has_intelligence", False) and not r.load_error]


def _grade_index(letter: str) -> Optional[int]:
    return _GRADE_INDEX.get(letter)


# ---------------------------------------------------------------------------
# §2.2 Concentration & accumulation
# ---------------------------------------------------------------------------

_CONC_DIMS = (
    ("mailbox", "Email / mailbox platform"),
    ("ns", "Nameserver / DNS provider"),
    ("registrar", "Registrar"),
    ("asn", "Hosting network (ASN)"),
    ("hosting", "Hosting provider"),
    ("ca_issuer", "Certificate authority"),
)


def _dim_value(dimension: str, ref: DomainRef) -> Optional[str]:
    vm = ref.vm
    if dimension == "mailbox":
        return vm.annotation.mailbox_provider or (vm.trust.mx_type if vm.trust.mx_type not in (None, "", "unknown") else None)
    if dimension == "ns":
        return vm.annotation.ns_provider
    if dimension == "registrar":
        return vm.registration.registrar
    if dimension == "asn":
        if vm.trust.asn:
            return f"AS{vm.trust.asn}" + (f" {vm.trust.isp}" if vm.trust.isp else "")
        return None
    if dimension == "hosting":
        return vm.annotation.hosting_provider
    return None


def _ca_issuers(ref: DomainRef) -> set[str]:
    """The set of CA issuers seen for a domain (a domain may hold several).
    Guards the two plausible `issuer_breakdown` shapes."""
    ca = ref.vm.cert_analysis or {}
    ib = ca.get("issuer_breakdown")
    out: set[str] = set()
    if isinstance(ib, dict):
        out.update(str(k) for k in ib.keys() if k)
    elif isinstance(ib, list):
        for item in ib:
            if isinstance(item, dict):
                name = item.get("issuer") or item.get("name") or item.get("ca")
                if name:
                    out.add(str(name))
            elif item:
                out.add(str(item))
    return out


def compute_concentration(refs: list[DomainRef], thresholds: EstateThresholds) -> list[ConcentrationDim]:
    assessed = _assessed(refs)
    dims: list[ConcentrationDim] = []
    for key, label in _CONC_DIMS:
        counts: dict[str, int] = {}
        denom = 0
        for r in assessed:
            if key == "ca_issuer":
                issuers = _ca_issuers(r)
                if not issuers:
                    continue
                denom += 1
                for iss in issuers:
                    counts[iss] = counts.get(iss, 0) + 1
            else:
                val = _dim_value(key, r)
                if not val:
                    continue
                denom += 1
                counts[val] = counts.get(val, 0) + 1

        shares = [
            ProviderShare(
                provider=p, count=c,
                pct=(c / denom if denom else 0.0),
                flagged=(denom > 0 and c / denom >= thresholds.concentration_flag_pct),
            )
            for p, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]
        top = shares[0] if shares else None
        dims.append(ConcentrationDim(
            dimension=key, label=label, shares=shares,
            top_provider=(top.provider if top else None),
            top_pct=(top.pct if top else 0.0),
            denom=denom,
            flagged=bool(top and top.flagged),
        ))
    return dims


# ---------------------------------------------------------------------------
# §2.3 Correlated weakness
# ---------------------------------------------------------------------------

def _is_weak(control: str, ref: DomainRef) -> bool:
    vm = ref.vm
    if control == "dmarc":
        pol = (vm.hygiene.dmarc_policy or "").lower()
        if pol:
            return pol not in ("reject", "quarantine")
        return bool(vm.trust.dmarc_risk)
    if control == "spf":
        # spf_strict True == strict; fall back to the medallion risk flag.
        return not vm.hygiene.spf_strict if vm.hygiene.spf_record else bool(vm.trust.spf_risk)
    if control == "dnssec":
        return not (vm.registration.dnssec or vm.hygiene.dnssec)
    if control == "caa":
        return not vm.hygiene.caa_present
    if control == "internal_ip_leak":
        return _leak_count(ref) > 0
    if control == "dangling_subdomain":
        return _dangling_count(ref) > 0
    return False


def _leak_count(ref: DomainRef) -> int:
    n = 0
    for s in (ref.vm.subdomains or []):
        if not isinstance(s, dict):
            continue
        note = (s.get("note") or "").lower()
        if s.get("risk_level") in ("review", "high") and ("private" in note or "internal" in note or "10." in note):
            n += 1
    return n


def _dangling_count(ref: DomainRef) -> int:
    return sum(1 for s in (ref.vm.subdomains or []) if isinstance(s, dict) and s.get("is_dangling"))


_CONTROLS = (
    ("dmarc", "DMARC not enforced", "Set DMARC to p=quarantine or p=reject on the affected domains."),
    ("spf", "SPF not strict", "Tighten SPF to end in -all (hard fail) on the affected domains."),
    ("dnssec", "DNSSEC not enabled", "Enable DNSSEC signing at the registrar/DNS provider."),
    ("caa", "CAA record missing", "Publish a CAA record to constrain which CAs may issue."),
    ("internal_ip_leak", "Internal-IP leak in public DNS", "Remove RFC1918 / internal endpoints from public DNS."),
    ("dangling_subdomain", "Dangling subdomain (takeover exposure)", "Remove or reclaim the dangling CNAME targets."),
)


def compute_correlated(refs: list[DomainRef], thresholds: EstateThresholds) -> list[WeaknessPrevalence]:
    assessed = _assessed(refs)
    n_assessed = len(assessed)
    seg_total: dict[str, int] = {}
    for r in assessed:
        seg_total[r.segment] = seg_total.get(r.segment, 0) + 1

    out: list[WeaknessPrevalence] = []
    for control, label, remediation in _CONTROLS:
        n_affected = 0
        per_segment: dict[str, int] = {}
        for r in assessed:
            if _is_weak(control, r):
                n_affected += 1
                per_segment[r.segment] = per_segment.get(r.segment, 0) + 1
        pct = (n_affected / n_assessed) if n_assessed else 0.0
        systemic_segments = [
            seg for seg, aff in per_segment.items()
            if seg_total.get(seg, 0) and aff / seg_total[seg] >= thresholds.systemic_weakness_pct
        ]
        out.append(WeaknessPrevalence(
            control=control, label=label,
            n_affected=n_affected, n_assessed=n_assessed, pct=pct,
            per_segment=per_segment, per_segment_total=dict(seg_total),
            systemic=(pct >= thresholds.systemic_weakness_pct),
            systemic_segments=sorted(systemic_segments),
            remediation=remediation,
        ))
    return out


# ---------------------------------------------------------------------------
# §2.4 Posture variance / drift / M&A gap
# ---------------------------------------------------------------------------

def _score_stats(scores: list[int]) -> ScoreStats:
    if not scores:
        return ScoreStats()
    med = statistics.median(scores)
    return ScoreStats(
        count=len(scores),
        mean=round(statistics.fmean(scores), 1),
        median=round(med, 1),
        min=min(scores),
        max=max(scores),
        grade=score_to_grade(round(med)).letter,
    )


def compute_variance(refs: list[DomainRef], thresholds: EstateThresholds) -> VarianceBlock:
    assessed = _assessed(refs)
    unassessed = sum(1 for r in refs if not getattr(r.vm, "has_intelligence", False) or r.load_error)

    by_segment: dict[str, list[int]] = {}
    all_scores: list[int] = []
    grade_dist: dict[str, int] = {}
    for r in assessed:
        s = int(r.vm.composite_score or 0)
        by_segment.setdefault(r.segment, []).append(s)
        all_scores.append(s)
        letter = r.vm.grade.letter if getattr(r.vm, "grade", None) else score_to_grade(s).letter
        grade_dist[letter] = grade_dist.get(letter, 0) + 1

    baseline = round(statistics.fmean(all_scores), 1) if all_scores else 0.0
    baseline_grade = score_to_grade(round(baseline)).letter if all_scores else "?"
    baseline_idx = _grade_index(baseline_grade)

    postures: list[SegmentPosture] = []
    outliers: list[str] = []
    for seg, scores in sorted(by_segment.items()):
        stats = _score_stats(scores)
        seg_dist: dict[str, int] = {}
        for s in scores:
            g = score_to_grade(s).letter
            seg_dist[g] = seg_dist.get(g, 0) + 1
        bands_below = 0
        seg_idx = _grade_index(stats.grade)
        if baseline_idx is not None and seg_idx is not None:
            bands_below = seg_idx - baseline_idx        # positive == worse than baseline
        is_outlier = bands_below >= thresholds.variance_outlier_bands
        if is_outlier:
            outliers.append(seg)
        postures.append(SegmentPosture(
            segment=seg, stats=stats, grade_distribution=seg_dist,
            is_outlier=is_outlier, bands_below_baseline=bands_below,
        ))

    return VarianceBlock(
        estate_baseline_score=baseline,
        estate_baseline_grade=baseline_grade,
        per_segment=postures,
        grade_distribution=grade_dist,
        outlier_segments=outliers,
        unassessed=unassessed,
    )


# ---------------------------------------------------------------------------
# §2.5 Active exposure rollup (EXACT impersonation only)
# ---------------------------------------------------------------------------

def compute_exposure(refs: list[DomainRef], thresholds: EstateThresholds) -> ExposureRollup:
    assessed = _assessed(refs)
    plat_7d: dict[str, int] = {}
    plat_30d: dict[str, int] = {}
    plat_domains: dict[str, set[str]] = {}
    plat_samples: dict[str, list[str]] = {}
    by_segment: dict[str, int] = {}
    lookalike_30d = 0

    for r in assessed:
        ext = r.vm.external_threat
        # EXACT only — lookalike_candidates are carried parallel, never summed.
        for imp in ext.impersonations:
            if getattr(imp, "confidence", "exact") != "exact":
                continue
            p = imp.platform
            plat_7d[p] = plat_7d.get(p, 0) + int(imp.count_7d or 0)
            plat_30d[p] = plat_30d.get(p, 0) + int(imp.count_30d or 0)
            plat_domains.setdefault(p, set()).add(r.domain)
            if imp.sample_domains:
                plat_samples.setdefault(p, [])
                for d in imp.sample_domains:
                    if d not in plat_samples[p]:
                        plat_samples[p].append(d)
            by_segment[r.segment] = by_segment.get(r.segment, 0) + int(imp.count_30d or 0)
        lookalike_30d += sum(int(c.count_30d or 0) for c in ext.lookalike_candidates)

    platforms = [
        TargetedPlatform(
            platform=p, count_7d=plat_7d.get(p, 0), count_30d=cnt,
            targeted_domains=len(plat_domains.get(p, set())),
            sample_domains=plat_samples.get(p, [])[:10],
        )
        for p, cnt in sorted(plat_30d.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    total_30d = sum(plat_30d.values())
    total_7d = sum(plat_7d.values())
    top_share = (platforms[0].count_30d / total_30d) if (platforms and total_30d) else 0.0
    samples: list[str] = []
    for p in platforms:
        for d in p.sample_domains:
            if d not in samples:
                samples.append(d)

    return ExposureRollup(
        total_7d=total_7d, total_30d=total_30d,
        by_platform=platforms, by_segment=by_segment,
        sample_domains=samples[:20],
        targeting_concentration=round(top_share, 3),
        lookalike_total_30d=lookalike_30d,
    )


# ---------------------------------------------------------------------------
# §2.6 Operational calendar
# ---------------------------------------------------------------------------

_LOCK_TOKENS = ("transferprohibited", "deleteprohibited", "updateprohibited", "clienthold", "serverhold")


def _parse_date(val) -> Optional[datetime]:
    if not val or not isinstance(val, str):
        return None
    s = val.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # date-only or unexpected format
        try:
            dt = datetime.fromisoformat(s[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def compute_calendar(refs: list[DomainRef], thresholds: EstateThresholds,
                     now: Optional[datetime] = None) -> CalendarBlock:
    now = now or datetime.now(timezone.utc)
    items: list[CalendarItem] = []

    for r in _assessed(refs):
        vm = r.vm
        # Domain expiry
        exp = _parse_date(vm.registration.expires_date)
        if exp is not None:
            days = (exp - now).days
            if days <= thresholds.domain_expiring_days:
                sev = "high" if days < 0 else "elevated" if days <= 14 else "medium"
                items.append(CalendarItem(
                    domain=r.domain, segment=r.segment, kind="domain_expiry",
                    date=vm.registration.expires_date, days_left=days, severity=sev,
                    detail=("Domain registration expired" if days < 0
                            else f"Domain registration expires in {days}d"),
                ))
        # Registrar locks
        status = (vm.registration.status or "").lower()
        if status and not any(tok in status for tok in _LOCK_TOKENS):
            items.append(CalendarItem(
                domain=r.domain, segment=r.segment, kind="unlocked", severity="medium",
                detail="No registrar lock present (transfer/delete not prohibited)",
            ))
        # Certificate hygiene from cert_analysis
        items.extend(_cert_calendar_items(r, thresholds))

    # Sort: overdue first, then soonest. Items without a date go last.
    def _key(it: CalendarItem):
        return (it.days_left is None, it.days_left if it.days_left is not None else 10**9)

    items.sort(key=_key)
    next_30 = sum(1 for it in items if it.days_left is not None and 0 <= it.days_left <= 30)
    next_90 = sum(1 for it in items if it.days_left is not None and 0 <= it.days_left <= 90)
    overdue = sum(1 for it in items if it.days_left is not None and it.days_left < 0)
    return CalendarBlock(items=items, next_30d=next_30, next_90d=next_90, overdue=overdue)


def _cert_calendar_items(ref: DomainRef, thresholds: EstateThresholds) -> list[CalendarItem]:
    ca = ref.vm.cert_analysis or {}
    out: list[CalendarItem] = []

    def _emit(bucket_key: str, kind: str, severity: str, verb: str):
        bucket = ca.get(bucket_key)
        if isinstance(bucket, list):
            for c in bucket:
                if not isinstance(c, dict):
                    continue
                name = c.get("dns_name") or c.get("common_name") or ref.domain
                days = c.get("days_remaining")
                out.append(CalendarItem(
                    domain=ref.domain, segment=ref.segment, kind=kind,
                    days_left=(int(days) if isinstance(days, (int, float)) else None),
                    severity=severity, detail=f"Certificate {verb}: {name}",
                ))
        elif isinstance(bucket, int) and bucket > 0:
            out.append(CalendarItem(
                domain=ref.domain, segment=ref.segment, kind=kind, severity=severity,
                detail=f"{bucket} certificate(s) {verb}",
            ))

    _emit("expired", "cert_expired", "high", "expired")
    _emit("expiring_soon", "cert_expiring", "elevated", "expiring soon")
    _emit("missed_renewals", "missed_renewal", "medium", "renewal missed")
    return out
