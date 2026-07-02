"""
estatereport/remediation.py
---------------------------
Appendix A — the remediation worksheet (spec §2b). Group by FIX PATTERN, not by
domain: one card per pattern, the record template written once, and a per-domain
table (checkbox / domain / admin point / Now / Fix) ordered by admin point so one
team's work batches into one change window.

Locked rules honoured:
  * Priorities from the email_control_maturity tier — baseline → Now, advanced →
    Soon, gold → Maturity (reuses freereport.maturity; the v8 BIMI/MTA-STS = HIGH
    ranking is NOT lifted).
  * Recovery / registrar work (expired names, locks) is Fix 1, always — takeover
    windows precede DNS hygiene.
  * Lift-guards: dedup on pattern_id (one pattern per control); `Now` is a
    FORMATTED evidence string, never a raw field name; no platform-global counts.
  * Overflow: per-pattern tables cap at 20 rows; the rest render as "+N in export".
  * admin_point derived from nameserver + registrar (zone-host level) — never
    account-level (not externally observable).
"""

from __future__ import annotations

from typing import Callable, Optional

from estatereport.contract import AdminPoint, RemediationEntry, RemediationPattern
from freereport import maturity

_ROW_CAP = 20

# tier → worksheet priority pill
_TIER_PRI = {"baseline": "now", "advanced": "soon", "gold": "plan"}


def _ns_admin(vm) -> str:
    return vm.annotation.ns_provider or "DNS zone host"


def _reg_admin(vm) -> str:
    return vm.registration.registrar or "registrar"


# ── per-control weakness tests + Now/Fix strings ─────────────────────────────

def _dmarc_weak(vm):
    return (vm.hygiene.dmarc_policy or "").lower() not in ("reject", "quarantine")


def _dmarc_now(vm):
    p = (vm.hygiene.dmarc_policy or "").lower()
    return "p=none (monitor only)" if p == "none" else "no DMARC record"


def _dmarc_fix(vm):
    p = (vm.hygiene.dmarc_policy or "").lower()
    return "p=quarantine" if p == "none" else "p=none + rua"


def _spf_weak(vm):
    spf = (vm.hygiene.spf_record or "").strip()
    return (not spf) or (not spf.endswith("-all"))


def _spf_now(vm):
    spf = (vm.hygiene.spf_record or "").strip()
    return "no SPF record" if not spf else "soft-fail (~all)"


def _spf_fix(vm):
    spf = (vm.hygiene.spf_record or "").strip()
    return '"v=spf1 -all" (non-sending)' if not spf else "-all after DMARC confirms senders"


def _caa_weak(vm):
    return not vm.hygiene.caa_present


def _dnssec_weak(vm):
    return not (vm.registration.dnssec or vm.hygiene.dnssec)


CONTROL_SPECS = [
    {"id": "dmarc", "title": "Enforce DMARC", "control": "dmarc",
     "why": "DMARC lets you reject mail spoofed as your domain. Staged: publish <code>p=none</code> "
            "with <code>rua</code> first to observe, then move to enforcement.",
     "record": ('_dmarc.<domain>.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@<domain>"\n'
                '<span class="cm"># then, once rua confirms your senders:</span>\n'
                '_dmarc.<domain>.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>"'),
     "end_state": "p=reject once rua confirms all senders",
     "weak": _dmarc_weak, "now": _dmarc_now, "fix": _dmarc_fix, "admin": _ns_admin},
    {"id": "spf", "title": "Tighten SPF to hard-fail", "control": "spf",
     "why": "SPF declares which servers may send as your domain. Move to hard-fail "
            "(<code>-all</code>) once DMARC reports confirm your legitimate senders; non-sending "
            "domains can go to <code>-all</code> immediately.",
     "record": ('<span class="cm"># target apex record (after DMARC confirms senders):</span>\n'
                'v=spf1 include:&lt;your-sender&gt; -all'),
     "end_state": "-all once DMARC confirms senders",
     "weak": _spf_weak, "now": _spf_now, "fix": _spf_fix, "admin": _ns_admin},
    {"id": "caa", "title": "Publish CAA records", "control": "caa",
     "why": "CAA reduces the set of certificate authorities that may issue for your domains.",
     "record": '<domain>.  IN  CAA  0 issue "&lt;your-ca&gt;"\n<domain>.  IN  CAA  0 iodef "mailto:security@<domain>"',
     "end_state": None,
     "weak": _caa_weak, "now": lambda vm: "no CAA record", "fix": lambda vm: 'issue "&lt;your-ca&gt;"',
     "admin": _ns_admin},
    {"id": "dnssec", "title": "Enable DNSSEC", "control": "dnssec",
     "why": "DNSSEC cryptographically signs your DNS records. Gold-standard; plan it — its absence "
            "does not create exploitable risk today.",
     "record": '<span class="cm"># enable signing at the DNS provider, then publish the DS at the registry</span>',
     "end_state": None,
     "weak": _dnssec_weak, "now": lambda vm: "zone unsigned", "fix": lambda vm: "sign zone + DS at registry",
     "admin": _ns_admin},
]


def _assessed_refs(mvp):
    return [d for seg in mvp.segments for d in seg.domains
            if getattr(d.vm, "has_intelligence", False) and not d.load_error]


def build_remediation(mvp, calendar_items) -> tuple[list[RemediationPattern], list[AdminPoint]]:
    refs = _assessed_refs(mvp)
    patterns: list[RemediationPattern] = []

    # ── Fix 1, always: recovery / registrar work (expired + unlocked) ────────
    overdue_domains = {c.domain for c in calendar_items if c.overdue}
    unlocked_domains = {c.domain for c in calendar_items if c.item_kind == "unlocked"}
    recov = sorted(overdue_domains | unlocked_domains)
    if recov:
        ref_by_dom = {d.domain: d for d in refs}
        entries = []
        for dom in recov:
            d = ref_by_dom.get(dom)
            vm = d.vm if d else None
            now = "expired" if dom in overdue_domains else "no registrar lock"
            entries.append(RemediationEntry(
                domain=dom, segment=(d.segment if d else ""),
                admin_point=(_reg_admin(vm) if vm else "registrar"),
                now=now, fix="renew + set registrar locks"))
        entries.sort(key=lambda e: (e.admin_point, e.domain))
        patterns.append(RemediationPattern(
            pattern_id="recovery", title="Recover expired / unlocked domains", priority="now",
            why_html="Expired registrations and absent locks are live takeover windows — recover "
                     "these before any DNS hygiene work.",
            record_template='<span class="cm"># at the registrar: renew, then enable</span>\n'
                            'clientTransferProhibited · clientDeleteProhibited · clientUpdateProhibited',
            end_state=None, entries=entries[:_ROW_CAP], overflow=max(0, len(entries) - _ROW_CAP)))

    # ── One pattern per control, dedup on pattern_id, tier-ordered ───────────
    for spec in CONTROL_SPECS:
        affected = [d for d in refs if spec["weak"](d.vm)]
        if not affected:
            continue
        tier = maturity.control(spec["control"]).tier
        entries = []
        for d in affected:
            vm = d.vm
            entries.append(RemediationEntry(
                domain=d.domain, segment=d.segment, admin_point=f"{spec['admin'](vm)}",
                now=spec["now"](vm), fix=spec["fix"](vm)))
        entries.sort(key=lambda e: (e.admin_point, e.domain))    # batch by admin point
        patterns.append(RemediationPattern(
            pattern_id=spec["id"], title=spec["title"], priority=_TIER_PRI[tier],
            why_html=spec["why"], record_template=spec["record"], end_state=spec["end_state"],
            entries=entries[:_ROW_CAP], overflow=max(0, len(entries) - _ROW_CAP)))

    # ── Isolated per-domain findings: internal-IP leak, dangling subdomain ───
    patterns.extend(_isolated_patterns(refs))

    admin_points = _admin_strip(patterns)
    return patterns, admin_points


def _isolated_patterns(refs) -> list[RemediationPattern]:
    out = []
    leaks = []
    dangles = []
    for d in refs:
        for s in (d.vm.subdomains or []):
            if not isinstance(s, dict):
                continue
            note = (s.get("note") or "").lower()
            if s.get("risk_level") in ("review", "high") and ("private" in note or "internal" in note):
                leaks.append((d, s))
            if s.get("is_dangling"):
                dangles.append((d, s))
    if leaks:
        entries = [RemediationEntry(domain=s.get("dns_name", d.domain), segment=d.segment,
                                    admin_point=_ns_admin(d.vm),
                                    now="internal IP in public DNS", fix="remove / split-horizon")
                   for d, s in leaks]
        entries.sort(key=lambda e: (e.admin_point, e.domain))
        out.append(RemediationPattern(
            pattern_id="internal_ip_leak", title="Remove internal endpoints from public DNS",
            priority="now",
            why_html="Private (RFC1918) addresses in public DNS reveal internal network structure.",
            record_template='<span class="cm"># remove the public A record, or move to split-horizon</span>',
            entries=entries[:_ROW_CAP], overflow=max(0, len(entries) - _ROW_CAP)))
    if dangles:
        entries = [RemediationEntry(domain=s.get("dns_name", d.domain), segment=d.segment,
                                    admin_point=_ns_admin(d.vm),
                                    now="dangling CNAME", fix="remove / reclaim target")
                   for d, s in dangles]
        entries.sort(key=lambda e: (e.admin_point, e.domain))
        out.append(RemediationPattern(
            pattern_id="dangling_subdomain", title="Resolve dangling subdomains (takeover exposure)",
            priority="now",
            why_html="A CNAME pointing at an unclaimed resource can be taken over by an attacker.",
            record_template='<span class="cm"># remove the CNAME or reclaim the target resource</span>',
            entries=entries[:_ROW_CAP], overflow=max(0, len(entries) - _ROW_CAP)))
    return out


def _admin_strip(patterns) -> list[AdminPoint]:
    counts: dict[str, int] = {}
    for p in patterns:
        for e in p.entries:
            counts[e.admin_point] = counts.get(e.admin_point, 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:3]
    return [AdminPoint(key="admin point", name=name, detail=f"{n} change(s) batch here")
            for name, n in top]
