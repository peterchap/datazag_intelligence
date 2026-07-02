"""
freereport/compose.py
---------------------
Turn a `ReportViewModel` into the template context for the 5-page free report.
Pure functions (no I/O). All contract reads are defensive — a missing field
renders an explicit honest state, never a blank or an exception.

House style enforced here:
  * describe the mechanism, hedge the universal (copy strings below avoid
    never/all/only/always);
  * only BASELINE email-control gaps are negatives — advanced/gold gaps come
    from maturity.py as cyan/amber opportunities, never red;
  * guards: exact-match impersonation only (lookalikes excluded from the
    headline); ownership-proof TXT tokens are not platform evidence; no
    platform-global counts bound to a per-domain claim.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from freereport import maturity

# Verbatim scope caveat (spec: mandatory, verbatim intent).
SCOPE_CAVEAT = (
    "Scope: this assessment covers only what is visible from public DNS and "
    "certificate transparency at a point in time. It does not cover endpoint "
    "security, network segmentation, identity and access management, patch "
    "posture, or physical security — all of which a full underwriting assessment "
    "also weighs."
)

# Ownership-proof TXT prefixes that must NOT be read as platform-use evidence.
_OWNERSHIP_TOKENS = ("google-site-verification", "ms=", "facebook-domain-verification",
                     "apple-domain-verification", "atlassian-domain-verification",
                     "docusign=", "adobe-idp-site-verification", "stripe-verification")


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def org_name(vm) -> str:
    """registrant_org if present, else a cleaned form of the apex, else the domain."""
    org = getattr(vm.registration, "registrant_org", None)
    if org:
        return org
    d = (vm.domain or "").strip().lower()
    if not d:
        return "this organisation"
    stem = d.split(".")[0]
    return stem.replace("-", " ").title() if stem else d


# ---------------------------------------------------------------------------
# Platform evidence (page 2 confirmed rows + page 3 mail line)
# ---------------------------------------------------------------------------

def _mx_host(vm) -> Optional[str]:
    for entry in (vm.dns_records.mx or []):
        parts = str(entry).split()
        if parts:
            return parts[-1]        # "10 host" -> host
    return None


def confirmed_platforms(vm) -> list[dict]:
    """Platforms evidenced by MX / SPF-include / CNAME — never ownership TXT tokens.
    Returns [{mark, name, category, note, evidence}]. De-duplicated by name."""
    out: list[dict] = []
    seen: set[str] = set()

    def add(name, category, note, evidence):
        key = (name or "").strip().lower()
        if not name or key in seen:
            return
        seen.add(key)
        out.append({"mark": name[0].upper(), "name": name, "category": category,
                    "note": note, "evidence": evidence})

    ann = vm.annotation
    if ann.mailbox_provider:
        mx = _mx_host(vm)
        add(ann.mailbox_provider, ann.mailbox_category or "Mailbox platform",
            "One of the most-impersonated surfaces in the credential-harvesting economy",
            f"MX → {mx}" if mx else "MX-derived from your mail configuration")

    for sig in (ann.platform_signals or []):
        ev = (sig.evidence or "").strip()
        st = (sig.signal_type or "").upper()
        mt = (sig.match_type or "").lower()
        # Guard: drop ownership-proof TXT tokens; keep MX / SPF-include / CNAME evidence.
        low = ev.lower()
        if any(tok in low for tok in _OWNERSHIP_TOKENS):
            continue
        if st in ("MX", "SPF_INCLUDE", "CNAME") or mt in ("mx", "cname", "spf", "suffix"):
            add(sig.provider, sig.category or "Detected platform",
                "Confirmed from your mail / DNS configuration", ev or f"{st or mt} evidence")
    return out


def top_platform(vm) -> str:
    plats = confirmed_platforms(vm)
    if plats:
        return plats[0]["name"]
    return vm.annotation.mailbox_provider or "the cloud platforms you use"


# ---------------------------------------------------------------------------
# Exact-impersonation headline (guard: exact only, lookalikes excluded)
# ---------------------------------------------------------------------------

def exact_impersonations(vm) -> list:
    return [i for i in vm.external_threat.impersonations
            if getattr(i, "confidence", "exact") == "exact"]


def exact_count_30d(vm) -> int:
    return sum(int(i.count_30d or 0) for i in exact_impersonations(vm))


# ---------------------------------------------------------------------------
# Registration / expiry helpers
# ---------------------------------------------------------------------------

_LOCK_TOKENS = ("transferprohibited", "deleteprohibited", "updateprohibited")


def has_locks(vm) -> bool:
    status = (vm.registration.status or "").lower()
    return any(tok in status for tok in _LOCK_TOKENS)


def expiry_days(vm, now: datetime) -> Optional[int]:
    exp = vm.registration.expires_date
    if not exp:
        return None
    try:
        dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00")[:19] if "T" in str(exp)
                                    else str(exp)[:10])
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - now).days


# ---------------------------------------------------------------------------
# Subdomain exposure
# ---------------------------------------------------------------------------

def internal_leaks(vm) -> list[dict]:
    """Subdomains leaking RFC1918 / internal endpoints into public DNS."""
    out = []
    for s in (vm.subdomains or []):
        if not isinstance(s, dict):
            continue
        note = (s.get("note") or "").lower()
        a = s.get("a_records") or []
        looks_private = ("private" in note or "internal" in note or "rfc1918" in note
                         or any(str(ip).startswith(("10.", "192.168.", "172.")) for ip in a))
        if s.get("risk_level") in ("review", "high") and looks_private:
            out.append({"host": s.get("dns_name") or s.get("host") or "",
                        "a": (a[0] if a else "")})
    return out


def high_risk_subs(vm) -> int:
    return sum(1 for s in (vm.subdomains or [])
               if isinstance(s, dict) and s.get("risk_level") == "high")


# ---------------------------------------------------------------------------
# Dashboard category states (page 1)
# ---------------------------------------------------------------------------

def _email_state(vm) -> tuple[str, str, str]:
    h = vm.hygiene
    pol = (h.dmarc_policy or "").lower()
    if pol == "reject" and h.spf_record:
        return ("ok", "Strong", "DMARC at reject with SPF in place — ahead of most organisations.")
    if not pol or pol == "none":
        return ("bad", "Exposed", "DMARC is absent or monitor-only — mail can be spoofed as your domain.")
    return ("warn", "Adequate", "Core email authentication is present but not yet at full enforcement.")


def _external_state(vm) -> tuple[str, str, str]:
    if exact_count_30d(vm) > 0:
        return ("warn", "Elevated",
                "Impersonation activity against your platform stack was observed in the last 30 days.")
    return ("ok", "Low",
            "No confirmed impersonation against your platform stack in the last 30 days.")


def _hygiene_state(vm, now: datetime) -> tuple[str, str, str]:
    locks = has_locks(vm)
    days = expiry_days(vm, now)
    urgent = days is not None and days < 30
    caa = vm.hygiene.caa_present
    dnssec = vm.hygiene.dnssec or vm.registration.dnssec
    if not locks or urgent:
        return ("bad", "Exposed",
                "Registrar locks are absent or a renewal is close — the domain is easier to hijack or let lapse.")
    if caa and dnssec:
        return ("ok", "Strong", "Enterprise registrar with locks, plus CAA and DNSSEC in place.")
    return ("warn", "Adequate",
            "Enterprise registrar and locks are present; secondary controls (CAA, DNSSEC) are not yet adopted.")


def _subdomain_state(vm) -> tuple[str, str, str]:
    leaks = internal_leaks(vm)
    hi = high_risk_subs(vm)
    total = len(vm.subdomains or [])
    if leaks or hi:
        note = []
        if leaks:
            note.append(f"{len(leaks)} internal endpoint(s) leaking to public DNS")
        if hi:
            note.append(f"{hi} of {total} high-risk")
        return ("bad", "Exposed", "; ".join(note) + ".")
    if any(isinstance(s, dict) and s.get("risk_level") == "review" for s in (vm.subdomains or [])):
        return ("warn", "Adequate", "Some subdomains warrant review, but none are high-risk.")
    return ("ok", "Clean", "No leaking or high-risk subdomains observed.")


def dashboard(vm, now: datetime) -> list[dict]:
    ext = _external_state(vm)
    email = _email_state(vm)
    hyg = _hygiene_state(vm, now)
    sub = _subdomain_state(vm)
    return [
        {"key": "External threat", **_card(ext)},
        {"key": "Email security", **_card(email)},
        {"key": "Domain hygiene", **_card(hyg)},
        {"key": "Subdomains", **_card(sub)},
    ]


def _card(t: tuple[str, str, str]) -> dict:
    return {"cls": t[0], "state": t[1], "note": t[2]}


# ---------------------------------------------------------------------------
# Synthesis + insurer lens (page 1)
# ---------------------------------------------------------------------------

def synthesis(vm, now: datetime) -> str:
    email_cls, email_state, _ = _email_state(vm)
    if email_cls == "ok":
        maturity_phrase = "a mature estate with enterprise-grade email security"
    elif email_cls == "bad":
        maturity_phrase = "an estate whose core email authentication needs attention"
    else:
        maturity_phrase = "an estate with the core email controls in place"

    strengths = _strengths(vm)
    weaknesses = _weaknesses(vm)
    strength_phrase = strengths[0]["plain"] if strengths else "a broadly sound configuration"
    if weaknesses:
        gap_phrase = f"a small number of issues — {weaknesses[0]['plain']} — that can be quickly addressed"
    else:
        gap_phrase = "only minor hardening opportunities, which can be addressed at your own pace"
    return (f"The DNS evidence shows <b>{maturity_phrase}</b> with {strength_phrase} — "
            f"{gap_phrase}.")


def insurer_lens(vm, now: datetime) -> str:
    strengths = _strengths(vm)
    weaknesses = _weaknesses(vm)
    pos = strengths[0]["plain"] if strengths else "a broadly sound external configuration"
    if weaknesses:
        gap = weaknesses[0]["plain"]
        tail = (f"offset by <b>{gap}</b>. On the externally observable evidence an underwriter "
                "would likely note this for remediation rather than treat it as a barrier to binding.")
    else:
        tail = ("with no material externally observable gaps. An underwriter would read this as a "
                "well-run external estate.")
    return f"On the externally observable evidence, an underwriter would see <b>{pos}</b> {tail}"


# ---------------------------------------------------------------------------
# Strengths / weaknesses (page 1 synthesis, page 3 balance)
# ---------------------------------------------------------------------------

def _strengths(vm) -> list[dict]:
    out = []
    h = vm.hygiene
    if (h.dmarc_policy or "").lower() == "reject":
        out.append({"plain": "email authentication enforced at the strongest level",
                    "html": "DMARC fully enforced at <code>p=reject</code> — the strongest available "
                            "protection against domain spoofing"})
    if vm.annotation.mailbox_provider:
        gw = next((p["name"] for p in confirmed_platforms(vm)
                   if p["name"] != vm.annotation.mailbox_provider), None)
        if gw:
            out.append({"plain": f"an enterprise mail path ({gw} in front of {vm.annotation.mailbox_provider})",
                        "html": f"Enterprise mail security: {gw} gateway in front of {vm.annotation.mailbox_provider}"})
    if has_locks(vm):
        rg = vm.registration.registrar or "an enterprise registrar"
        out.append({"plain": f"an enterprise registrar ({rg}) with domain locks",
                    "html": f"Enterprise registrar ({rg}) with server-side locks that reduce the risk of domain hijack"})
    if not vm.threat.listed_feeds:
        host = vm.annotation.hosting_provider
        out.append({"plain": "clean hosting with no threat-feed hits",
                    "html": (f"Clean hosting{' on ' + host if host else ''} — no malicious-IP, "
                             "fast-flux or threat-feed hits")})
    return out


def _weaknesses(vm) -> list[dict]:
    out = []
    leaks = internal_leaks(vm)
    if leaks:
        ex = leaks[0]["a"]
        out.append({"plain": f"{len(leaks)} internal endpoint(s) exposed in public DNS",
                    "html": f"{len(leaks)} internal endpoint(s) (<code>{ex}</code>-style private addresses) "
                            "exposed in public DNS — this can confirm internal network structure to an attacker"})
    hi = high_risk_subs(vm)
    if hi:
        out.append({"plain": f"{hi} high-risk dev/test subdomains",
                    "html": f"{hi} subdomains are exposed dev/test environments — typically less hardened than production"})
    h = vm.hygiene
    if h.spf_record and h.spf_record.strip().endswith("~all"):
        out.append({"plain": "SPF left at soft-fail",
                    "html": "SPF at soft-fail (<code>~all</code>) leaves a narrow spoofing gap behind the DMARC policy"})
    return out


# ---------------------------------------------------------------------------
# Observed-event line (page 2 evidence)
# ---------------------------------------------------------------------------

def observed_event_line(vm) -> str:
    n = exact_count_30d(vm)
    plat = top_platform(vm)
    if n <= 0:
        return ("In the last 30 days we observed <b>no confirmed impersonation</b> against your "
                "platform stack. The economics above still apply — the absence of an observed "
                "event is not the absence of risk — so the primer stands regardless.")
    cert = "one certificate was" if n == 1 else f"{n} certificates were"
    return (f"In the last 30 days, {cert} issued for domains impersonating a {plat} login page on an "
            "exact match to your environment — instances of the machine above, pointed at your stack. "
            "The domain, certificate serial and issuance time are verifiable. Lower-confidence "
            "typosquat candidates are tracked separately and excluded from this figure.")


# ---------------------------------------------------------------------------
# Three-surface map (page 3)
# ---------------------------------------------------------------------------

def surfaces(vm, now: datetime) -> list[dict]:
    h = vm.hygiene
    ann = vm.annotation
    # -- Surface 01: Communication --
    comm: list[dict] = []
    if (h.dmarc_policy or "").lower() == "reject":
        comm.append({"b": "ok", "html": "<b style='color:var(--ink)'>Baseline:</b>&nbsp;DMARC "
                     "<code>p=reject</code> + SPF in place — strong"})
    elif not h.dmarc_policy or (h.dmarc_policy or "").lower() == "none":
        comm.append({"b": "bad", "html": "<b style='color:var(--ink)'>Baseline:</b>&nbsp;DMARC absent "
                     "or monitor-only — mail can be spoofed as your domain"})
    else:
        comm.append({"b": "warn", "html": f"<b style='color:var(--ink)'>Baseline:</b>&nbsp;DMARC at "
                     f"<code>{h.dmarc_policy}</code> — not yet at full enforcement"})
    n = exact_count_30d(vm)
    if n > 0:
        comm.append({"b": "warn", "html": f"{n} confirmed {top_platform(vm)} impersonation (30d)"})
    else:
        comm.append({"b": "ok", "html": "No confirmed platform impersonation (30d)"})
    if h.spf_record and h.spf_record.strip().endswith("~all"):
        comm.append({"b": "warn", "html": "SPF soft-fail (<code>~all</code>) — minor tightening available"})
    adv = [c.label for c in maturity.absent_controls(vm, tier="advanced") if c.key in ("mta_sts", "tls_rpt")]
    if adv:
        comm.append({"b": "cy", "html": "<b style='color:var(--ink)'>Advanced:</b>&nbsp;"
                     + " / ".join(adv) + " not yet adopted"})

    # -- Surface 02: Digital --
    dig: list[dict] = []
    leaks = internal_leaks(vm)
    if leaks:
        dig.append({"b": "bad", "html": f"<b style='color:var(--ink)'>{len(leaks)} internal endpoint(s) "
                    "leaking</b> to public DNS"})
    hi = high_risk_subs(vm)
    total = len(vm.subdomains or [])
    if hi:
        dig.append({"b": "bad", "html": f"{hi} of {total} subdomains high-risk (dev/test)"})
    if not h.caa_present:
        dig.append({"b": "cy", "html": "<b style='color:var(--ink)'>Hardening:</b>&nbsp;no CAA — "
                    "mis-issuance barrier absent"})
    else:
        dig.append({"b": "ok", "html": "CAA present — certificate issuance constrained"})
    if h.tls_issuer:
        left = f", {h.tls_days_left}d left" if getattr(h, "tls_days_left", None) is not None else ", valid"
        dig.append({"b": "ok", "html": f"Certificates healthy ({h.tls_issuer}{left})"})
    if not dig:
        dig.append({"b": "ok", "html": "No public-facing digital exposure observed"})

    # -- Surface 03: Hosting & network --
    host: list[dict] = []
    hp = ann.hosting_provider
    host.append({"b": "ok" if hp else "na", "html": f"<b style='color:var(--ink)'>Hosting:</b>&nbsp;"
                 + (hp or "not determined")})
    asn = vm.trust.asn or ann.asn
    prefix = vm.trust.prefix or ann.prefix
    net = (f"AS{asn}" + (f" · <code>{prefix}</code>" if prefix else "")) if asn else "not determined"
    host.append({"b": "ok" if asn else "na", "html": f"<b style='color:var(--ink)'>Network:</b>&nbsp;{net}"})
    loc = vm.trust.isp_country or ann.isp_country
    host.append({"b": "ok" if loc else "na", "html": "<b style='color:var(--ink)'>Location:</b>&nbsp;"
                 + (loc or "not determined")})
    mail = ann.mailbox_provider
    gw = next((p["name"] for p in confirmed_platforms(vm) if p["name"] != mail), None)
    mail_line = (mail + (f" via {gw}" if gw else "")) if mail else "not determined"
    host.append({"b": "ok" if mail else "na", "html": f"<b style='color:var(--ink)'>Mail:</b>&nbsp;{mail_line}"})
    if vm.threat.listed_feeds:
        host.append({"b": "bad", "html": "Threat-feed: listed on " + ", ".join(vm.threat.listed_feeds)})
    else:
        host.append({"b": "ok", "html": "Clean — no threat-feed or malicious-IP hits"})

    return [
        {"n": "01", "name": "Communication", "items": comm,
         "foot": "The human-targeting surface — email, impersonation, social engineering."},
        {"n": "02", "name": "Digital", "items": dig,
         "foot": "The system-targeting surface — APIs, subdomains, DNS, certificates."},
        {"n": "03", "name": "Hosting &amp; network", "items": host,
         "foot": "The infrastructure you're hosted on — IP, network, hosting and mail providers."},
    ]


def maturity_note_controls(vm) -> list:
    """Absent advanced + gold controls, for the cyan 'opportunities' note."""
    return maturity.absent_controls(vm, tier="advanced") + maturity.absent_controls(vm, tier="gold")


# ---------------------------------------------------------------------------
# Precise fixes (page 4)
# ---------------------------------------------------------------------------

_CAA_MAP = {
    "digicert": "digicert.com", "let's encrypt": "letsencrypt.org", "lets encrypt": "letsencrypt.org",
    "sectigo": "sectigo.com", "globalsign": "globalsign.com", "google": "pki.goog",
    "amazon": "amazon.com", "entrust": "entrust.net", "godaddy": "godaddy.com",
}


def _caa_domain(issuer: Optional[str]) -> str:
    iss = (issuer or "").lower()
    for k, v in _CAA_MAP.items():
        if k in iss:
            return v
    first = iss.split()[0] if iss else ""
    return f"{first}.com" if first else "your-ca.example"


def fixes(vm, now: datetime) -> list[dict]:
    out: list[dict] = []
    d = vm.domain
    h = vm.hygiene

    leaks = internal_leaks(vm)
    if leaks:
        lines = ["<span class=\"cm\"># remove these public records — internal resolution only</span>"]
        for lk in leaks:
            lines.append(f"{lk['host']:<40} A   {lk['a']}   ← remove")
        out.append({
            "title": "Remove internal endpoints from public DNS",
            "priority": "now",
            "why": ("Several hostnames resolve to private addresses that should not normally appear in "
                    "public DNS — they can reveal internal network structure to an attacker. Remove the "
                    "public A records or move them to split-horizon (internal-only) resolution."),
            "cmd": "\n".join(lines),
        })

    if h.spf_record and h.spf_record.strip().endswith("~all"):
        target = h.spf_record.strip()[:-4] + "-all"
        strong = (h.dmarc_policy or "").lower() == "reject"
        why = ("Your apex SPF uses soft-fail (<code>~all</code>). Move to hard-fail (<code>-all</code>) "
               "once your DMARC reports confirm all legitimate senders are listed.")
        if strong:
            why = ("Your DMARC at <code>p=reject</code> is strong, but the apex SPF still uses soft-fail "
                   "(<code>~all</code>). " + why.split(". ", 1)[1])
        out.append({
            "title": "Tighten SPF to hard-fail", "priority": "now", "why": why,
            "cmd": (f"<span class=\"cm\"># current (apex)</span>\n{h.spf_record.strip()}\n"
                    f"<span class=\"cm\"># target — after confirming senders in DMARC reports</span>\n{target}"),
        })

    if not h.caa_present:
        ca = _caa_domain(h.tls_issuer)
        out.append({
            "title": "Publish a CAA record", "priority": "soon",
            "why": ("CAA reduces the set of certificate authorities authorised to issue for your domain. "
                    f"Without it that set is unrestricted; a CAA record limits issuance to your known CA."),
            "cmd": (f"{d}.  IN  CAA  0 issue \"{ca}\"\n"
                    f"{d}.  IN  CAA  0 issuewild \"{ca}\"\n"
                    f"{d}.  IN  CAA  0 iodef \"mailto:security@{d}\""),
        })

    adv_gold = maturity_note_controls(vm)
    if any(c.key in ("mta_sts", "tls_rpt", "dnssec", "dane") for c in adv_gold):
        out.append({
            "title": "Adopt advanced mail-in-transit controls", "priority": "plan",
            "why": ("<b>Good-to-have, not urgent.</b> MTA-STS enforces TLS on inbound mail and TLS-RPT "
                    "reports failures — the advanced tier above the baseline you already meet. "
                    "DNSSEC/DANE is the gold-standard layer. Plan these; their absence does not create "
                    "exploitable risk today."),
            "cmd": (f"_mta-sts.{d}.   TXT  \"v=STSv1; id=20260701\"\n"
                    f"_smtp._tls.{d}. TXT  \"v=TLSRPTv1; rua=mailto:tls@{d}\"\n"
                    "<span class=\"cm\"># gold standard: DNSSEC signing at your registrar, then DANE</span>"),
        })

    for i, f in enumerate(out, 1):
        f["num"] = i
    return out


def monitor_note(vm, now: datetime) -> Optional[str]:
    """Domain expiry as a grey 'worth a glance' note — only when an enterprise
    registrar + locks make lapse unlikely (spec page 4). Otherwise expiry is a
    hard finding surfaced elsewhere."""
    days = expiry_days(vm, now)
    if days is None or not has_locks(vm):
        return None
    if days < 30:
        return None  # urgent lapse is not a "glance" — it surfaces as a hygiene negative
    rg = vm.registration.registrar or "an enterprise registrar"
    exp = vm.registration.expires_date
    return (f"The domain renews <b>{exp}</b> ({days} days). On {rg} with registrar locks set, lapse is "
            "unlikely — a quick confirmation that auto-renew is on is sufficient, not an urgent task.")


# ---------------------------------------------------------------------------
# Top-level assembler
# ---------------------------------------------------------------------------

def compose_context(vm, generated_at: Optional[str] = None, now: Optional[datetime] = None) -> dict:
    now = now or datetime.now(timezone.utc)
    gen = generated_at or vm.generated_at or now.isoformat()
    date_str = _pretty_date(gen[:10] if gen else "")
    fx = fixes(vm, now)
    return {
        "domain": vm.domain,
        "org": org_name(vm),
        "date": date_str,
        # page 1
        "synthesis": synthesis(vm, now),
        "dashboard": dashboard(vm, now),
        "lens_body": insurer_lens(vm, now),
        "scope_caveat": SCOPE_CAVEAT,
        # page 2
        "top_platform": top_platform(vm),
        "confirmed_platforms": confirmed_platforms(vm),
        "observed_event": observed_event_line(vm),
        # page 3
        "surfaces": surfaces(vm, now),
        "strengths": _strengths(vm),
        "weaknesses": _weaknesses(vm),
        "maturity_controls": maturity_note_controls(vm),
        # page 4
        "fixes": fx,
        "fix_count": len(fx),
        "monitor_note": monitor_note(vm, now),
    }


_MONTHS = ("", "January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December")


def _pretty_date(iso: str) -> str:
    try:
        y, m, d = iso.split("-")[:3]
        return f"{int(d)} {_MONTHS[int(m)]} {y}"
    except (ValueError, IndexError):
        return iso or ""
