import json

BASE = "/root/output/estate/Kids_Planet_Day_Nurseries"
est = json.load(open(f"{BASE}/estate.json"))

print("=" * 70)
print("VARIANCE BY SEGMENT (correct fields)")
print("=" * 70)
v = est.get("variance", {}) or {}
print(f"  estate baseline: {v.get('estate_baseline_score')} ({v.get('estate_baseline_grade')})")
for sp in v.get("per_segment", []):
    s = sp.get("stats") or {}
    print(f"  {sp.get('segment',''):10} n={s.get('count')} mean={s.get('mean')} "
          f"median={s.get('median')} min={s.get('min')} max={s.get('max')} "
          f"outlier={sp.get('is_outlier')} bands_below={sp.get('bands_below_baseline')} "
          f"grades={json.dumps(sp.get('grade_distribution'))}")

print()
print("=" * 70)
print("CALENDAR (correct fields)")
print("=" * 70)
c = est.get("calendar", {}) or {}
print(f"  overdue={c.get('overdue')} next_30d={c.get('next_30d')} next_90d={c.get('next_90d')}")
for it in (c.get("items") or [])[:14]:
    print(f"    {it.get('domain'):34} {it.get('kind'):14} date={it.get('date')} "
          f"days_left={it.get('days_left')} sev={it.get('severity')}")

print()
print("=" * 70)
print("EXPOSURE / IMPERSONATION — is 15,638 credible?")
print("=" * 70)
x = est.get("exposure", {}) or {}
print("  keys:", sorted(x.keys()))
print(f"  total_7d={x.get('total_7d')} total_30d={x.get('total_30d')}")
for p in (x.get("platforms") or [])[:8]:
    print(f"    {json.dumps(p)[:160]}")

print()
print("=" * 70)
print("PER-DOMAIN: what does one 'broken' domain actually carry?")
print("=" * 70)
for seg in est.get("segments", []):
    for d in seg.get("domains", []):
        if d.get("domain") in ("poppyandjacks.co.uk", "gigglesandwiggles.co.uk"):
            vm = d.get("vm") or {}
            t = vm.get("trust") or {}
            h = vm.get("hygiene") or {}
            print(f"  {d.get('domain')} seg={d.get('segment')} "
                  f"grade={(vm.get('grade') or {}).get('letter')}/{vm.get('composite_score')}")
            print(f"     mx_type={t.get('mx_type')} dmarc={h.get('dmarc_policy')} "
                  f"spf_strict={h.get('spf_strict')}")
            print(f"     findings: {[f.get('title','')[:52] for f in (vm.get('findings') or [])]}")
            print(f"     subdomains={len(vm.get('subdomains') or [])} "
                  f"cert_analysis={len(vm.get('cert_analysis') or {})}")
