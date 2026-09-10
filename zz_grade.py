"""Grade the rendered estate report against the independently-recorded ground
truth in estates/nursery_group/EXPECTED_FINDINGS.md."""
import json

BASE = "/root/output/estate/Kids_Planet_Day_Nurseries"

est = json.load(open(f"{BASE}/estate.json"))
rep = json.load(open(f"{BASE}/estate_report.json"))

print("=" * 68)
print("CROSSESTATE EXCEPTION REGISTER")
print("=" * 68)
for e in est.get("exceptions", []):
    members = e.get("members") or []
    m = f"  [{len(members)}] {', '.join(members[:4])}" + (" ..." if len(members) > 4 else "")
    print(f"  {e.get('severity','?'):9} {e.get('finding','?')}")
    print(f"      {e.get('title','')[:110]}")
    if members:
        print(f"     {m}")

print()
print("=" * 68)
print("CONCENTRATION DIMENSIONS")
print("=" * 68)
for d in est.get("concentration", []):
    print(f"  {d.get('label','?'):32} top={d.get('top_provider')} "
          f"pct={d.get('top_pct')} denom={d.get('denom')} flagged={d.get('flagged')}")

print()
print("=" * 68)
print("VARIANCE BY SEGMENT")
print("=" * 68)
v = est.get("variance", {}) or {}
print(f"  estate baseline score: {v.get('estate_baseline_score')}")
for sp in v.get("per_segment", []):
    print(f"  {sp.get('segment','?'):12} n={sp.get('count')} median={sp.get('median_score')} "
          f"bands_below={sp.get('bands_below_baseline')}")
print(f"  grade distribution: {json.dumps(v.get('grade_distribution'))}")

print()
print("=" * 68)
print("CALENDAR")
print("=" * 68)
c = est.get("calendar", {}) or {}
print(f"  overdue={c.get('overdue')} next_30d={c.get('next_30d')} next_90d={c.get('next_90d')}")
for it in (c.get("items") or [])[:8]:
    print(f"    {it.get('domain')} {it.get('kind')} {it.get('due')}")

print()
print("=" * 68)
print("GROUND-TRUTH CHECK")
print("=" * 68)
GT = {
    "poppyandjacks.co.uk": "live MX (M365), dead web",
    "wavertondaynurseries.co.uk": "live MX (Google), dead web",
    "thehunnypot.co.uk": "previous owner's hosting/mail",
    "tiptoes.co.uk": "expired TLS cert",
    "lindenhousedaynursery.co.uk": "TLS misconfig",
    "lawleyvillagedaynursery.co.uk": "registrar parking page",
    "gigglesandwiggles.co.uk": "registrar parking page",
    "highbanknursery.co.uk": "registrar parking page",
    "earlybirdsdaynursery.co.uk": "registrar parking page",
}
named = set()
for e in est.get("exceptions", []):
    named.update(e.get("members") or [])
for e in rep.get("exceptions", []):
    named.update(e.get("members") or e.get("domains") or [])

for dom, what in GT.items():
    print(f"  {'NAMED  ' if dom in named else 'MISSING'}  {dom:32} {what}")

print()
print(f"  exception register named {len(named)} distinct domains")
