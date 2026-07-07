import sys; sys.path.insert(0,"/root/dnsproject")
from scripts.lake_enrich import LakeEnricher
e=LakeEnricher()
for t in ("gold.scenario_domain_intel","gold.scenario_weaponization","gold.gold_risk_domain"):
    try: print(t, "->", e.con.execute(f"SELECT count(*) FROM {t}").fetchone()[0], "rows")
    except Exception as ex: print(t, "-> ERR", str(ex)[:90])
