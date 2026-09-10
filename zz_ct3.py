"""Is san_domains actually populated? And is there a live certstream landing
prefix beyond the 3-day seed corpus?"""
import sys
sys.path.insert(0, "/root/dnsproject")
sys.path.insert(0, "/root/dnsproject/scripts")

from dotenv import load_dotenv
load_dotenv()

from lake_enrich import lake_connect
con = lake_connect()


def q(label, sql):
    try:
        rows = con.execute(sql).fetchall()
        print(f"\n--- {label}")
        for r in rows[:12]:
            print("   ", r)
        if not rows:
            print("    (no rows)")
    except Exception as e:
        print(f"\n--- {label}\n    ERROR {type(e).__name__}: {e}")


q("san_domains populated?", """
    SELECT
      count(*)                                            AS total,
      count(san_domains)                                  AS san_not_null,
      sum(CASE WHEN len(coalesce(san_domains,[]))>0 THEN 1 ELSE 0 END) AS san_non_empty,
      sum(CASE WHEN san_count>0 THEN 1 ELSE 0 END)        AS san_count_positive
    FROM events.certstream_events""")

q("a row with a real SAN array", """
    SELECT primary_domain, san_count, san_domains
    FROM events.certstream_events
    WHERE san_domains IS NOT NULL AND len(san_domains) > 1
    LIMIT 3""")

q("rows per day", """
    SELECT event_date, count(*) FROM events.certstream_events
    GROUP BY 1 ORDER BY 1""")

# Is anything else in the lake carrying cert/SAN data with better coverage?
q("tables mentioning cert/san", """
    SELECT table_schema, table_name FROM information_schema.tables
    WHERE lower(table_name) LIKE '%cert%' OR lower(table_name) LIKE '%san%'
       OR lower(table_name) LIKE '%ct_%'
    ORDER BY 1,2""")

q("events schema tables", """
    SELECT table_name FROM information_schema.tables
    WHERE table_schema='events' ORDER BY 1""")
