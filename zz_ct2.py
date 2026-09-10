"""events.certstream_events — real schema. Can it replace CertSpotter for the
three things the cross-estate analytics need?"""
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
        for r in rows[:15]:
            print("   ", r)
        if not rows:
            print("    (no rows)")
    except Exception as e:
        print(f"\n--- {label}\n    ERROR {type(e).__name__}: {e}")


q("date range / freshness", """
    SELECT min(event_date), max(event_date), count(DISTINCT event_date)
    FROM events.certstream_events""")

q("sample: SAN sets", """
    SELECT primary_domain, ca_issuer, san_count, not_after, san_domains[1:4]
    FROM events.certstream_events
    WHERE san_count > 1 LIMIT 5""")

q("COVERAGE — estate domains as primary_domain", """
    SELECT primary_domain, count(*) n, max(event_date) latest
    FROM events.certstream_events
    WHERE primary_domain IN ('bt.com','revolut.com','tiptoes.co.uk',
        'kidsplanetdaynurseries.co.uk','poppyandjacks.co.uk','ee.co.uk','openreach.com')
    GROUP BY 1 ORDER BY n DESC""")

q("COVERAGE — estate domains anywhere in san_domains", """
    SELECT d AS estate_domain, count(*) n
    FROM events.certstream_events, UNNEST(san_domains) AS t(d)
    WHERE d IN ('bt.com','revolut.com','tiptoes.co.uk',
        'kidsplanetdaynurseries.co.uk','poppyandjacks.co.uk','ee.co.uk','openreach.com')
    GROUP BY 1 ORDER BY n DESC""")

q("CA issuer breakdown (top 10 overall)", """
    SELECT ca_issuer, count(*) n FROM events.certstream_events
    GROUP BY 1 ORDER BY n DESC LIMIT 10""")

q("cross-domain SANs — the discovery signal", """
    SELECT primary_domain, san_count, san_domains[1:6]
    FROM events.certstream_events
    WHERE san_count BETWEEN 2 AND 20
      AND primary_domain LIKE '%nursery%'
    LIMIT 5""")
