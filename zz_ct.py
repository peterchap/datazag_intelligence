"""Can events.certstream_events stand in for CertSpotter?

Needs to supply three things the cross-estate analytics use:
  1. issuer_breakdown   -> CA concentration dimension
  2. not_after          -> certificate expiry in the calendar block
  3. cross_domain_sans  -> discovery corroboration (the hard one: needs SAN SETS,
                          not just per-domain rows)
"""
import json
import sys

sys.path.insert(0, "/root/dnsproject")
sys.path.insert(0, "/root/dnsproject/scripts")

from dotenv import load_dotenv
load_dotenv()

try:
    from lake_enrich import lake_connect
    con = lake_connect()
except Exception as e:
    print(f"lake_enrich.lake_connect failed: {type(e).__name__}: {e}")
    from ducklake_conn import connect
    con = connect()


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


q("row count", "SELECT count(*) FROM events.certstream_events")
q("columns", """SELECT column_name, data_type FROM information_schema.columns
                WHERE table_schema='events' AND table_name='certstream_events'
                ORDER BY ordinal_position""")
q("date range", """SELECT min(capture_timestamp), max(capture_timestamp)
                   FROM events.certstream_events""")
q("sample rows", """SELECT domain, primary_domain, ca_issuer, not_after
                    FROM events.certstream_events LIMIT 5""")
q("raw_metadata sample (SAN sets?)", """SELECT raw_metadata
                                        FROM events.certstream_events
                                        WHERE raw_metadata IS NOT NULL LIMIT 2""")
q("coverage: our estate domains", """
    SELECT primary_domain, count(*) n, max(capture_timestamp) latest
    FROM events.certstream_events
    WHERE primary_domain IN ('bt.com','revolut.com','tiptoes.co.uk',
                             'kidsplanetdaynurseries.co.uk','poppyandjacks.co.uk')
    GROUP BY 1 ORDER BY n DESC""")
