import duckdb
import json
try:
    df = duckdb.query("DESCRIBE SELECT * FROM read_parquet('C:/root/asn_data_v3/ducklake/gold/gold_risk_domain_*.parquet')").df()
    print(df.to_string())
    
    # Let's also fetch a row that has domain_risk_context
    row = duckdb.query("SELECT domain_risk_context FROM read_parquet('C:/root/asn_data_v3/ducklake/gold/gold_risk_domain_*.parquet') WHERE domain_risk_context IS NOT NULL LIMIT 1").df()
    if not row.empty:
        print("\nContext sample:")
        print(row['domain_risk_context'].iloc[0])
except Exception as e:
    print(f"Error: {e}")
