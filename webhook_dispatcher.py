import os
import json
import time
import logging
import sqlite3
import duckdb
import asyncio
from datetime import datetime, timezone
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - WEBHOOK_DISPATCHER - %(levelname)s - %(message)s')

app = FastAPI(title="Datazag Blocklist Webhook Dispatcher", version="1.0")

DB_PATH = "C:/root/asn_data_v3/ducklake/gold/unified_blocklist_latest.parquet" if os.name == 'nt' else "/root/asn_data_v3/ducklake/gold/unified_blocklist_latest.parquet"
STATE_DB = os.path.join(os.path.dirname(__file__), "webhook_state.db")
WEBHOOK_REGISTRY = os.path.join(os.path.dirname(__file__), "webhooks.json")

def init_db():
    conn = sqlite3.connect(STATE_DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS dispatched_alerts (
            domain TEXT PRIMARY KEY,
            threat_level TEXT,
            dispatched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class WebhookConfig(BaseModel):
    client_name: str
    webhook_url: str
    minimum_threat_level: str = "HIGH"

@app.post("/register_webhook")
async def register_webhook(config: WebhookConfig):
    webhooks = []
    if os.path.exists(WEBHOOK_REGISTRY):
        with open(WEBHOOK_REGISTRY, "r") as f:
            webhooks = json.load(f)
            
    # Update or add
    webhooks = [w for w in webhooks if w["client_name"] != config.client_name]
    webhooks.append(config.dict())
    
    with open(WEBHOOK_REGISTRY, "w") as f:
        json.dump(webhooks, f, indent=4)
        
    return {"status": "success", "message": f"Webhook registered for {config.client_name}"}

def check_and_dispatch():
    if not os.path.exists(DB_PATH):
        logging.warning(f"Blocklist parquet not found at {DB_PATH}. Waiting for compactor.")
        return

    try:
        # 1. Read latest blocklist
        db = duckdb.connect()
        df = db.execute(f"SELECT domain, primary_ip, risk_score, threat_level, reasons FROM read_parquet('{DB_PATH}')").df()
    except Exception as e:
        logging.error(f"DuckDB read error: {e}")
        return

    # 2. Get registered webhooks
    if not os.path.exists(WEBHOOK_REGISTRY):
        return
        
    with open(WEBHOOK_REGISTRY, "r") as f:
        webhooks = json.load(f)
        
    if not webhooks:
        return

    # 3. Check state DB
    conn = sqlite3.connect(STATE_DB)
    c = conn.cursor()
    
    dispatched = 0
    for _, row in df.iterrows():
        domain = row["domain"]
        threat_level = row["threat_level"]
        
        c.execute("SELECT 1 FROM dispatched_alerts WHERE domain=?", (domain,))
        if c.fetchone():
            continue # Already alerted
            
        # Dispatch to matching webhooks
        payload = {
            "incident_id": f"BLK-{int(time.time())}-{domain}",
            "domain": domain,
            "primary_ip": row["primary_ip"],
            "risk_score": row["risk_score"],
            "threat_level": threat_level,
            "reasons": row["reasons"],
            "timestamp_utc": datetime.now(timezone.utc).isoformat()
        }
        
        for wh in webhooks:
            # Simple threshold logic
            if wh["minimum_threat_level"] == "CRITICAL" and threat_level != "CRITICAL":
                continue
                
            try:
                resp = requests.post(wh["webhook_url"], json=payload, timeout=5.0)
                logging.info(f"📤 Dispatched blocklist alert for {domain} to {wh['client_name']} (Status: {resp.status_code})")
            except Exception as e:
                logging.error(f"❌ Failed to reach webhook for {wh['client_name']}: {e}")
                
        # Mark as dispatched
        c.execute("INSERT INTO dispatched_alerts (domain, threat_level) VALUES (?, ?)", (domain, threat_level))
        dispatched += 1
        
    conn.commit()
    conn.close()
    
    if dispatched > 0:
        logging.info(f"✅ Dispatched {dispatched} new infrastructure alerts.")

@app.get("/trigger_dispatch")
async def trigger_dispatch(background_tasks: BackgroundTasks):
    """Manually trigger the dispatch loop (can also be called via cron)"""
    background_tasks.add_task(check_and_dispatch)
    return {"status": "Dispatched background task"}

if __name__ == "__main__":
    import uvicorn
    # Make sure we have an empty registry to start
    if not os.path.exists(WEBHOOK_REGISTRY):
        with open(WEBHOOK_REGISTRY, "w") as f:
            json.dump([], f)
    
    uvicorn.run(app, host="0.0.0.0", port=8085)
