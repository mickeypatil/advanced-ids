from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
from typing import Tuple, List
import sqlite3
from datetime import datetime

# Threat Detector Class
class ThreatDetector:
    def __init__(self):
        self.sql_patterns = [
            r"(?i)union.*select",
            r"(?i)select.*from.*where",
            r"(?i)drop.*table",
            r"(?i)1\s*=\s*1",
            r"(?i)or\s*1\s*=\s*1",
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
        ]

    def detect_sql_injection(self, payload: str) -> Tuple[bool, str]:
        for pattern in self.sql_patterns:
            if re.search(pattern, payload):
                return True, f"SQL Injection detected"
        return False, ""

    def detect_xss(self, payload: str) -> Tuple[bool, str]:
        for pattern in self.xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True, f"XSS detected"
        return False, ""

    def analyze(self, payload: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> list:
        alerts = []
        
        is_sqli, reason = self.detect_sql_injection(payload)
        if is_sqli:
            alerts.append({
                "alert_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload_sample": payload[:100],
                "description": reason
            })
        
        is_xss, reason = self.detect_xss(payload)
        if is_xss:
            alerts.append({
                "alert_type": "XSS_ATTEMPT",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload_sample": payload[:100],
                "description": reason
            })
        
        return alerts

# FastAPI Setup
app = FastAPI(title="Advanced IDS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = ThreatDetector()
DB_FILE = "ids_alerts.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            payload_sample TEXT,
            timestamp TEXT,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class AlertRequest(BaseModel):
    payload: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/analyze")
def analyze_payload(request: AlertRequest):
    alerts = detector.analyze(request.payload, request.src_ip, request.dst_ip, request.src_port, request.dst_port)
    
    # Save to database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    for alert in alerts:
        cursor.execute("""
            INSERT INTO alerts 
            (alert_type, severity, src_ip, dst_ip, src_port, dst_port, payload_sample, timestamp, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["alert_type"], alert["severity"], alert["src_ip"], alert["dst_ip"],
            alert["src_port"], alert["dst_port"], alert["payload_sample"],
            datetime.utcnow().isoformat(), alert["description"]
        ))
    
    conn.commit()
    conn.close()
    
    return {"alerts_found": len(alerts), "alerts": alerts}

@app.get("/alerts")
def get_alerts(limit: int = 100):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT rowid, alert_type, severity, src_ip, dst_ip, src_port, dst_port, payload_sample, timestamp, description FROM alerts ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    
    alerts = []
    for row in rows:
        alerts.append({
            "id": row[0],
            "alert_type": row[1],
            "severity": row[2],
            "src_ip": row[3],
            "dst_ip": row[4],
            "src_port": row[5],
            "dst_port": row[6],
            "payload_sample": row[7],
            "timestamp": row[8],
            "description": row[9]
        })
    return alerts

@app.get("/stats")
def get_stats():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    conn.close()
    return {"total_alerts": total_alerts}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
