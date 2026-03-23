import aiosqlite
import datetime

DB_PATH = "security_logs.db"

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                sender TEXT,
                is_malicious BOOLEAN,
                threat_type TEXT,
                confidence REAL,
                latency_ms REAL
            )
        """)
        await db.commit()

async def log_event(sender: str, is_malicious: bool, threat_type: str, confidence: float, latency: float):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO logs (timestamp, sender, is_malicious, threat_type, confidence, latency_ms) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.datetime.now().isoformat(), sender, is_malicious, threat_type, confidence, latency)
        )
        await db.commit()