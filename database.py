"""
Time-Series Database Layer
Stores network measurements over time using SQLite to distinguish
temporary anomalies from persistent issues.
"""

import sqlite3
import json
import time
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "network_guardian.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module TEXT NOT NULL,
            timestamp REAL NOT NULL,
            raw_data TEXT NOT NULL,
            diagnoses TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scan_module_time
            ON scan_history(module, timestamp);
    """)
    conn.commit()
    conn.close()


def save_scan(module, raw_data, diagnoses):
    """Save a scan result with its diagnoses."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO scan_history (module, timestamp, raw_data, diagnoses) VALUES (?, ?, ?, ?)",
        (module, time.time(), json.dumps(raw_data), json.dumps(diagnoses))
    )
    conn.commit()
    conn.close()


def get_history(module, limit=20):
    """Retrieve recent scan history for a module."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scan_history WHERE module = ? ORDER BY timestamp DESC LIMIT ?",
        (module, limit)
    ).fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "module": row["module"],
            "timestamp": row["timestamp"],
            "raw_data": json.loads(row["raw_data"]),
            "diagnoses": json.loads(row["diagnoses"]),
        })
    return results


def get_trend(module, hours=24):
    """Get scan results from the last N hours for trend analysis."""
    cutoff = time.time() - (hours * 3600)
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scan_history WHERE module = ? AND timestamp > ? ORDER BY timestamp ASC",
        (module, cutoff)
    ).fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "diagnoses": json.loads(row["diagnoses"]),
        })
    return results


# Initialize on import
init_db()
