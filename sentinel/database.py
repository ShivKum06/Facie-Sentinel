import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "sentinel.db"


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS api_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT UNIQUE, timestamp TEXT,
            ip TEXT, user_id TEXT, method TEXT, endpoint TEXT, status_code INTEGER,
            request_size INTEGER, response_size INTEGER, latency REAL
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, threat_type TEXT,
            rule_score INTEGER, anomaly_score REAL, risk_score INTEGER, severity TEXT,
            reason TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, endpoint TEXT, ip TEXT,
            threat_type TEXT, risk_score INTEGER, action TEXT, status TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, original_action TEXT,
            new_action TEXT, reason TEXT, actor TEXT, created_at TEXT
        );
        ''')
        columns = {row["name"] for row in db.execute("PRAGMA table_info(incidents)").fetchall()}
        for column, definition in (("ai_action", "TEXT"), ("ai_confidence", "REAL"), ("ai_reason", "TEXT"), ("facie_state", "TEXT")):
            if column not in columns:
                db.execute(f"ALTER TABLE incidents ADD COLUMN {column} {definition}")


def insert(table: str, values: dict[str, Any]) -> int:
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    with connect() as db:
        cursor = db.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values()))
        return cursor.lastrowid


def rows(query: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connect() as db:
        return [dict(row) for row in db.execute(query, parameters).fetchall()]


def one(query: str, parameters: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    result = rows(query, parameters)
    return result[0] if result else None
