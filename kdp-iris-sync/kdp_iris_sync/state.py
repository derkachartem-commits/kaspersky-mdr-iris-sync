"""SQLite state: webhook outbox + KDP event registry (idempotency)."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    processed_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS events (
    event_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    external_id TEXT NOT NULL,
    resource TEXT,
    alert_id INTEGER,
    case_id INTEGER,
    state TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    details TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class State:
    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.executescript(SCHEMA)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(events)")}
            if "case_id" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN case_id INTEGER")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    # ---------------------------------------------------------------- outbox
    def add_outbox(self, payload: Dict[str, Any]) -> int:
        with self._lock, self._connect() as db:
            cur = db.execute(
                "INSERT INTO outbox(received_at, payload) VALUES (?, ?)",
                (utcnow(), json.dumps(payload, ensure_ascii=False)),
            )
            return int(cur.lastrowid)

    def pending(self, limit: int = 20) -> List[sqlite3.Row]:
        with self._connect() as db:
            return list(
                db.execute(
                    "SELECT * FROM outbox WHERE processed_at IS NULL ORDER BY id LIMIT ?",
                    (limit,),
                )
            )

    def mark_done(self, row_id: int) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE outbox SET processed_at=?, last_error=NULL WHERE id=?",
                (utcnow(), row_id),
            )

    def mark_error(self, row_id: int, error: str) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE outbox SET attempts=attempts+1, last_error=? WHERE id=?",
                (error[:2000], row_id),
            )

    def outbox_stats(self) -> Dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT COUNT(*) AS pending, "
                "MIN(received_at) AS oldest FROM outbox WHERE processed_at IS NULL"
            ).fetchone()
            return {"pending": row["pending"], "oldest_pending": row["oldest"]}

    # ------------------------------------------------------------------ meta
    def set_meta(self, key: str, value: str) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_meta(self, key: str, default: str = "") -> str:
        with self._connect() as db:
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    # ---------------------------------------------------------------- events
    def get_event(self, key: str) -> Optional[sqlite3.Row]:
        with self._connect() as db:
            return db.execute("SELECT * FROM events WHERE event_key=?", (key,)).fetchone()

    def open_event(
        self, key: str, kind: str, external_id: str, resource: str, details: Dict[str, Any]
    ) -> sqlite3.Row:
        now = utcnow()
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO events(event_key, kind, external_id, resource, state, "
                "first_seen, last_seen, details) VALUES (?,?,?,?,'open',?,?,?) "
                "ON CONFLICT(event_key) DO UPDATE SET last_seen=excluded.last_seen, "
                "details=excluded.details",
                (key, kind, external_id, resource, now, now,
                 json.dumps(details, ensure_ascii=False)),
            )
            return db.execute("SELECT * FROM events WHERE event_key=?", (key,)).fetchone()

    def set_alert_id(self, key: str, alert_id: int) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE events SET alert_id=? WHERE event_key=?", (alert_id, key))

    def set_case_id(self, key: str, case_id: int) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE events SET case_id=? WHERE event_key=?", (case_id, key))

    def close_event(self, key: str) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE events SET state='closed', last_seen=? WHERE event_key=?",
                (utcnow(), key),
            )

    def touch(self, key: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE events SET last_seen=? WHERE event_key=?", (utcnow(), key))

    def list_events(self, state: Optional[str] = "open", limit: int = 200) -> List[sqlite3.Row]:
        with self._connect() as db:
            if state:
                rows = db.execute(
                    "SELECT * FROM events WHERE state=? ORDER BY last_seen DESC LIMIT ?",
                    (state, limit),
                )
            else:
                rows = db.execute(
                    "SELECT * FROM events ORDER BY last_seen DESC LIMIT ?", (limit,)
                )
            return list(rows)
