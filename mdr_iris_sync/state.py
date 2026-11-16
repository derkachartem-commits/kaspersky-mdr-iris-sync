"""SQLite state store.

The state database is the source of truth for the MDR incident -> IRIS
alert/case mapping and for comment idempotency. Keep it backed up: losing it
means previously imported incidents can be imported again.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id         TEXT PRIMARY KEY,
    incident_number     TEXT,
    alert_id            INTEGER,
    case_id             INTEGER,
    mdr_status          TEXT,
    mdr_update_time     INTEGER,
    iris_status_id      INTEGER,
    iris_case_status_id INTEGER,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    direction   TEXT NOT NULL,
    source_key  TEXT NOT NULL,
    target_key  TEXT,
    content_hash TEXT,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (direction, source_key)
);

CREATE INDEX IF NOT EXISTS idx_comments_target
    ON comments (direction, target_key);

CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class StateDB:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ kv
    def get_kv(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def get_kv_int(self, key: str, default: int = 0) -> int:
        value = self.get_kv(key)
        try:
            return int(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    def set_kv(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
            self._conn.commit()

    # ----------------------------------------------------------- incidents
    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_incidents(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM incidents ORDER BY created_at ASC"
        params: tuple = ()
        if limit:
            sql += " LIMIT ?"
            params = (int(limit),)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def upsert_incident(
        self,
        incident_id: str,
        *,
        incident_number: Optional[str] = None,
        alert_id: Optional[int] = None,
        case_id: Optional[int] = None,
        mdr_status: Optional[str] = None,
        mdr_update_time: Optional[int] = None,
        iris_status_id: Optional[int] = None,
        iris_case_status_id: Optional[int] = None,
    ) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO incidents (
                    incident_id, incident_number, alert_id, case_id,
                    mdr_status, mdr_update_time, iris_status_id,
                    iris_case_status_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    incident_number     = COALESCE(excluded.incident_number, incidents.incident_number),
                    alert_id            = COALESCE(excluded.alert_id, incidents.alert_id),
                    case_id             = COALESCE(excluded.case_id, incidents.case_id),
                    mdr_status          = COALESCE(excluded.mdr_status, incidents.mdr_status),
                    mdr_update_time     = COALESCE(excluded.mdr_update_time, incidents.mdr_update_time),
                    iris_status_id      = COALESCE(excluded.iris_status_id, incidents.iris_status_id),
                    iris_case_status_id = COALESCE(excluded.iris_case_status_id, incidents.iris_case_status_id),
                    updated_at          = excluded.updated_at
                """,
                (
                    incident_id,
                    incident_number,
                    alert_id,
                    case_id,
                    mdr_status,
                    mdr_update_time,
                    iris_status_id,
                    iris_case_status_id,
                    now,
                    now,
                ),
            )
            self._conn.commit()

    def set_alert(self, incident_id: str, alert_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET alert_id = ?, updated_at = ? WHERE incident_id = ?",
                (int(alert_id), int(time.time()), incident_id),
            )
            self._conn.commit()

    def set_case(self, incident_id: str, case_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET case_id = ?, updated_at = ? WHERE incident_id = ?",
                (int(case_id), int(time.time()), incident_id),
            )
            self._conn.commit()

    def update_states(
        self,
        incident_id: str,
        *,
        mdr_status: Optional[str],
        mdr_update_time: Optional[int],
        iris_status_id: Optional[int],
        iris_case_status_id: Optional[int],
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE incidents SET
                    mdr_status = ?,
                    mdr_update_time = ?,
                    iris_status_id = ?,
                    iris_case_status_id = ?,
                    updated_at = ?
                WHERE incident_id = ?
                """,
                (
                    mdr_status,
                    mdr_update_time,
                    iris_status_id,
                    iris_case_status_id,
                    int(time.time()),
                    incident_id,
                ),
            )
            self._conn.commit()

    # ------------------------------------------------------------ comments
    def comment_seen(self, direction: str, source_key: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM comments WHERE direction = ? AND source_key = ?",
                (direction, source_key),
            ).fetchone()
        return row is not None

    def is_our_target(self, direction: str, target_key: str) -> bool:
        """True if target_key was created by the opposite sync direction."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM comments WHERE direction = ? AND target_key = ?",
                (direction, target_key),
            ).fetchone()
        return row is not None

    def mark_comment(
        self,
        direction: str,
        source_key: str,
        target_key: Optional[str] = None,
        content_hash: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO comments (direction, source_key, target_key, content_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(direction, source_key) DO UPDATE SET
                    target_key = COALESCE(excluded.target_key, comments.target_key),
                    content_hash = COALESCE(excluded.content_hash, comments.content_hash)
                """,
                (direction, source_key, target_key, content_hash, int(time.time())),
            )
            self._conn.commit()

    def comment_hashes(self, direction: str) -> List[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT content_hash FROM comments WHERE direction = ? AND content_hash IS NOT NULL",
                (direction,),
            ).fetchall()
        return [row["content_hash"] for row in rows]
