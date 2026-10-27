"""Persistent audit trail (SQLite, parameterized queries only)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    session     TEXT    NOT NULL,
    stage       TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    risk_score  INTEGER NOT NULL,
    findings    TEXT    NOT NULL,
    preview     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class AuditLog:
    def __init__(self, path: str = "agentwarden_audit.db"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)

    def write(self, event: dict[str, Any]) -> dict[str, Any]:
        event = {**event, "ts": time.time()}
        with self._lock:
            self._db.execute(
                "INSERT INTO events (ts, session, stage, target, action, risk_score, findings, preview) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event["ts"], event["session"], event["stage"], event["target"], event["action"],
                 event["risk_score"], json.dumps(event["findings"]), event["payload_preview"]))
            self._db.commit()
        return event

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [{"id": r["id"], "ts": r["ts"], "session": r["session"], "stage": r["stage"],
                 "target": r["target"], "action": r["action"], "risk_score": r["risk_score"],
                 "findings": json.loads(r["findings"]), "payload_preview": r["preview"]} for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            by_action = dict(self._db.execute("SELECT action, COUNT(*) FROM events GROUP BY action").fetchall())
            rows = self._db.execute("SELECT findings FROM events WHERE action != 'allow'").fetchall()
        detectors: dict[str, int] = {}
        for (f,) in rows:
            for item in json.loads(f):
                detectors[item["detector"]] = detectors.get(item["detector"], 0) + 1
        return {"total": sum(by_action.values()), "by_action": by_action,
                "top_detectors": sorted(detectors.items(), key=lambda kv: -kv[1])[:8]}
