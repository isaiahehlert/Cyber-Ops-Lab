from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from minisoc.common.schema import NormalizedEvent

from .base import Storage


class SQLiteStorage(Storage):
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init(self) -> None:
        with self._connect() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                  event_id TEXT PRIMARY KEY,
                  ts TEXT NOT NULL,
                  host TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  action TEXT NOT NULL,
                  outcome TEXT NOT NULL,
                  severity INTEGER NOT NULL,
                  user TEXT,
                  src_ip TEXT,
                  message TEXT NOT NULL,
                  json TEXT NOT NULL
                );
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);")

    def insert_events(self, events: Iterable[NormalizedEvent]) -> int:
        rows = []
        for e in events:
            host = e.host.name
            user = e.user.name if e.user and e.user.name else None
            src_ip = e.src.ip if e.src and e.src.ip else None
            rows.append(
                (
                    str(e.event_id),
                    e.ts,
                    host,
                    e.event.type,
                    e.event.action,
                    e.event.outcome,
                    int(e.event.severity),
                    user,
                    src_ip,
                    e.message,
                    e.model_dump_json(),
                )
            )

        with self._connect() as c:
            c.executemany(
                """
                INSERT OR REPLACE INTO events
                (event_id, ts, host, event_type, action, outcome, severity, user, src_ip, message, json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def recent_events(self, limit: int = 50) -> list[dict]:
        with self._connect() as c:
            cur = c.execute("SELECT json FROM events ORDER BY ts DESC LIMIT ?", (limit,))
            return [json.loads(r[0]) for r in cur.fetchall()]
