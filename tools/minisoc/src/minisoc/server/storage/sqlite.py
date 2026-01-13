from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from minisoc.common.schema import NormalizedEvent

from .base import Storage


@dataclass(frozen=True)
class Alert:
    alert_id: str
    ts: str
    rule_id: str
    title: str
    severity: int
    entity: str  # e.g. "src_ip:203.0.113.10" or "user:root"
    event_ids: list[str]
    details: dict


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

            c.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                  alert_id TEXT PRIMARY KEY,
                  ts TEXT NOT NULL,
                  rule_id TEXT NOT NULL,
                  title TEXT NOT NULL,
                  severity INTEGER NOT NULL,
                  entity TEXT NOT NULL,
                  event_ids TEXT NOT NULL,
                  details TEXT NOT NULL
                );
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_entity ON alerts(entity);")

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
                    e.model_dump_json(by_alias=True),
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

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        with self._connect() as c:
            cur = c.execute(
                "SELECT ts, rule_id, title, severity, entity, event_ids, details FROM alerts ORDER BY ts DESC LIMIT ?",
                (limit,),
            )
            out: list[dict] = []
            for ts, rule_id, title, severity, entity, event_ids, details in cur.fetchall():
                out.append(
                    {
                        "ts": ts,
                        "rule_id": rule_id,
                        "title": title,
                        "severity": int(severity),
                        "entity": entity,
                        "event_ids": json.loads(event_ids),
                        "details": json.loads(details),
                    }
                )
            return out

    def insert_alert(self, alert: Alert) -> None:
        with self._connect() as c:
            c.execute(
                """
                INSERT OR IGNORE INTO alerts
                (alert_id, ts, rule_id, title, severity, entity, event_ids, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.ts,
                    alert.rule_id,
                    alert.title,
                    int(alert.severity),
                    alert.entity,
                    json.dumps(alert.event_ids),
                    json.dumps(alert.details),
                ),
            )
