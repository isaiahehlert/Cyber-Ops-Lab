from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

log = logging.getLogger("minisoc.alerting")


@dataclass(frozen=True)
class AlertOut:
    alert_id: str
    ts: str  # event time (what we display)
    rule_id: str
    title: str
    severity: int
    entity: str
    event_ids: list[str]
    details: dict


class Notifier(Protocol):
    def notify(self, alert: AlertOut, suppressed_repeats: int = 0) -> None: ...


class ConsoleNotifier:
    def notify(self, alert: AlertOut, suppressed_repeats: int = 0) -> None:
        extra = f" (+{suppressed_repeats} suppressed repeats)" if suppressed_repeats > 0 else ""
        print(f"[ALERT] {alert.ts} {alert.rule_id} sev={alert.severity} {alert.entity} :: {alert.title}{extra}")
        if alert.details:
            print("        details:", json.dumps(alert.details, sort_keys=True))


def _parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class DedupeCache:
    """
    Persisted dedupe with TTL based on *seen time* (when we emitted/routed the alert),
    not event time. This is crucial for delayed logs and replay labs.
    File format: alert_id|seen_ts
    """
    def __init__(self, path: Path, ttl_minutes: int = 60) -> None:
        self.path = path
        self.ttl = timedelta(minutes=max(ttl_minutes, 0))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seen: dict[str, datetime] = {}
        self._load_and_prune()

    def _load_and_prune(self) -> None:
        now = datetime.now(timezone.utc)
        lines = self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if "|" not in line:
                self._seen[line] = now
                continue
            aid, ts = line.split("|", 1)
            try:
                self._seen[aid] = _parse_ts(ts)
            except Exception:
                self._seen[aid] = now

        self._prune()
        self._rewrite()

    def _rewrite(self) -> None:
        with self.path.open("w", encoding="utf-8") as f:
            for aid, seen_dt in self._seen.items():
                f.write(f"{aid}|{seen_dt.isoformat().replace('+00:00','Z')}\n")

    def _prune(self) -> None:
        if self.ttl.total_seconds() <= 0:
            self._seen.clear()
            return
        cutoff = datetime.now(timezone.utc) - self.ttl
        self._seen = {aid: dt for aid, dt in self._seen.items() if dt >= cutoff}

    def seen(self, alert_id: str) -> bool:
        if self.ttl.total_seconds() <= 0:
            return False
        self._prune()
        return alert_id in self._seen

    def mark_seen_now(self, alert_id: str) -> None:
        if self.ttl.total_seconds() <= 0:
            return
        self._seen[alert_id] = datetime.now(timezone.utc)
        self._rewrite()


class Router:
    """
    Routes alerts with dedupe + suppressed-repeat counting.

    - If dedupe suppresses an alert_id, increment suppressed counter.
    - When it emits again (after TTL), it prints (+N suppressed repeats).
    """
    def __init__(self, notifier: Notifier, dedupe: DedupeCache | None = None) -> None:
        self.notifier = notifier
        self.dedupe = dedupe
        self._suppressed: dict[str, int] = {}

    def route(self, alert: AlertOut) -> None:
        if self.dedupe and self.dedupe.seen(alert.alert_id):
            self._suppressed[alert.alert_id] = self._suppressed.get(alert.alert_id, 0) + 1
            n = self._suppressed[alert.alert_id]
            if n in (10, 25, 50, 100):
                log.info("dedupe: alert_id=%s suppressed=%d", alert.alert_id, n)
            return

        suppressed = self._suppressed.pop(alert.alert_id, 0)
        self.notifier.notify(alert, suppressed_repeats=suppressed)

        if self.dedupe:
            # IMPORTANT: mark seen by *now*, not by alert.ts (event time)
            self.dedupe.mark_seen_now(alert.alert_id)
