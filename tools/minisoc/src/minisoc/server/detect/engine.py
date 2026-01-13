from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable

from minisoc.common.schema import NormalizedEvent
from minisoc.server.storage.sqlite import Alert


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: int
    entity: str
    event_ids: list[str]
    details: dict


def stable_alert_id(rule_id: str, entity: str, bucket: str) -> str:
    # bucket lets you dedupe per time-window (“2026-01-12T00:00” etc.)
    h = hashlib.sha256(f"{rule_id}|{entity}|{bucket}".encode("utf-8")).hexdigest()[:24]
    return f"a_{h}"


class BruteForceRule:
    rule_id = "AUTH001"
    title = "SSH brute force suspected"
    severity = 7

    def __init__(self, threshold: int = 5, window_s: int = 120) -> None:
        self.threshold = threshold
        self.window_s = window_s
        # state: src_ip -> list of (ts_str, event_id)
        self._fails: dict[str, list[tuple[str, str]]] = {}

    def _prune(self, ts: str, src_ip: str) -> None:
        # MVP: prune by keeping last N only (cheap). We’ll do real time math later.
        lst = self._fails.get(src_ip, [])
        if len(lst) > 200:
            self._fails[src_ip] = lst[-200:]

    def on_event(self, ev: NormalizedEvent) -> Detection | None:
        if ev.event.type != "auth" or ev.event.action != "ssh_login":
            return None
        if ev.event.outcome != "failure":
            return None
        if not ev.src or not ev.src.ip:
            return None

        src_ip = ev.src.ip
        self._fails.setdefault(src_ip, []).append((ev.ts, str(ev.event_id)))
        self._prune(ev.ts, src_ip)

        # crude window bucket: minute-level
        bucket = ev.ts[:16]  # "YYYY-MM-DDTHH:MM"
        fails = self._fails[src_ip]

        if len(fails) >= self.threshold:
            event_ids = [eid for _, eid in fails[-self.threshold :]]
            entity = f"src_ip:{src_ip}"
            return Detection(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                entity=entity,
                event_ids=event_ids,
                details={"threshold": self.threshold, "bucket": bucket},
            )
        return None


class DetectionEngine:
    def __init__(self) -> None:
        self.rules: list[BruteForceRule] = [BruteForceRule()]

    def process(self, ev: NormalizedEvent) -> Iterable[Detection]:
        for r in self.rules:
            d = r.on_event(ev)
            if d:
                yield d

    def to_alert(self, det: Detection, ts: str) -> Alert:
        bucket = det.details.get("bucket", ts[:16])
        alert_id = stable_alert_id(det.rule_id, det.entity, str(bucket))
        return Alert(
            alert_id=alert_id,
            ts=ts,
            rule_id=det.rule_id,
            title=det.title,
            severity=det.severity,
            entity=det.entity,
            event_ids=det.event_ids,
            details=det.details,
        )
