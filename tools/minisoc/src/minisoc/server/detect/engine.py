from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timezone
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
    h = hashlib.sha256(f"{rule_id}|{entity}|{bucket}".encode("utf-8")).hexdigest()[:24]
    return f"a_{h}"


def parse_ts(ts: str) -> datetime:
    # Expect RFC3339 with Z
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def bucket_minute(ts: str) -> str:
    return ts[:16]  # "YYYY-MM-DDTHH:MM"


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # Great-circle distance
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class BruteForceRule:
    rule_id = "AUTH001"
    title = "SSH brute force suspected"
    severity = 7

    def __init__(self, threshold: int = 5) -> None:
        self.threshold = threshold
        self._fails: dict[str, list[tuple[str, str]]] = {}  # src_ip -> [(ts, event_id)]

    def on_event(self, ev: NormalizedEvent) -> Detection | None:
        if ev.event.type != "auth" or ev.event.action != "ssh_login":
            return None
        if ev.event.outcome != "failure":
            return None
        if not ev.src or not ev.src.ip:
            return None

        src_ip = ev.src.ip
        self._fails.setdefault(src_ip, []).append((ev.ts, str(ev.event_id)))
        if len(self._fails[src_ip]) > 200:
            self._fails[src_ip] = self._fails[src_ip][-200:]

        if len(self._fails[src_ip]) >= self.threshold:
            ids = [eid for _, eid in self._fails[src_ip][-self.threshold :]]
            entity = f"src_ip:{src_ip}"
            b = bucket_minute(ev.ts)
            return Detection(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                entity=entity,
                event_ids=ids,
                details={"threshold": self.threshold, "bucket": b},
            )
        return None


class PasswordSprayRule:
    rule_id = "AUTH002"
    title = "Password spraying suspected"
    severity = 8

    def __init__(self, distinct_users: int = 4, max_per_user: int = 2) -> None:
        self.distinct_users = distinct_users
        self.max_per_user = max_per_user
        # src_ip -> bucket -> user -> [event_id...]
        self._state: dict[str, dict[str, dict[str, list[str]]]] = {}

    def on_event(self, ev: NormalizedEvent) -> Detection | None:
        if ev.event.type != "auth" or ev.event.action != "ssh_login":
            return None
        if ev.event.outcome != "failure":
            return None
        if not ev.src or not ev.src.ip:
            return None
        if not ev.user or not ev.user.name:
            return None

        src_ip = ev.src.ip
        user = ev.user.name
        b = bucket_minute(ev.ts)

        self._state.setdefault(src_ip, {}).setdefault(b, {}).setdefault(user, []).append(str(ev.event_id))

        users = self._state[src_ip][b]
        distinct = len(users)
        # spray-ish if many users targeted but only a little per user
        if distinct >= self.distinct_users and all(len(ids) <= self.max_per_user for ids in users.values()):
            # include one event_id per user for compactness
            event_ids = [ids[-1] for ids in users.values()]
            return Detection(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                entity=f"src_ip:{src_ip}",
                event_ids=event_ids,
                details={"bucket": b, "distinct_users": distinct, "max_per_user": self.max_per_user},
            )
        return None


class NewIPForUserRule:
    rule_id = "AUTH003"
    title = "New source IP for user login"
    severity = 5

    def __init__(self) -> None:
        # user -> set(known_ips)
        self._known: dict[str, set[str]] = {}

    def on_event(self, ev: NormalizedEvent) -> Detection | None:
        if ev.event.type != "auth" or ev.event.action != "ssh_login":
            return None
        if ev.event.outcome != "success":
            return None
        if not ev.user or not ev.user.name:
            return None
        if not ev.src or not ev.src.ip:
            return None

        user = ev.user.name
        ip = ev.src.ip

        known = self._known.setdefault(user, set())
        if known and ip not in known:
            known.add(ip)
            b = bucket_minute(ev.ts)
            return Detection(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                entity=f"user:{user}",
                event_ids=[str(ev.event_id)],
                details={"bucket": b, "new_ip": ip, "known_ip_count": len(known) - 1},
            )

        known.add(ip)
        return None


class OffHoursLoginRule:
    rule_id = "AUTH004"
    title = "Off-hours successful login"
    severity = 6

    def __init__(self, start_hour: int = 8, end_hour: int = 18) -> None:
        # Off-hours if hour < start_hour or hour >= end_hour (UTC for now)
        self.start_hour = start_hour
        self.end_hour = end_hour

    def on_event(self, ev: NormalizedEvent) -> Detection | None:
        if ev.event.type != "auth" or ev.event.action != "ssh_login":
            return None
        if ev.event.outcome != "success":
            return None
        if not ev.user or not ev.user.name:
            return None

        dt = parse_ts(ev.ts)
        hour = dt.hour
        if hour < self.start_hour or hour >= self.end_hour:
            b = bucket_minute(ev.ts)
            return Detection(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                entity=f"user:{ev.user.name}",
                event_ids=[str(ev.event_id)],
                details={"bucket": b, "hour_utc": hour, "start_hour": self.start_hour, "end_hour": self.end_hour},
            )
        return None


class ImpossibleTravelLiteRule:
    rule_id = "AUTH005"
    title = "Impossible travel suspected (geo jump too fast)"
    severity = 9

    def __init__(self, max_kmh: float = 900.0) -> None:
        self.max_kmh = max_kmh
        # user -> (dt, lat, lon, event_id)
        self._last: dict[str, tuple[datetime, float, float, str]] = {}

    def on_event(self, ev: NormalizedEvent) -> Detection | None:
        if ev.event.type != "auth" or ev.event.action != "ssh_login":
            return None
        if ev.event.outcome != "success":
            return None
        if not ev.user or not ev.user.name:
            return None
        if not ev.src or not ev.src.geo:
            return None

        geo = ev.src.geo
        if "lat" not in geo or "lon" not in geo:
            return None

        user = ev.user.name
        dt = parse_ts(ev.ts)
        lat = float(geo["lat"])
        lon = float(geo["lon"])

        prev = self._last.get(user)
        self._last[user] = (dt, lat, lon, str(ev.event_id))

        if not prev:
            return None

        prev_dt, prev_lat, prev_lon, prev_eid = prev
        delta_h = max((dt - prev_dt).total_seconds() / 3600.0, 1e-6)
        dist_km = haversine_km(prev_lat, prev_lon, lat, lon)
        speed = dist_km / delta_h

        if speed > self.max_kmh:
            b = bucket_minute(ev.ts)
            return Detection(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                entity=f"user:{user}",
                event_ids=[prev_eid, str(ev.event_id)],
                details={
                    "bucket": b,
                    "km": round(dist_km, 1),
                    "hours": round(delta_h, 3),
                    "speed_kmh": round(speed, 1),
                    "max_kmh": self.max_kmh,
                },
            )
        return None


class DetectionEngine:
    def __init__(self) -> None:
        self.rules = [
            BruteForceRule(),
            PasswordSprayRule(),
            NewIPForUserRule(),
            OffHoursLoginRule(),
            ImpossibleTravelLiteRule(),
        ]

    def process(self, ev: NormalizedEvent) -> Iterable[Detection]:
        for r in self.rules:
            d = r.on_event(ev)
            if d:
                yield d

    def to_alert(self, det: Detection, ts: str) -> Alert:
        bucket = str(det.details.get("bucket", bucket_minute(ts)))
        alert_id = stable_alert_id(det.rule_id, det.entity, bucket)
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
