from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set

from minisoc.common.schema import NormalizedEvent


@dataclass
class _IPState:
    first_seen: float
    last_seen: float
    last_emit: float = 0.0
    total_failures: int = 0
    window_failures: int = 0
    window_reset_at: float = field(default_factory=lambda: time.time())
    users: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)


class SuspiciousTracker:
    """Suspicious-only JSONL logger (threshold + cooldown; no disk spam)."""

    def __init__(self, *, path: Path, window_s: int = 60, threshold: int = 5, cooldown_s: int = 60) -> None:
        self.path = path
        self.window_s = max(1, int(window_s))
        self.threshold = max(1, int(threshold))
        self.cooldown_s = max(0, int(cooldown_s))
        self._state: Dict[str, _IPState] = {}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def observe_failure(self, ev: NormalizedEvent) -> None:
        ip = (ev.src.ip if ev.src else None) or ""
        if not ip:
            return

        now = time.time()
        st = self._state.get(ip)
        if st is None:
            st = _IPState(first_seen=now, last_seen=now)
            self._state[ip] = st

        st.last_seen = now
        st.total_failures += 1

        if now - st.window_reset_at > self.window_s:
            st.window_reset_at = now
            st.window_failures = 0
            st.users.clear()
            st.ports.clear()

        st.window_failures += 1

        if ev.user and ev.user.name:
            st.users.add(ev.user.name)
        if ev.src and ev.src.port is not None:
            try:
                st.ports.add(int(ev.src.port))
            except Exception:
                pass

        if st.window_failures < self.threshold:
            return
        if self.cooldown_s and (now - st.last_emit) < self.cooldown_s:
            return

        st.last_emit = now

        rec = {
            "schema": "minisoc.suspicious.v1",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "reason": f"local_ssh_bruteforce: >= {self.threshold} failures in {self.window_s}s",
            "src": {"ip": ip, "ports": sorted(st.ports)},
            "usernames": sorted(st.users),
            "counts": {
                "window_failures": st.window_failures,
                "total_failures": st.total_failures,
                "window_s": self.window_s,
                "threshold": self.threshold,
                "cooldown_s": self.cooldown_s,
            },
            "host": {"name": ev.host.name if ev.host else None, "ip": ev.host.ip if ev.host else None},
            "event": {"type": ev.event.type, "action": ev.event.action, "outcome": ev.event.outcome, "severity": ev.event.severity},
            "source": {"kind": ev.source.kind if ev.source else None, "path": str(ev.source.path) if ev.source and ev.source.path else None},
            "raw": {"line": ev.raw.line if ev.raw else None, "parser": ev.raw.parser if ev.raw else None},
        }

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
