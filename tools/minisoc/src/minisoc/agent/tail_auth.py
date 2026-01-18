from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from minisoc.agent.sources import follow_file, follow_journal_sshd, pick_auth_source
from minisoc.agent.suspicious import SuspiciousTracker
from minisoc.common.schema import NormalizedEvent
import httpx



def _strip_syslog_prefix(line: str) -> str:
    # Accept either syslog-shaped lines or journald '-o cat' lines.
    # Example syslog: 'Jan 18 00:00:23 host sshd[2215]: Failed password ...'
    return re.sub(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+", "", line)

def _normalize_journal_message(line: str) -> str:
    """
    journald -o cat often emits message-only lines, e.g.:
      "Failed password for pi from 192.168.0.102 port 49280 ssh2"
    Our sshd parser expects syslog-ish lines containing "sshd[...]:".
    This function wraps message-only sshd lines into a syslog-like string.
    """
    s = line.strip()
    if not s:
        return s
    # If it already looks syslog-ish, keep it.
    if "sshd[" in s or "sshd:" in s:
        return s
    # Common sshd messages (message-only)
    if s.startswith("Failed password ") or s.startswith("Invalid user ") or s.startswith("Connection closed by "):
        return f"sshd[0]: {s}"
    return s

log = logging.getLogger("minisoc.agent")

DEBUG_SAMPLE_LINES = 10

Mode = Literal["live", "replay"]
SourcePref = Literal["auto", "file", "journal"]

SSH_FAIL = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")
SSH_OK = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")


def utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class TailStats:
    read: int = 0
    parsed: int = 0
    sent: int = 0
    failed: int = 0


def parse_sshd_line(line: str, *, host: str, host_ip: str | None, source_path: str) -> NormalizedEvent | None:
    line = _strip_syslog_prefix(line)
    m = SSH_FAIL.search(line)
    outcome = None
    sev = None
    if m:
        outcome = "failure"
        sev = 4
    else:
        m = SSH_OK.search(line)
        if m:
            outcome = "success"
            sev = 3

    if not m:
        return None

    user = m.group("user")
    ip = m.group("ip")
    port = int(m.group("port"))

    ev = NormalizedEvent(
        schema="minisoc.event.v1",
        ts=utc_now_rfc3339(),
        event_id=uuid4(),
        host={"name": host, "ip": host_ip},
        source={"kind": "auth", "path": source_path},
        event={"type": "auth", "action": "ssh_login", "outcome": outcome, "severity": sev},
        message=f"SSH login {outcome} for user={user} from {ip}",
        raw={"line": line, "parser": "auth.sshd"},
        user={"name": user, "uid": None},
        src={"ip": ip, "port": port, "geo": None},
        tags=["ssh", "auth", outcome],
    )
    return ev


def send_event(client: httpx.Client, server_url: str, ev: NormalizedEvent) -> None:
    # IMPORTANT: ensure UUID/datetime become JSON-safe
    payload = ev.model_dump(mode="json", by_alias=True)
    r = client.post(f"{server_url.rstrip('/')}/ingest", json=payload)
    r.raise_for_status()


def run_tail_auth(
    *,
    server_url: str,
    log_path: Path,
    host: str,
    host_ip: str | None,
    dry_run: bool,
    mode: Mode,
    from_start_live: bool,
    source: SourcePref = "auto",
    heartbeat_s: float | None = 30.0,
    suspicious_log_path: Path | None = None,
    local_bruteforce_window_s: int = 60,
    local_bruteforce_threshold: int = 5,
    local_bruteforce_cooldown_s: int = 60,
) -> TailStats:
    """
    live: follow forever
    replay: read once then exit
    """
    stats = TailStats()

    source_kind = source
    tracker = None
    debug_sample_remaining = DEBUG_SAMPLE_LINES
    if suspicious_log_path:
        tracker = SuspiciousTracker(
            path=suspicious_log_path,
            window_s=local_bruteforce_window_s,
            threshold=local_bruteforce_threshold,
            cooldown_s=local_bruteforce_cooldown_s,
        )

    decision = pick_auth_source(log_path, prefer=source)

    source_kind = decision.kind
    # banner: what we picked and why
    log.info(
        "agent source selected: kind=%s path=%s reason=%s",
        decision.kind,
        str(decision.path) if decision.path else "-",
        decision.reason,
    )
    if decision.kind == "file" and (decision.path is None or not decision.path.exists()):
        log.warning("auth file missing/unreadable; if this is a container, use source=journal (or auto fallback).")

    # iterator selection
    if decision.kind == "journal":
        iterator = follow_journal_sshd(from_start=(mode == "replay"))
        source_path = "journald:sshd"
    else:
        # file mode
        p = decision.path or log_path
        iterator = follow_file(p, from_start=(mode == "replay") or from_start_live)
        source_path = str(p)

    last_beat = time.monotonic()
    beat_enabled = heartbeat_s is not None and heartbeat_s > 0

    with httpx.Client(timeout=5.0) as client:
        for line in iterator:
            stats = TailStats(read=stats.read + 1, parsed=stats.parsed, sent=stats.sent, failed=stats.failed)
        if source_kind == "journal":
            line = _normalize_journal_message(line)
            if debug_sample_remaining > 0:
                log.info(f"RAW(journal): {line}")
                debug_sample_remaining -= 1


            # --- DEBUG/ROBUSTNESS: always let parser try; log first N raw lines ---
            if source_kind == "journal":
                line = _normalize_journal_message(line)
            if debug_sample_remaining > 0:
                log.info("RAW(%s): %s", source_kind, line)
                debug_sample_remaining -= 1
            ev = parse_sshd_line(line, host=host, host_ip=host_ip, source_path=source_path)
            if ev:
                stats = TailStats(read=stats.read, parsed=stats.parsed + 1, sent=stats.sent, failed=stats.failed)

                if dry_run:
                    print(json.dumps(ev.model_dump(mode="json", by_alias=True)))
                else:
                    try:
                        if tracker and ev.event.outcome == "failure":
                            try:
                                tracker.observe_failure(ev)
                            except Exception:
                                pass
                        send_event(client, server_url, ev)
                        stats = TailStats(read=stats.read, parsed=stats.parsed, sent=stats.sent + 1, failed=stats.failed)
                    except Exception:
                        log.exception("send failed: server=%s", server_url)
                        stats = TailStats(read=stats.read, parsed=stats.parsed, sent=stats.sent, failed=stats.failed + 1)

            if beat_enabled and mode == "live":
                now = time.monotonic()
                if now - last_beat >= float(heartbeat_s):
                    log.info("agent heartbeat: read=%d parsed=%d sent=%d failed=%d", stats.read, stats.parsed, stats.sent, stats.failed)
                    last_beat = now

            if mode == "replay":
                # replay mode ends when file iterator ends; journal iterator doesn't naturally end,
                # so we require file-based replay or user uses --from-start + live if they want.
                # Here we only exit if we've hit EOF semantics via follow_file (not possible to detect here),
                # so replay is primarily intended for file sources.
                pass

    return stats
