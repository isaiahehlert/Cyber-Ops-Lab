from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import httpx

from minisoc.common.schema import NormalizedEvent

log = logging.getLogger("minisoc.agent")

SSH_FAIL = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SSH_OK = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")


@dataclass(frozen=True)
class TailStats:
    read: int = 0
    parsed: int = 0
    sent: int = 0
    failed: int = 0


def utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def follow(path: Path, *, from_start: bool = False, sleep_s: float = 0.2) -> Iterator[str]:
    """Tail -f without external deps."""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        if not from_start:
            f.seek(0, 2)  # end
        while True:
            line = f.readline()
            if not line:
                time.sleep(sleep_s)
                continue
            yield line.rstrip("\n")


def replay_file(path: Path) -> Iterator[str]:
    """Read file once from start and exit."""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")


def parse_sshd_line(line: str, host: str, host_ip: str | None, source_path: str) -> NormalizedEvent | None:
    m = SSH_FAIL.search(line)
    outcome: str | None = None
    if m:
        outcome = "failure"
    else:
        m = SSH_OK.search(line)
        if m:
            outcome = "success"

    if not m or not outcome:
        return None

    user = m.group("user")
    ip = m.group("ip")
    port = int(m.group("port"))

    msg = f"SSH login {outcome} for user={user} from {ip}"
    sev = 4 if outcome == "failure" else 3

    return NormalizedEvent.from_parts(
        ts=utc_now_rfc3339(),
        host_name=host,
        host_ip=host_ip,
        source_kind="auth",
        source_path=source_path,
        event_type="auth",
        event_action="ssh_login",
        outcome=outcome,
        severity=sev,
        message=msg,
        raw_line=line,
        parser="auth.sshd",
        user=user,
        src_ip=ip,
        src_port=port,
        tags=["ssh", "auth", outcome],
    )


def send_event(client: httpx.Client, server_url: str, ev: NormalizedEvent) -> None:
    r = client.post(
        f"{server_url.rstrip('/')}/ingest",
        content=ev.model_dump_json(by_alias=True),
        headers={"content-type": "application/json"},
    )
    r.raise_for_status()


def run_tail_auth(
    *,
    server_url: str,
    log_path: Path,
    host: str,
    host_ip: str | None,
    dry_run: bool = False,
    mode: str = "live",          # "live" or "replay"
    from_start_live: bool = False,
) -> TailStats:
    stats = TailStats()

    if mode == "replay":
        iterator = replay_file(log_path)
        source_path = str(log_path)  # for replay, reflect actual file
    else:
        iterator = follow(log_path, from_start=from_start_live)
        source_path = str(log_path)

    with httpx.Client(timeout=5.0) as client:
        for line in iterator:
            stats = TailStats(read=stats.read + 1, parsed=stats.parsed, sent=stats.sent, failed=stats.failed)
            ev = parse_sshd_line(line, host=host, host_ip=host_ip, source_path=source_path)
            if not ev:
                continue

            stats = TailStats(read=stats.read, parsed=stats.parsed + 1, sent=stats.sent, failed=stats.failed)

            if dry_run:
                print(ev.model_dump_json(by_alias=True))
                continue

            try:
                send_event(client, server_url, ev)
                stats = TailStats(read=stats.read, parsed=stats.parsed, sent=stats.sent + 1, failed=stats.failed)
            except Exception:
                log.exception("send failed: server=%s", server_url)
                stats = TailStats(read=stats.read, parsed=stats.parsed, sent=stats.sent, failed=stats.failed + 1)

    # replay exits; live runs forever (so this print mostly helps replay)
    print(f"agent: mode={mode} read={stats.read} parsed={stats.parsed} sent={stats.sent} failed={stats.failed}")
    return stats
