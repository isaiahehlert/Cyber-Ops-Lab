from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from minisoc.agent.sources import follow_file, follow_journal_sshd, pick_auth_source
from minisoc.common.schema import NormalizedEvent


log = logging.getLogger("minisoc.agent")

SSH_FAIL = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")
SSH_OK = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")


@dataclass(frozen=True)
class TailStats:
    read: int = 0
    parsed: int = 0
    sent: int = 0
    failed: int = 0


def utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_sshd_line(line: str, *, host: str, host_ip: str | None, source_path: str) -> NormalizedEvent | None:
    m_fail = SSH_FAIL.search(line)
    m_ok = SSH_OK.search(line)

    if not (m_fail or m_ok):
        return None

    outcome = "failure" if m_fail else "success"
    m = m_fail or m_ok
    assert m is not None

    user = m.group("user")
    ip = m.group("ip")
    port = int(m.group("port"))

    msg = f"SSH login {outcome} for user={user} from {ip}"

    return NormalizedEvent.from_parts(
        ts=utc_now_rfc3339(),
        host_name=host,
        host_ip=host_ip,
        source_kind="auth",
        source_path=source_path,
        event_type="auth",
        action="ssh_login",
        outcome=outcome,
        severity=4 if outcome == "failure" else 3,
        message=msg,
        raw_line=line,
        raw_parser="auth.sshd",
        user=user,
        src_ip=ip,
        src_port=port,
        tags=["ssh", "auth", outcome],
    )


def send_event(client: httpx.Client, server_url: str, ev: NormalizedEvent) -> None:
    # mode="json" converts UUID -> str, etc.
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
    source: str = "auto",      # auto|file|journal
    from_start: bool = False,
) -> TailStats:
    stats = TailStats()
    decision = pick_auth_source(preferred_path=log_path)

    if source == "auto":
        src_kind = decision.kind
        src_path = str(decision.path) if decision.path else "journald:sshd"
        log.info("auth source auto: kind=%s reason=%s", decision.kind, decision.reason)
    elif source == "file":
        src_kind = "file"
        src_path = str(log_path)
        log.info("auth source forced: file path=%s", log_path)
    elif source == "journal":
        src_kind = "journal"
        src_path = "journald:sshd"
        log.info("auth source forced: journald (sshd)")
    else:
        raise ValueError("source must be one of: auto, file, journal")

    if src_kind == "file":
        iterator = follow_file(Path(src_path), from_start=from_start)
    else:
        iterator = follow_journal_sshd(from_start=from_start)

    with httpx.Client(timeout=5.0) as client:
        for line in iterator:
            stats = TailStats(read=stats.read + 1, parsed=stats.parsed, sent=stats.sent, failed=stats.failed)

            ev = parse_sshd_line(line, host=host, host_ip=host_ip, source_path=src_path)
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

    return stats
