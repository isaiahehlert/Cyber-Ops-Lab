from __future__ import annotations

import os
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Literal


SourceKind = Literal["file", "journal"]


@dataclass(frozen=True)
class AutoSourceDecision:
    kind: SourceKind
    reason: str
    path: Path | None = None


DEFAULT_AUTH_PATH_CANDIDATES: tuple[Path, ...] = (
    Path("/var/log/auth.log"),     # Debian/Ubuntu/RPi OS
    Path("/var/log/secure"),       # RHEL/CentOS/Fedora
    Path("/var/log/messages"),     # some syslog setups
)


def _is_readable_file(p: Path) -> bool:
    try:
        return p.exists() and p.is_file() and os.access(p, os.R_OK)
    except Exception:
        return False


def journalctl_available() -> bool:
    # cheap capability probe; no follow mode, no buffering issues
    try:
        r = subprocess.run(
            ["journalctl", "-n", "1", "-o", "short", "-u", "ssh", "-u", "sshd", "--no-pager"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def pick_auth_source(
    requested_path: Path | None,
    prefer: SourceKind | Literal["auto"] = "auto",
) -> AutoSourceDecision:
    """
    Decide where to read sshd/auth events from.

    Rules:
    - If prefer="file": use requested_path (or first candidate) if readable, else error (no journald fallback).
    - If prefer="journal": use journald if available, else error.
    - If prefer="auto": try file first, then fall back to journald if no readable file exists.
    """
    file_target: Path | None = requested_path
    if file_target is None:
        for c in DEFAULT_AUTH_PATH_CANDIDATES:
            if _is_readable_file(c):
                file_target = c
                break

    if prefer == "file":
        if file_target and _is_readable_file(file_target):
            return AutoSourceDecision("file", "prefer=file and path readable", path=file_target)
        return AutoSourceDecision("file", "prefer=file but no readable auth log path found", path=file_target)

    if prefer == "journal":
        if journalctl_available():
            return AutoSourceDecision("journal", "prefer=journal and journalctl available", path=None)
        return AutoSourceDecision("journal", "prefer=journal but journalctl not available", path=None)

    # auto
    if file_target and _is_readable_file(file_target):
        return AutoSourceDecision("file", "auto picked readable auth log file", path=file_target)

    if journalctl_available():
        return AutoSourceDecision("journal", "auto fell back to journald (no readable auth log file)", path=None)

    return AutoSourceDecision(
        "file",
        "auto failed: no readable auth log file and journalctl unavailable",
        path=file_target,
    )


def follow_file(path: Path, *, from_start: bool, sleep_s: float = 0.2) -> Iterator[str]:
    """
    Tail -f a file with no deps.
    - from_start=False: start at end (live mode)
    - from_start=True: start at beginning (replay/lab mode)
    """
    with path.open("r", encoding="utf-8", errors="replace") as f:
        if not from_start:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(sleep_s)
                continue
            yield line.rstrip("\n")


def follow_journal_sshd(*, from_start: bool, poll_s: float = 0.35) -> Iterator[str]:
    """
    GUARANTEED journald reader (no `journalctl -f`).
    We poll `journalctl --since <time>` repeatedly and de-dupe lines.

    Why: `journalctl -f` + pipes can stall forever due to buffering behavior.
    Polling avoids that entire failure class.
    """
    # Start window:
    # - from_start: go way back
    # - live: start a few minutes back so we catch immediate attempts
    if from_start:
        since = "1970-01-01 00:00:00"
    else:
        since = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

    # de-dupe sliding window of recent lines
    recent = deque(maxlen=500)
    recent_set: set[str] = set()

    def bump_recent(s: str) -> bool:
        # returns True if new
        if s in recent_set:
            return False
        recent.append(s)
        recent_set.add(s)
        # keep set in sync with deque
        if len(recent) == recent.maxlen:
            # rebuild occasionally to avoid set growth
            recent_set.clear()
            recent_set.update(recent)
        return True

    while True:
        # overlap slightly to avoid missing boundary events
        # (we de-dupe so overlap is safe)
        args = [
            "journalctl",
            "-o",
            "short",
            "-u",
            "ssh",
            "-u",
            "sshd",
            "--since",
            since,
            "--no-pager",
        ]
        try:
            r = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
            if r.stdout:
                for line in r.stdout.splitlines():
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    if bump_recent(line):
                        yield line
        except Exception:
            # don't die: keep trying
            pass

        # move cursor forward (small overlap)
        since = (datetime.now() - timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")
        time.sleep(poll_s)
