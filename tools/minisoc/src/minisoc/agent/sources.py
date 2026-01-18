from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
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
    # fast, cheap capability probe
    try:
        r = subprocess.run(
            ["journalctl","-f","-o","short","-u","ssh","-u","sshd","--no-pager"],
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
    # Resolve file target if any
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


def follow_journal_sshd(*, from_start: bool) -> Iterator[str]:
    """
    Follow sshd lines via journald.

    from_start=False: follow new messages
    from_start=True: replay available history (can be large on real boxes)
    """
    args = ["journalctl", "-f", "-o", "short"]
    if from_start:
        # no -f history-only mode would exit; we want history + follow
        args = ["journalctl", "-o", "short", "-f"]
    # Filter to sshd-ish lines. We avoid unit names because distro differs.
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert p.stdout is not None
    for line in p.stdout:
        if "sshd" in line:
            yield line.rstrip("\n")
