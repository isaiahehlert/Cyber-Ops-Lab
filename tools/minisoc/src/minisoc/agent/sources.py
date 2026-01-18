from __future__ import annotations
import logging

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
    try:
        r = subprocess.run(
            ["journalctl", "-n", "0", "--show-cursor", "--no-pager"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
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
    GUARANTEED journald reader using cursors (no `journalctl -f`, no `--since`).
    - Keeps a journal cursor and requests entries after it.
    - Avoids buffering/locale/since-format issues entirely.
    """
    import re

    log = logging.getLogger("minisoc.agent.sources")
    cursor_re = re.compile(r"^-- cursor:\s*(.+)\s*$")

    def run_journalctl(extra: list[str]) -> tuple[list[str], str | None]:
        args = [
            "journalctl",
            "-o", "short",
            "-u", "ssh",
            "-u", "sshd",
            "--no-pager",
            "--show-cursor",
            *extra,
        ]
        out = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        ).stdout

        out_lines = out.splitlines()
        cur = None
        keep: list[str] = []
        for ln in out_lines:
            m = cursor_re.match(ln)
            if m:
                cur = m.group(1).strip()
            elif ln.strip():
                keep.append(ln.rstrip("\n"))
        return keep, cur

    cursor: str | None = None

    if not from_start:
        # establish "current" cursor without consuming entries
        _ignored, cur = run_journalctl(["-n", "0"])
        cursor = cur
        if cursor is None:
            # fallback: take cursor from last entry (discard it)
            _ignored, cursor = run_journalctl(["-n", "1"])
            if cursor is None:
                log.warning("journalctl cursor probe failed; proceeding without cursor (from_start behavior).")

    while True:
        extra: list[str] = []
        if cursor:
            extra += ["--after-cursor", cursor]

        new_lines, new_cursor = run_journalctl(extra)
        if new_cursor:
            cursor = new_cursor

        for ln in new_lines:
            yield ln

        time.sleep(poll_s)

