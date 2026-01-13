from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal, Sequence


SourceKind = Literal["file", "journal"]


@dataclass(frozen=True)
class AutoSourceDecision:
    kind: SourceKind
    reason: str
    path: Path | None = None


DEFAULT_AUTH_PATH_CANDIDATES: tuple[Path, ...] = (
    Path("/var/log/auth.log"),     # Debian/Ubuntu/RPi OS (often)
    Path("/var/log/secure"),       # RHEL/CentOS/Fedora
    Path("/var/log/messages"),     # some syslog setups
)


def pick_auth_source(
    *,
    preferred_path: Path | None = None,
    candidates: Sequence[Path] = DEFAULT_AUTH_PATH_CANDIDATES,
) -> AutoSourceDecision:
    if preferred_path and preferred_path.exists():
        return AutoSourceDecision(kind="file", reason=f"preferred path exists: {preferred_path}", path=preferred_path)

    for p in candidates:
        if p.exists():
            return AutoSourceDecision(kind="file", reason=f"found log file: {p}", path=p)

    if _has_journalctl():
        return AutoSourceDecision(kind="journal", reason="no auth files found; journalctl available", path=None)

    return AutoSourceDecision(
        kind="file",
        reason="no auth files found and journalctl missing; using preferred/default",
        path=preferred_path or candidates[0],
    )


def _has_journalctl() -> bool:
    try:
        r = subprocess.run(["journalctl", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def follow_file(path: Path, *, from_start: bool, sleep_s: float = 0.2) -> Iterator[str]:
    """
    Tail -f a file without external deps, rotation-safe.
    Reopens file if inode changes (log rotation).
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    def _open():
        f = path.open("r", encoding="utf-8", errors="replace")
        st = os.fstat(f.fileno())
        inode = getattr(st, "st_ino", None)
        return f, inode

    f, inode = _open()
    try:
        if not from_start:
            f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
                continue

            # No new data; check rotation.
            try:
                st_now = path.stat()
                inode_now = getattr(st_now, "st_ino", None)
                if inode is not None and inode_now is not None and inode_now != inode:
                    f.close()
                    f, inode = _open()
                    if not from_start:
                        f.seek(0, 2)
            except FileNotFoundError:
                pass

            time.sleep(sleep_s)
    finally:
        try:
            f.close()
        except Exception:
            pass


def follow_journal_sshd(*, from_start: bool) -> Iterator[str]:
    """
    Follow sshd messages via journald using `journalctl -f`.
    """
    args = ["journalctl", "-o", "short-iso"]
    if not from_start:
        args += ["-n", "0"]
    args += ["-f", "_COMM=sshd"]

    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    assert proc.stdout is not None
    for raw in proc.stdout:
        s = raw.rstrip("\n")
        if s:
            yield s
