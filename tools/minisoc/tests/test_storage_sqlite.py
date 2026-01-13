from __future__ import annotations

from pathlib import Path

from minisoc.common.schema import Host, Source, EventCore, Raw, NormalizedEvent
from minisoc.server.storage.sqlite import SQLiteStorage


def test_sqlite_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    s = SQLiteStorage(db)
    s.init()

    ev = NormalizedEvent(
        ts="2026-01-12T00:00:00Z",
        host=Host(name="test-host", ip=None),
        source=Source(kind="auth", path="/var/log/auth.log"),
        event=EventCore(type="auth", action="ssh_login", outcome="failure", severity=4),
        message="SSH login failed",
        raw=Raw(line="Failed password for root from 1.2.3.4", parser="auth.sshd"),
        tags=["ssh", "auth"],
    )
    assert s.insert_events([ev]) == 1
    rec = s.recent_events(limit=5)
    assert len(rec) == 1
    assert rec[0]["message"] == "SSH login failed"
