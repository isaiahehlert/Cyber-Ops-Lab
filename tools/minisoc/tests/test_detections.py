from __future__ import annotations

import json
from pathlib import Path

from minisoc.common.schema import NormalizedEvent
from minisoc.server.detect.engine import DetectionEngine


def load_events(path: Path) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        payload = json.loads(line)
        events.append(NormalizedEvent.model_validate(payload))
    return events


def run_engine(events: list[NormalizedEvent]) -> list[str]:
    eng = DetectionEngine()
    fired: list[str] = []
    for ev in events:
        for det in eng.process(ev):
            fired.append(det.rule_id)
    return fired


def test_auth001_bruteforce_fires() -> None:
    events = load_events(Path("data/replay_scenarios/01_ssh_bruteforce.jsonl"))
    fired = run_engine(events)
    assert "AUTH001" in fired


def test_auth002_password_spray_fires() -> None:
    events = load_events(Path("data/replay_scenarios/02_password_spray.jsonl"))
    fired = run_engine(events)
    assert "AUTH002" in fired


def test_auth003_new_ip_for_user_fires() -> None:
    events = load_events(Path("data/replay_scenarios/03_new_ip_for_user.jsonl"))
    fired = run_engine(events)
    assert "AUTH003" in fired


def test_auth004_off_hours_fires() -> None:
    events = load_events(Path("data/replay_scenarios/04_off_hours_login.jsonl"))
    fired = run_engine(events)
    assert "AUTH004" in fired


def test_auth005_impossible_travel_fires() -> None:
    events = load_events(Path("data/replay_scenarios/05_impossible_travel.jsonl"))
    fired = run_engine(events)
    assert "AUTH005" in fired
