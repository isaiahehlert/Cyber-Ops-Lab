from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import httpx

log = logging.getLogger("minisoc.replay")


@dataclass(frozen=True)
class ReplayStats:
    sent: int
    failed: int


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {line_no} in {path}: {e}") from e


def replay_scenario(
    server_url: str,
    scenario_path: Path,
    delay_s: float = 0.05,
    timeout_s: float = 5.0,
) -> ReplayStats:
    ingest_url = server_url.rstrip("/") + "/ingest"
    sent = 0
    failed = 0

    log.info("replay: server=%s scenario=%s delay_s=%.3f", server_url, scenario_path, delay_s)

    with httpx.Client(timeout=timeout_s) as client:
        for payload in iter_jsonl(scenario_path):
            sent += 1
            try:
                r = client.post(ingest_url, json=payload)
                if r.status_code >= 400:
                    failed += 1
                    log.error("ingest failed status=%s body=%s", r.status_code, r.text[:500])
            except Exception as e:
                failed += 1
                log.exception("ingest exception: %s", e)

            if delay_s > 0:
                time.sleep(delay_s)

    log.info("replay done: sent=%d failed=%d", sent, failed)
    return ReplayStats(sent=sent, failed=failed)
