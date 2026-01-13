from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI

from minisoc.common.schema import NormalizedEvent
from minisoc.server.detect.engine import DetectionEngine
from minisoc.server.storage.sqlite import SQLiteStorage


def utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def create_app(db_path: Path, jsonl_dir: Path) -> FastAPI:
    log = logging.getLogger("minisoc.server")
    app = FastAPI(title="MiniSOC Server", version="0.1.0")
    store = SQLiteStorage(db_path)
    store.init()
    engine = DetectionEngine()

    jsonl_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = jsonl_dir / "events.jsonl"

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "ts": utc_now_rfc3339()}

    @app.post("/ingest")
    def ingest(ev: NormalizedEvent) -> dict:
        store.insert_events([ev])

        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(ev.model_dump_json(by_alias=True) + "\n")

        # detect + alert
        alert_count = 0
        for det in engine.process(ev):
            store.insert_alert(engine.to_alert(det, ts=ev.ts))
            alert_count += 1

        log.info(
            "ingested event_id=%s type=%s action=%s alerts=%d",
            ev.event_id,
            ev.event.type,
            ev.event.action,
            alert_count,
        )
        return {"ok": True, "event_id": str(ev.event_id), "alerts": alert_count}

    @app.get("/events/recent")
    def recent(limit: int = 50) -> dict:
        return {"events": store.recent_events(limit=limit)}

    @app.get("/alerts/recent")
    def recent_alerts(limit: int = 50) -> dict:
        return {"alerts": store.recent_alerts(limit=limit)}

    return app
