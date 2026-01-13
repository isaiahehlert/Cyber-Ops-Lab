from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from minisoc.common.schema import NormalizedEvent
from minisoc.server.storage.sqlite import SQLiteStorage


def utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def create_app(db_path: Path, jsonl_dir: Path) -> FastAPI:
    log = logging.getLogger("minisoc.server")
    app = FastAPI(title="MiniSOC Server", version="0.1.0")
    store = SQLiteStorage(db_path)
    store.init()

    jsonl_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = jsonl_dir / "events.jsonl"

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "ts": utc_now_rfc3339()}

    @app.post("/ingest")
    def ingest(payload: dict) -> dict:
        try:
            ev = NormalizedEvent.model_validate(payload)
        except ValidationError as ve:
            raise HTTPException(status_code=400, detail=ve.errors())

        store.insert_events([ev])

        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(ev.model_dump_json() + "\n")

        log.info("ingested event_id=%s type=%s action=%s", ev.event_id, ev.event.type, ev.event.action)
        return {"ok": True, "event_id": str(ev.event_id)}

    @app.get("/events/recent")
    def recent(limit: int = 50) -> dict:
        return {"events": store.recent_events(limit=limit)}

    return app
