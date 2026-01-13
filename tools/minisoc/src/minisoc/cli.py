from __future__ import annotations

import logging
from pathlib import Path

import typer
import uvicorn

from minisoc.common.config import load_config
from minisoc.common.log import setup_logging
from minisoc.server.api import create_app

app = typer.Typer(help="MiniSOC: Pi-friendly Home SOC / Mini-SIEM")


@app.command()
def server(config: Path = typer.Option(Path("configs/server.example.yaml"), "--config", "-c")) -> None:
    cfg = load_config(config)
    setup_logging(cfg.logging, name="minisoc-server")
    log = logging.getLogger("minisoc.cli")

    api = create_app(cfg.server.db_path, cfg.server.jsonl_dir)
    log.info("starting server on %s:%d", cfg.server.bind_host, cfg.server.bind_port)
    uvicorn.run(api, host=cfg.server.bind_host, port=cfg.server.bind_port, log_level="info")


@app.command()
def query(
    config: Path = typer.Option(Path("configs/server.example.yaml"), "--config", "-c"),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    from minisoc.server.storage.sqlite import SQLiteStorage

    cfg = load_config(config)
    setup_logging(cfg.logging, name="minisoc-tool")
    store = SQLiteStorage(cfg.server.db_path)
    store.init()

    for ev in store.recent_events(limit=limit):
        print(
            f'{ev["ts"]} {ev["host"]["name"]} {ev["event"]["type"]}.{ev["event"]["action"]} '
            f'{ev["event"]["outcome"]} sev={ev["event"]["severity"]} :: {ev["message"]}'
        )


if __name__ == "__main__":
    app()
