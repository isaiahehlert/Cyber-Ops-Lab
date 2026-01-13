from __future__ import annotations

import logging
from pathlib import Path

import typer
import uvicorn

from minisoc.common.config import load_config
from minisoc.common.log import setup_logging
from minisoc.replay import replay_scenario
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


@app.command()
def alerts(
    config: Path = typer.Option(Path("configs/server.example.yaml"), "--config", "-c"),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    from minisoc.server.storage.sqlite import SQLiteStorage

    cfg = load_config(config)
    setup_logging(cfg.logging, name="minisoc-tool")
    store = SQLiteStorage(cfg.server.db_path)
    store.init()

    for a in store.recent_alerts(limit=limit):
        print(
            f'{a["ts"]} {a["rule_id"]} sev={a["severity"]} {a["entity"]} :: {a["title"]} '
            f'(events={len(a["event_ids"])})'
        )


@app.command()
def replay(
    scenario: Path = typer.Option(
        Path("data/replay_scenarios/01_ssh_bruteforce.jsonl"),
        "--scenario",
        "-s",
        help="Path to a JSONL scenario file (one event JSON per line).",
    ),
    config: Path = typer.Option(Path("configs/agent.example.yaml"), "--config", "-c"),
    delay_s: float = typer.Option(0.02, "--delay-s", help="Delay between events (seconds)."),
) -> None:
    cfg = load_config(config)
    setup_logging(cfg.logging, name="minisoc-replay")

    stats = replay_scenario(
        server_url=cfg.agent.server_url,
        scenario_path=scenario,
        delay_s=delay_s,
    )
    print(f"replay: sent={stats.sent} failed={stats.failed}")


if __name__ == "__main__":
    app()
