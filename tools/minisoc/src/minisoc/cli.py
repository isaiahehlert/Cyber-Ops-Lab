from __future__ import annotations

import logging
from pathlib import Path

import typer
import uvicorn
import httpx

from minisoc.common.config import load_config
from minisoc.common.log import setup_logging
from minisoc.replay import replay_scenario
from minisoc.agent.tail_auth import run_tail_auth
from minisoc.agent.sources import pick_auth_source
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



@app.command("agent-tail-auth")
def agent_tail_auth(
    config: Path = typer.Option(Path("configs/agent.example.yaml"), "--config", "-c"),
    log_path: str = typer.Option("auto", "--log-path", help="Path to auth log file, or 'auto'"),
    host: str = typer.Option("lab-host", "--host"),
    host_ip: str | None = typer.Option(None, "--host-ip"),
    mode: str = typer.Option("live", "--mode", help="live (tail) or replay (read from-start/testing)"),
    from_start: bool = typer.Option(False, "--from-start", help="For live mode: start reading at beginning (lab/testing)"),
    source: str = typer.Option("auto", "--source", help="auto|file|journal"),
    heartbeat_s: float = typer.Option(30.0, "--heartbeat-s", help="Seconds between heartbeat logs (0 disables)"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    cfg = load_config(config)
    setup_logging(cfg.logging, name="minisoc-agent")

    lp = Path("/var/log/auth.log") if log_path.strip().lower() == "auto" else Path(log_path)

    stats = run_tail_auth(
        server_url=cfg.agent.server_url,
        log_path=lp,
        host=host,
        host_ip=host_ip,
        dry_run=dry_run,
        mode=mode,  # type: ignore[arg-type]
        from_start_live=from_start,
        source=source,  # type: ignore[arg-type]
        heartbeat_s=(None if heartbeat_s <= 0 else heartbeat_s),
    )
    print(f"agent: mode={mode} read={stats.read} parsed={stats.parsed} sent={stats.sent} failed={stats.failed}")



@app.command()
def doctor(
    log_path: Path = typer.Option(Path("/var/log/auth.log"), "--log-path"),
) -> None:
    decision = pick_auth_source(preferred_path=log_path)
    print("MiniSOC doctor")
    print(f"  preferred log path: {log_path}")
    print(f"  auto decision:      {decision.kind} ({decision.reason})")
    if decision.path:
        print(f"  chosen file path:   {decision.path}")
        print(f"  exists:             {decision.path.exists()}")
        try:
            with decision.path.open("r", encoding="utf-8", errors="replace") as f:
                _ = f.readline()
            print("  readable:           yes")
        except Exception as e:
            print(f"  readable:           no ({type(e).__name__}: {e})")
    else:
        print("  journald:           enabled (journalctl)")
        print("  tip: journald may require sudo or systemd-journal group")



@app.command("agent-tail-auth")
def agent_tail_auth(
    config: Path = typer.Option(Path("configs/agent.example.yaml"), "--config", "-c"),
    log_path: str = typer.Option("auto", "--log-path", help="Path to auth log file, or 'auto'"),
    host: str = typer.Option("lab-host", "--host"),
    host_ip: str | None = typer.Option(None, "--host-ip"),
    mode: str = typer.Option("live", "--mode", help="live (tail) or replay (read from-start/testing)"),
    from_start: bool = typer.Option(False, "--from-start", help="For live mode: start reading at beginning (lab/testing)"),
    source: str = typer.Option("auto", "--source", help="auto|file|journal"),
    heartbeat_s: float = typer.Option(30.0, "--heartbeat-s", help="Seconds between heartbeat logs (0 disables)"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    cfg = load_config(config)
    setup_logging(cfg.logging, name="minisoc-agent")

    lp = Path("/var/log/auth.log") if log_path.strip().lower() == "auto" else Path(log_path)

    stats = run_tail_auth(
        server_url=cfg.agent.server_url,
        log_path=lp,
        host=host,
        host_ip=host_ip,
        dry_run=dry_run,
        mode=mode,  # type: ignore[arg-type]
        from_start_live=from_start,
        source=source,  # type: ignore[arg-type]
        heartbeat_s=(None if heartbeat_s <= 0 else heartbeat_s),
    )
    print(f"agent: mode={mode} read={stats.read} parsed={stats.parsed} sent={stats.sent} failed={stats.failed}")



@app.command()
def doctor(config: Path = typer.Option(Path("configs/agent.example.yaml"), "--config", "-c")) -> None:
    """
    Quick sanity checks for live deployment.
    """
    cfg = load_config(config)
    print("=== minisoc doctor ===")
    print(f"server_url: {cfg.agent.server_url}")

    # Server health check
    try:
        r = httpx.get(f"{cfg.agent.server_url.rstrip('/')}/health", timeout=2.0)
        print(f"server /health: {r.status_code} {r.text.strip()[:200]}")
    except Exception as e:
        print(f"server /health: FAILED ({type(e).__name__}: {e})")

    # Auth source decision
    decision = pick_auth_source(None, prefer="auto")
    print(f"auth source decision: kind={decision.kind} reason={decision.reason} path={decision.path}")

    # Candidate file checks (informational)
    from minisoc.agent.sources import DEFAULT_AUTH_PATH_CANDIDATES
    import os, shutil
    for c in DEFAULT_AUTH_PATH_CANDIDATES:
        readable = c.exists() and c.is_file() and os.access(c, os.R_OK)
        print(f"candidate: {c} exists={c.exists()} readable={readable}")

    print(f"journalctl available: {shutil.which('journalctl') is not None}")
    print("=== end ===")


if __name__ == "__main__":
    app()
