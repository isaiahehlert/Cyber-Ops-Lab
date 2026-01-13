from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


class LoggingCfg(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    dir: Path = Path("./var/log")
    max_bytes: int = 5_000_000
    backups: int = 3


class ServerCfg(BaseModel):
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080
    db_path: Path = Path("./var/minisoc.db")
    jsonl_dir: Path = Path("./var/jsonl")


class AgentCfg(BaseModel):
    host_name: str = "localhost"
    tail_paths: list[Path] = Field(
        default_factory=lambda: [Path("/var/log/auth.log"), Path("/var/log/syslog")]
    )
    server_url: str = "http://127.0.0.1:8080"
    poll_interval_s: float = 0.5


class AppCfg(BaseModel):
    logging: LoggingCfg = Field(default_factory=LoggingCfg)
    server: ServerCfg = Field(default_factory=ServerCfg)
    agent: AgentCfg = Field(default_factory=AgentCfg)


def load_config(path: Path) -> AppCfg:
    data: dict[str, Any] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text()) or {}
    return AppCfg.model_validate(data)
