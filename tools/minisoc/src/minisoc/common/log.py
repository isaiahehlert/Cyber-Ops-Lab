from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import LoggingCfg


def setup_logging(cfg: LoggingCfg, name: str) -> logging.Logger:
    cfg.dir.mkdir(parents=True, exist_ok=True)
    log_path = Path(cfg.dir) / f"{name}.log"

    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.level))

    fmt = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    fh = RotatingFileHandler(
        log_path,
        maxBytes=cfg.max_bytes,
        backupCount=cfg.backups,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    logging.getLogger("uvicorn").setLevel(logging.INFO)
    return logging.getLogger(name)
