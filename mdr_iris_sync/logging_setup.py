"""Logging setup: rotating file + console."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict


def setup_logging(cfg: Dict[str, Any]) -> logging.Logger:
    log_cfg = cfg.get("log", {})
    level_name = str(log_cfg.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    log_file = Path(log_cfg.get("file", "logs/mdr-iris-sync.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=int(log_cfg.get("max_mb", 10)) * 1024 * 1024,
        backupCount=int(log_cfg.get("backups", 5)),
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    # requests/urllib3 are chatty at DEBUG; keep them at WARNING.
    logging.getLogger("urllib3").setLevel(max(level, logging.WARNING))

    logger = logging.getLogger("mdr_iris_sync")
    logger.info("logging initialized: file=%s level=%s", log_file, level_name)
    return logger
