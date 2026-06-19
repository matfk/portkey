from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from server.config import Config

logger = logging.getLogger("portkey")


def setup_logging(config: Config) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    level = getattr(logging, config.logging.level.upper(), logging.INFO)
    fmt = logging.Formatter(fmt=config.logging.format, datefmt=config.logging.datefmt)

    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        logs_path = config.server.logs
        logs_path.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            logs_path / "portkeyd.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Cannot open log file: %s", exc)

    logger.info("Logging initialized (level=%s, logs=%s)", config.logging.level, config.server.logs)
