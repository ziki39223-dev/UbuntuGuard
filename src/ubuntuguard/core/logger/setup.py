"""Structured logging setup (text or JSON lines)."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

LOGGER_NAME = "ubuntuguard"


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .astimezone()
            .isoformat(timespec="seconds")
        )
        message = record.getMessage()
        if record.exc_info:
            message = f"{message} | {self.formatException(record.exc_info)}"
        return (
            f'ts={timestamp} level={record.levelname.lower()} '
            f'mod={record.name} msg="{message}"'
        )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .astimezone()
            .isoformat(timespec="seconds"),
            "level": record.levelname.lower(),
            "module": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(
    level: str = "info",
    log_dir: str | Path | None = None,
    json_mode: bool = False,
) -> logging.Logger:
    """Configure the package logger. File logging is optional and best-effort."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level.upper())
    logger.propagate = False
    logger.handlers.clear()

    formatter: logging.Formatter = JsonFormatter() if json_mode else TextFormatter()

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_dir is not None:
        try:
            directory = Path(log_dir)
            directory.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(
                directory / "ubuntuguard.log", encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("file logging disabled (%s): %s", log_dir, exc)

    return logger
