from __future__ import annotations

import logging
import os
from pathlib import Path


LOGGER_NAME = "antios"


def _privileged_windows_context() -> bool:
    if os.name != "nt":
        return False
    try:
        from .elevation import is_administrator
        return is_administrator()
    except (OSError, AttributeError):
        # Failing closed is safer than appending from an elevated process to
        # a user-provided symlink / junction path.
        return True


def configure_logging(level: str = "INFO", file_path: str = "") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    for existing in logger.handlers[:]:
        logger.removeHandler(existing)
        existing.close()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    if file_path and not _privileged_windows_context():
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(target, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))
        logger.addHandler(handler)
    else:
        logger.addHandler(logging.NullHandler())

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
