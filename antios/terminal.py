from __future__ import annotations

import os
import sys
from typing import TextIO


RESET = "\x1b[0m"
COLORS = {
    "ok": "\x1b[32m",
    "info": "\x1b[36m",
    "advisory": "\x1b[33m",
    "warn": "\x1b[31m",
    "heading": "\x1b[1m",
    "dim": "\x1b[2m",
}


def color_enabled(
    stream: TextIO | None = None,
    mode: str = "auto",
) -> bool:
    mode = mode.lower()
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    if mode == "always":
        return True

    stream = stream or sys.stdout
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def paint(text: str, role: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS.get(role, '')}{text}{RESET}"
