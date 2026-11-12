from __future__ import annotations

import platform
from typing import Any

from . import __version__


def version_info() -> dict[str, Any]:
    return {
        "name": "AntiOS",
        "publisher": "DargonITP",
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def render_version() -> str:
    info = version_info()
    return f"{info['name']} {info['version']} (Python {info['python']})"
