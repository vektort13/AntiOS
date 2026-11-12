from __future__ import annotations

import json
import os
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .i18n import SUPPORTED_LANGUAGES
from .storage_cleanup import (
    DEFAULT_DUPLICATE_MIN_BYTES,
    DEFAULT_LARGE_BYTES,
    DEFAULT_OLD_DAYS,
)


@dataclass(frozen=True)
class GeneralConfig:
    computer_name_prefix: str = "LAB"
    backup_path: str = "antios-backup.json"
    color: str = "auto"


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file: str = ""


@dataclass(frozen=True)
class UIConfig:
    language: str = "auto"
    theme: str = "system"
    start_with_windows: bool = True


@dataclass(frozen=True)
class CleanupConfig:
    old_days: int = DEFAULT_OLD_DAYS
    large_mb: int = DEFAULT_LARGE_BYTES // (1024 * 1024)
    duplicate_min_mb: int = DEFAULT_DUPLICATE_MIN_BYTES // (1024 * 1024)
    remember_folder: bool = True
    last_path: str = ""


@dataclass(frozen=True)
class ProtectionConfig:
    resident_enabled: bool = True


@dataclass(frozen=True)
class UpdateConfig:
    auto_update: bool = True


@dataclass(frozen=True)
class AppConfig:
    general: GeneralConfig = GeneralConfig()
    logging: LoggingConfig = LoggingConfig()
    ui: UIConfig = UIConfig()
    cleanup: CleanupConfig = CleanupConfig()
    protection: ProtectionConfig = ProtectionConfig()
    updates: UpdateConfig = UpdateConfig()

    def to_dict(self) -> dict[str, Any]:
        return {
            "general": asdict(self.general),
            "logging": asdict(self.logging),
            "ui": asdict(self.ui),
            "cleanup": asdict(self.cleanup),
            "protection": asdict(self.protection),
            "updates": asdict(self.updates),
        }


def default_config_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return root / "AntiOS" / "antios.toml"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg) if xdg else Path.home() / ".config"
    return root / "antios" / "antios.toml"


def _color(value: Any) -> str:
    color = str(value or "auto").lower()
    if color not in {"auto", "always", "never"}:
        raise ValueError("general.color must be one of: auto, always, never")
    return color


def _level(value: Any) -> str:
    level = str(value or "INFO").upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("logging.level must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
    return level


def _language(value: Any) -> str:
    language = str(value or "auto")
    if language == "auto":
        return language
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(
            "ui.language must be auto or one of: " + ", ".join(SUPPORTED_LANGUAGES)
        )
    return language


def _theme(value: Any) -> str:
    theme = str(value or "system").lower()
    if theme not in {"system", "dark", "light"}:
        raise ValueError("ui.theme must be one of: system, dark, light")
    return theme


def _positive_int(value: Any, *, name: str, default: int, minimum: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer") from None
    if parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return parsed


def load_config(path: str | Path | None = None) -> AppConfig:
    target = Path(path) if path else default_config_path()
    if not target.exists():
        return AppConfig()

    data = tomllib.loads(target.read_text(encoding="utf-8"))
    general = data.get("general") or {}
    logging_data = data.get("logging") or {}
    ui = data.get("ui") or {}
    cleanup = data.get("cleanup") or {}
    protection = data.get("protection") or {}
    updates = data.get("updates") or {}

    prefix = str(general.get("computer_name_prefix", "LAB")).strip() or "LAB"
    if len(prefix) > 6:
        raise ValueError("general.computer_name_prefix must be 6 characters or fewer")

    backup_path = str(general.get("backup_path", "antios-backup.json")).strip()
    if not backup_path:
        raise ValueError("general.backup_path must not be empty")

    return AppConfig(
        general=GeneralConfig(
            computer_name_prefix=prefix,
            backup_path=backup_path,
            color=_color(general.get("color", "auto")),
        ),
        logging=LoggingConfig(
            level=_level(logging_data.get("level", "INFO")),
            file=str(logging_data.get("file", "")),
        ),
        ui=UIConfig(
            language=_language(ui.get("language", "auto")),
            theme=_theme(ui.get("theme", "system")),
            start_with_windows=bool(ui.get("start_with_windows", True)),
        ),
        cleanup=CleanupConfig(
            old_days=_positive_int(
                cleanup.get("old_days", DEFAULT_OLD_DAYS),
                name="cleanup.old_days",
                default=DEFAULT_OLD_DAYS,
            ),
            large_mb=_positive_int(
                cleanup.get("large_mb", DEFAULT_LARGE_BYTES // (1024 * 1024)),
                name="cleanup.large_mb",
                default=DEFAULT_LARGE_BYTES // (1024 * 1024),
            ),
            duplicate_min_mb=_positive_int(
                cleanup.get(
                    "duplicate_min_mb",
                    DEFAULT_DUPLICATE_MIN_BYTES // (1024 * 1024),
                ),
                name="cleanup.duplicate_min_mb",
                default=DEFAULT_DUPLICATE_MIN_BYTES // (1024 * 1024),
            ),
            remember_folder=bool(cleanup.get("remember_folder", True)),
            last_path=str(cleanup.get("last_path", "")),
        ),
        protection=ProtectionConfig(
            resident_enabled=bool(protection.get("resident_enabled", True)),
        ),
        updates=UpdateConfig(
            auto_update=bool(updates.get("auto_update", True)),
        ),
    )


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_config(config: AppConfig) -> str:
    return f"""# AntiOS v2 configuration
[general]
computer_name_prefix = {_toml_string(config.general.computer_name_prefix)}
backup_path = {_toml_string(config.general.backup_path)}
color = {_toml_string(config.general.color)} # auto | always | never

[logging]
level = {_toml_string(config.logging.level)}
file = {_toml_string(config.logging.file)} # empty disables file logging

[ui]
language = {_toml_string(config.ui.language)} # auto | en | ru | es | zh-CN | fi | pl | mn
theme = {_toml_string(config.ui.theme)} # system | dark | light
start_with_windows = {str(config.ui.start_with_windows).lower()}

[cleanup]
old_days = {config.cleanup.old_days}
large_mb = {config.cleanup.large_mb}
duplicate_min_mb = {config.cleanup.duplicate_min_mb}
remember_folder = {str(config.cleanup.remember_folder).lower()}
last_path = {_toml_string(config.cleanup.last_path)}

[protection]
resident_enabled = {str(config.protection.resident_enabled).lower()}

[updates]
auto_update = {str(config.updates.auto_update).lower()}
"""


def render_default_config() -> str:
    return render_config(AppConfig())


def save_config(
    config: AppConfig,
    path: str | Path | None = None,
) -> Path:
    target = Path(path) if path else default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(render_config(config), encoding="utf-8")
    temp.replace(target)
    return target


def write_default_config(
    path: str | Path | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    target = Path(path) if path else default_config_path()
    if target.exists() and not overwrite:
        raise FileExistsError(f"Configuration already exists: {target}")
    return save_config(AppConfig(), target)
