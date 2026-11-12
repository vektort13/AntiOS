from pathlib import Path

import pytest

from antios.config import (
    AppConfig,
    CleanupConfig,
    ProtectionConfig,
    UIConfig,
    UpdateConfig,
    load_config,
    render_default_config,
    save_config,
    write_default_config,
)


def test_missing_config_uses_defaults(tmp_path):
    config = load_config(tmp_path / "missing.toml")
    assert config == AppConfig()


def test_write_and_load_default_config(tmp_path):
    path = tmp_path / "antios.toml"
    created = write_default_config(path)
    assert created == path
    assert path.read_text(encoding="utf-8") == render_default_config()

    config = load_config(path)
    assert config.general.computer_name_prefix == "LAB"
    assert config.general.color == "auto"
    assert config.logging.level == "INFO"
    assert config.ui == UIConfig()
    assert config.ui.start_with_windows is True
    assert config.cleanup == CleanupConfig()
    assert config.protection == ProtectionConfig()
    assert config.updates == UpdateConfig()


def test_config_rejects_invalid_color(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text(
        '[general]\ncolor = "rainbow"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(path)


def test_config_rejects_long_prefix(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text(
        '[general]\ncomputer_name_prefix = "TOOLONG"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(path)

def test_config_rejects_empty_backup_path(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text(
        '[general]\nbackup_path = ""\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(path)



def test_save_and_load_ui_preferences(tmp_path):
    path = tmp_path / "antios.toml"
    config = AppConfig(
        ui=UIConfig(language="pl", theme="light"),
        cleanup=CleanupConfig(
            old_days=90,
            large_mb=250,
            duplicate_min_mb=2,
            remember_folder=True,
            last_path=r"C:\Users\Example\Downloads",
        ),
        protection=ProtectionConfig(resident_enabled=False),
        updates=UpdateConfig(auto_update=False),
    )

    save_config(config, path)
    loaded = load_config(path)

    assert loaded.ui.language == "pl"
    assert loaded.ui.theme == "light"
    assert loaded.ui.start_with_windows is True
    assert loaded.cleanup.old_days == 90
    assert loaded.cleanup.large_mb == 250
    assert loaded.cleanup.duplicate_min_mb == 2
    assert loaded.cleanup.remember_folder is True
    assert loaded.cleanup.last_path == r"C:\Users\Example\Downloads"
    assert loaded.protection.resident_enabled is False
    assert loaded.updates.auto_update is False


def test_config_rejects_invalid_theme(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text('[ui]\ntheme = "neon"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="ui.theme"):
        load_config(path)


def test_config_rejects_invalid_ui_language(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text('[ui]\nlanguage = "xx"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="ui.language"):
        load_config(path)


def test_config_rejects_nonpositive_cleanup_threshold(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text('[cleanup]\nold_days = 0\n', encoding="utf-8")

    with pytest.raises(ValueError, match="cleanup.old_days"):
        load_config(path)



def test_config_can_disable_dashboard_autostart(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text(
        '[ui]\nlanguage = "ru"\ntheme = "dark"\nstart_with_windows = false\n',
        encoding="utf-8",
    )

    loaded = load_config(path)

    assert loaded.ui.language == "ru"
    assert loaded.ui.theme == "dark"
    assert loaded.ui.start_with_windows is False


def test_rendered_config_persists_dashboard_autostart(tmp_path):
    path = tmp_path / "antios.toml"
    config = AppConfig(ui=UIConfig(start_with_windows=False))

    save_config(config, path)
    text = path.read_text(encoding="utf-8")

    assert "start_with_windows = false" in text
    assert load_config(path).ui.start_with_windows is False
