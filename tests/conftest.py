import os

import pytest


@pytest.fixture(autouse=True)
def isolate_app_data(tmp_path_factory, monkeypatch):
    """Give tests and their child processes a disposable AntiOS profile."""
    variables = ("LOCALAPPDATA", "APPDATA") if os.name == "nt" else (
        "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
    )
    profile = tmp_path_factory.mktemp("antios-profile")
    for name in variables:
        directory = profile / name.lower()
        directory.mkdir()
        monkeypatch.setenv(name, str(directory))
