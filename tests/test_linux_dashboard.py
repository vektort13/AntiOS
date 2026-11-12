import builtins
import os
import sys

import pytest

from antios import dashboard, linux_dashboard


def test_import_self_test_checks_the_real_linux_tk_dependency(monkeypatch):
    original_import = builtins.__import__
    def import_without_tk(name, *args, **kwargs):
        if name == "tkinter":
            raise ImportError("GLIBC compatibility fixture")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", import_without_tk)
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(RuntimeError, match="compatible Tcl/Tk.*GLIBC compatibility fixture"):
        dashboard.main(["--self-test"])


@pytest.mark.skipif(not sys.platform.startswith("linux") or not os.environ.get("DISPLAY"),
                    reason="Linux Tk display required")
def test_linux_ui_self_test_builds_the_window_without_starting_work(monkeypatch):
    def unexpected_work():
        raise AssertionError("UI self-test must not start diagnostics")
    monkeypatch.setattr(linux_dashboard, "collect_linux_health", unexpected_work)
    assert dashboard.main(["--ui-self-test"]) == 0
