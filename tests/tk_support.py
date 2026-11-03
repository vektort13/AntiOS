"""Probe the same Tk initialization used by the app, without retaining an interpreter."""
from functools import lru_cache, wraps
import importlib.util
import os
import subprocess
import sys

from antios.windows_process import hidden_process_kwargs


@lru_cache(maxsize=1)
def native_tk_display_available():
    if importlib.util.find_spec("tkinter") is None:
        return False
    if os.name != "nt" and not os.environ.get("DISPLAY"):
        return False
    # Tcl's package loader may look for a DLL in a different directory from
    # _tkinter. Only a real Tk() window tests the application's startup path.
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import tkinter as tk; root = tk.Tk(); "
             "root.withdraw(); root.update_idletasks(); root.destroy()"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, **hidden_process_kwargs(),
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def isolated_tk_test(function):
    """Give each desktop scenario its own interpreter, like a real app launch.

    Some bundled Windows Tcl runtimes cannot reliably reinitialize Tk after
    destroy(). Run the entire pytest case (including fixtures) in a fresh
    process; failures are propagated, never converted into skips.
    """
    @wraps(function)
    def run(*args, **kwargs):
        node = os.environ["PYTEST_CURRENT_TEST"].rsplit(" (", 1)[0]
        if os.environ.get("ANTIOS_TK_TEST_NODE") == node:
            return function(*args, **kwargs)
        result = subprocess.run(
            [sys.executable, "-m", "pytest", node, "-ra", "-W", "error"],
            env=dict(os.environ, ANTIOS_TK_TEST_NODE=node),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=90,
            **hidden_process_kwargs(),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "1 passed" in result.stdout, result.stdout + result.stderr
    return run
