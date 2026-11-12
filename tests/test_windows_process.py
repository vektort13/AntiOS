import os
from pathlib import Path
import subprocess

import pytest

from antios.windows_process import hidden_process_kwargs, system_executable


def test_non_windows_hidden_process_kwargs_are_empty():
    if os.name == "nt":
        pytest.skip("non-Windows contract")
    assert hidden_process_kwargs() == {}


@pytest.mark.skipif(os.name != "nt", reason="Windows console suppression contract")
def test_windows_helpers_use_no_console_and_hidden_startup():
    kwargs = hidden_process_kwargs()
    assert kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW
    startup = kwargs["startupinfo"]
    assert startup.dwFlags & subprocess.STARTF_USESHOWWINDOW
    assert startup.wShowWindow == subprocess.SW_HIDE


@pytest.mark.skipif(os.name != "nt", reason="Windows System32 path contract")
def test_system_executable_is_absolute_system32_path():
    path = Path(system_executable("WindowsPowerShell/v1.0/powershell.exe"))
    assert path.is_absolute()
    assert path.name.lower() == "powershell.exe"
    assert "system32" in str(path).lower()
