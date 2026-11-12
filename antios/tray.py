"""AntiOS Windows tray lifecycle and protection-state icon policy."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any, Callable

from .windows_process import hidden_process_kwargs


PRESENCE_TTL_SECONDS = 15.0


def icon_asset(name: str) -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        path = base / "antios" / "assets" / "icons" / name
    else:
        path = Path(__file__).resolve().parent / "assets" / "icons" / name
    if not path.is_file():
        raise FileNotFoundError(f"AntiOS icon asset is missing: {path}")
    return path


def tray_variant(state: str | None) -> str:
    """Green only while Resident Guard is genuinely protecting."""
    return "ok" if state in {"monitoring", "scanning"} else "alert"


def application_icon_asset(state: str | None) -> Path:
    """Green main icon for healthy state, red taskbar icon for alert state."""
    name = "app_main.png" if tray_variant(state) == "ok" else "app_taskbar.png"
    return icon_asset(name)


def protection_title(state: str | None) -> str:
    if state in {"monitoring", "scanning"}:
        return "AntiOS — protection active"
    if state == "attention":
        return "AntiOS — threat requires attention"
    if state == "degraded":
        return "AntiOS — protection degraded"
    if state in {"failed", "unresponsive"}:
        return "AntiOS — protection failed"
    if state in {"stopped", "not-running"}:
        return "AntiOS — protection is not running"
    return "AntiOS — protection starting"


def _presence_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return root / "AntiOS" / "dashboard-tray.json"
    return Path.home() / ".cache" / "antios" / "dashboard-tray.json"


def mark_dashboard_presence() -> None:
    """Publish a short-lived heartbeat so Guard does not show a duplicate icon."""
    path = _presence_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"pid": os.getpid(), "heartbeat": time.time()}
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload), encoding="utf-8")
    temp.replace(path)


def clear_dashboard_presence() -> None:
    try:
        _presence_path().unlink(missing_ok=True)
    except OSError:
        pass


def dashboard_presence_active(*, now: float | None = None) -> bool:
    path = _presence_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        heartbeat = float(data.get("heartbeat", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False
    current = time.time() if now is None else now
    return 0 <= current - heartbeat <= PRESENCE_TTL_SECONDS


def _tray_image(variant: str):
    from PIL import Image

    with Image.open(icon_asset(f"tray_{variant}.png")) as image:
        return image.convert("RGBA")


def launch_dashboard() -> bool:
    """Open the installed GUI without creating a console window."""
    if os.name != "nt":
        return False
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).resolve().parent / "AntiOS-GUI.exe"
        if not executable.is_file():
            return False
        command = [str(executable)]
    else:
        command = [sys.executable, "-m", "antios.dashboard"]
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            **hidden_process_kwargs(),
        )
    except OSError:
        return False
    return True


class DashboardTray:
    """Tray icon owned by the dashboard process.

    Closing the window hides it; this icon is the explicit path back into the
    same process. Guard suppresses its own icon while this heartbeat is alive.
    """

    def __init__(
        self,
        *,
        show: Callable[[], None],
        exit_app: Callable[[], None],
    ) -> None:
        self._show = show
        self._exit_app = exit_app
        self._icon: Any | None = None
        self._thread: threading.Thread | None = None
        self._state = "not-running"
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._icon is not None

    def start(self, state: str = "not-running") -> bool:
        if os.name != "nt":
            return False
        try:
            import pystray
        except Exception:
            return False

        with self._lock:
            if self._icon is not None:
                self.set_state(state)
                return True
            self._state = str(state or "not-running")
            menu = pystray.Menu(
                pystray.MenuItem(
                    "Open AntiOS",
                    lambda _icon, _item: self._show(),
                    default=True,
                ),
                pystray.MenuItem(
                    "Exit AntiOS",
                    lambda _icon, _item: self._exit_app(),
                ),
            )
            icon = pystray.Icon(
                "AntiOS",
                _tray_image(tray_variant(self._state)),
                protection_title(self._state),
                menu,
            )
            self._icon = icon

            def runner() -> None:
                try:
                    icon.run()
                except Exception:
                    pass

            self._thread = threading.Thread(
                target=runner,
                name="AntiOSDashboardTray",
                daemon=True,
            )
            self._thread.start()
            return True

    def set_state(self, status: dict[str, Any] | str) -> None:
        state = status.get("state") if isinstance(status, dict) else status
        state = str(state or "not-running")
        with self._lock:
            self._state = state
            icon = self._icon
            if icon is None:
                return
            try:
                icon.icon = _tray_image(tray_variant(state))
                icon.title = protection_title(state)
            except Exception:
                pass

    def stop(self) -> None:
        with self._lock:
            icon, thread = self._icon, self._thread
            self._icon = None
            self._thread = None
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)


class GuardTray:
    """Resident Guard tray icon.

    The Guard owns the tray when no dashboard process is active. While the
    dashboard is alive, Guard deliberately suppresses this icon to avoid two
    AntiOS icons representing the same protection state.
    """

    def __init__(self) -> None:
        self._icon: Any | None = None
        self._icon_thread: threading.Thread | None = None
        self._monitor_thread: threading.Thread | None = None
        self._state: str = "starting"
        self._lock = threading.RLock()
        self._stop = threading.Event()

    def _create_icon(self) -> None:
        try:
            import pystray
        except Exception:
            return
        with self._lock:
            if self._icon is not None or self._stop.is_set():
                return
            state = self._state
            menu = pystray.Menu(
                pystray.MenuItem(
                    "Open AntiOS",
                    lambda _icon, _item: launch_dashboard(),
                    default=True,
                ),
            )
            icon = pystray.Icon(
                "AntiOSGuard",
                _tray_image(tray_variant(state)),
                protection_title(state),
                menu,
            )
            self._icon = icon

            def runner() -> None:
                try:
                    icon.run()
                except Exception:
                    pass

            self._icon_thread = threading.Thread(
                target=runner,
                name="AntiOSGuardTrayIcon",
                daemon=True,
            )
            self._icon_thread.start()

    def _hide_icon(self) -> None:
        with self._lock:
            icon, thread = self._icon, self._icon_thread
            self._icon = None
            self._icon_thread = None
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)

    def _monitor(self) -> None:
        while not self._stop.is_set():
            if dashboard_presence_active():
                self._hide_icon()
            else:
                self._create_icon()
            self._stop.wait(1.0)
        self._hide_icon()

    def start(self, state: str = "starting") -> None:
        if os.name != "nt":
            return
        with self._lock:
            self._state = str(state or "starting")
            if self._monitor_thread is not None and self._monitor_thread.is_alive():
                return
            self._stop.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitor,
                name="AntiOSGuardTrayMonitor",
                daemon=True,
            )
            self._monitor_thread.start()

    def set_state(self, status: dict[str, Any] | str) -> None:
        state = status.get("state") if isinstance(status, dict) else status
        state = str(state or "starting")
        with self._lock:
            self._state = state
            icon = self._icon
            if icon is None:
                return
            try:
                icon.icon = _tray_image(tray_variant(state))
                icon.title = protection_title(state)
            except Exception:
                pass

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            monitor = self._monitor_thread
            self._monitor_thread = None
        self._hide_icon()
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=2)
