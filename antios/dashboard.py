from __future__ import annotations

import argparse
import ctypes
import json
import os
import queue
import sys
import threading
import webbrowser
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .antivirus_ui import AntivirusPanel
from .diagnostics import classify_error, record_event
from .config import (
    AppConfig,
    CleanupConfig,
    UIConfig,
    default_config_path,
    load_config,
    save_config,
)
from .consumer import evaluate_health
from .core import scan
from .health import collect_health
from .i18n import LANGUAGE_NAMES, Translator, detect_language, normalize_language
from .registry import WindowsRegistryBackend, is_windows
from .storage_cleanup import (
    DEFAULT_OLD_DAYS,
    cleanup_files,
    default_cleanup_backup_path,
    default_scan_path,
    format_bytes,
    scan_storage,
)
from .storage_intelligence import (
    StorageJournal, candidate_categories, copy_evidence, insights_for_scan,
)
from .backup_proof import prove_cleanup_backup
from .tray import (
    DashboardTray,
    application_icon_asset,
    icon_asset,
    clear_dashboard_presence,
    mark_dashboard_presence,
)

PROJECT_URL = "https://github.com/Dargon777/AntiOS"
RELEASES_URL = PROJECT_URL + "/releases"
BUG_URL = PROJECT_URL + "/issues/new?template=bug_report.yml"
FEATURE_URL = PROJECT_URL + "/issues/new?template=feature_request.yml"
PRIVACY_URL = PROJECT_URL + "/blob/master/PRIVACY.md"
SUPPORT_URL = PROJECT_URL + "/blob/master/SUPPORT.md"

DARK_THEME = {
    "bg": "#08111B",
    "sidebar": "#0B1520",
    "surface": "#101C28",
    "surface_alt": "#152332",
    "surface_hover": "#1B2E3F",
    "surface_soft": "#0D1924",
    "border": "#233748",
    "border_soft": "#1B2B39",
    "text": "#F3F7FA",
    "muted": "#A0AFBC",
    "muted_2": "#718391",
    "accent": "#52E0A4",
    "accent_hover": "#6DEAB4",
    "accent_text": "#07140F",
    "accent_soft": "#103528",
    "cyan": "#49B8F2",
    "cyan_soft": "#102B3A",
    "ok": "#52E0A4",
    "ok_bg": "#103528",
    "review": "#F3B94E",
    "review_bg": "#382B12",
    "warn": "#F06472",
    "warn_bg": "#3A1820",
    "info": "#5AA8FF",
    "info_bg": "#142C49",
    "purple": "#A678F2",
}

LIGHT_THEME = {
    "bg": "#F4F7F9",
    "sidebar": "#F8FAFB",
    "surface": "#FFFFFF",
    "surface_alt": "#F0F4F6",
    "surface_hover": "#E7EEF2",
    "surface_soft": "#FAFBFC",
    "border": "#D7E0E6",
    "border_soft": "#E3E9ED",
    "text": "#10202D",
    "muted": "#556A79",
    "muted_2": "#7C8D99",
    "accent": "#0FAF78",
    "accent_hover": "#0C9969",
    "accent_text": "#FFFFFF",
    "accent_soft": "#E2F7EF",
    "cyan": "#287FBD",
    "cyan_soft": "#E8F3FA",
    "ok": "#0C9969",
    "ok_bg": "#E2F7EF",
    "review": "#9A6A0A",
    "review_bg": "#FFF3D7",
    "warn": "#C94655",
    "warn_bg": "#FDECEF",
    "info": "#2F73C7",
    "info_bg": "#EAF2FC",
    "purple": "#7952C8",
}

# UI geometry is based on an 8 px rhythm. Larger dimensions follow a
# phi-like progression (8, 13, 21, 34, 55) to keep hierarchy stable.
GRID = 8
PHI_SPACE = {
    "xs": 8,
    "sm": 13,
    "md": 21,
    "lg": 34,
    "xl": 55,
}
CARD_RADIUS = 16  # semantic token; Tk cards emulate radius through spacing/borders
SIDEBAR_WIDTH = 224
CONTENT_MAX = 1320

THEME = dict(DARK_THEME)
STATUS_STYLE: dict[str, tuple[str, str, str]] = {}


def _refresh_status_style() -> None:
    STATUS_STYLE.clear()
    STATUS_STYLE.update({
        "ok": ("OK", THEME["ok"], THEME["ok_bg"]),
        "advisory": ("REVIEW", THEME["review"], THEME["review_bg"]),
        "warn": ("WARNING", THEME["warn"], THEME["warn_bg"]),
        "info": ("INFO", THEME["info"], THEME["info_bg"]),
    })


def _system_theme() -> str:
    if os.name != "nt":
        return "dark"
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return "light" if int(value) else "dark"
    except Exception:
        return "dark"


def _apply_theme_palette(mode: str) -> str:
    resolved = _system_theme() if mode == "system" else mode
    palette = LIGHT_THEME if resolved == "light" else DARK_THEME
    THEME.clear()
    THEME.update(palette)
    _refresh_status_style()
    return resolved


_refresh_status_style()

def _open_url(url: str) -> None:
    webbrowser.open(url, new=2)


def collect_dashboard_data(language: str = "en") -> dict[str, Any]:
    tr = Translator(language)
    if not is_windows():
        raise RuntimeError(tr.t("error.dashboard_windows"))
    backend = WindowsRegistryBackend()
    scan_data = scan(backend)
    health_data = collect_health()
    evaluation = evaluate_health(
        scan_data,
        health_data,
        language=language,
    )
    return {
        "scan": scan_data,
        "health": health_data,
        "evaluation": evaluation,
    }


def _format_bytes(value: Any, tr: Translator | None = None) -> str:
    if not isinstance(value, (int, float)):
        return (tr or Translator("en")).t("value.unknown")
    gb = float(value) / (1024 ** 3)
    return f"{gb:.1f} GB"


def _friendly_bool(value: Any, tr: Translator | None = None) -> str:
    translator = tr or Translator("en")
    if value is True:
        return translator.t("value.on")
    if value is False:
        return translator.t("value.off")
    return translator.t("value.unknown")


def _open_settings(uri: str) -> None:
    if os.name != "nt":
        return
    os.startfile(uri)  # type: ignore[attr-defined]


def _configure_windows_identity() -> None:
    """Give unpackaged builds a stable taskbar identity.

    Packaged MSIX apps already receive their AppUserModelID from Windows and
    must not be regrouped under a synthetic desktop identity.
    """
    if os.name != "nt":
        return
    try:
        length = ctypes.c_uint32(0)
        result = ctypes.windll.kernel32.GetCurrentPackageFullName(
            ctypes.byref(length),
            None,
        )
        appmodel_error_no_package = 15700
        if result != appmodel_error_no_package:
            return
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            ctypes.c_wchar_p("DargonITP.AntiOS")
        )
    except Exception:
        pass


def _apply_window_icon(root: Any, state: str | None = None) -> None:
    """Green while protected; red only for attention/degraded/no protection."""
    try:
        image = root.tk.call(
            "image", "create", "photo",
            "-file", str(application_icon_asset(state)),
        )
        root.tk.call("wm", "iconphoto", root._w, "-default", image)
        root._antios_taskbar_icon = image
    except Exception:
        pass


def _enable_dark_titlebar(root: Any, dark: bool = True) -> None:
    """Ask modern Windows to render the native title bar to match the app."""
    if os.name != "nt":
        return
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1 if dark else 0)
        # DWMWA_USE_IMMERSIVE_DARK_MODE is 20 on modern Windows.
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            20,
            ctypes.byref(value),
            ctypes.sizeof(value),
        )
    except Exception:
        # Cosmetic only. The dashboard must still work if DWM rejects it.
        pass


class ScrollFrame:
    def __init__(self, parent: Any, tk: Any) -> None:
        self.tk = tk
        self.frame = tk.Frame(parent, bg=THEME["bg"])
        self.canvas = tk.Canvas(
            self.frame,
            bg=THEME["bg"],
            highlightthickness=0,
            bd=0,
        )
        self.scrollbar = tk.Scrollbar(
            self.frame,
            orient="vertical",
            command=self.canvas.yview,
            relief="flat",
            bd=0,
            width=10,
        )
        self.inner = tk.Frame(self.canvas, bg=THEME["bg"])
        self.window = self.canvas.create_window(
            (0, 0),
            window=self.inner,
            anchor="nw",
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.inner.bind(
            "<Configure>",
            lambda _event: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            ),
        )
        self.canvas.bind(
            "<Configure>",
            lambda event: self.canvas.itemconfigure(
                self.window,
                width=event.width,
            ),
        )

        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _event: Any) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_wheel(self, _event: Any) -> None:
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event: Any) -> None:
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


class Dashboard:
    def __init__(
        self,
        root: Any,
        *,
        language: str | None = None,
        auto_refresh: bool = True,
        tray_enabled: bool = True,
        background_services: bool = True,
    ) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.root = root
        self.tk = tk
        self.ttk = ttk
        self.config_path = default_config_path()
        try:
            self.config = load_config(self.config_path)
        except (OSError, ValueError):
            self.config = AppConfig()

        self.language_setting = (
            normalize_language(language)
            if language
            else self.config.ui.language
        )
        detected_language = detect_language()
        self.language = normalize_language(
            detected_language
            if self.language_setting == "auto"
            else self.language_setting
        )
        self.tr = Translator(self.language)

        self.theme_mode = self.config.ui.theme
        self.resolved_theme = _apply_theme_palette(self.theme_mode)

        self.data: dict[str, Any] | None = None
        self.pages: dict[str, Any] = {}
        self.nav_buttons: dict[str, Any] = {}
        self.active_page = "overview"
        self._check_rows: list[Any] = []

        configured_path = Path(self.config.cleanup.last_path).expanduser()
        self.storage_path = (
            configured_path
            if self.config.cleanup.remember_folder
            and self.config.cleanup.last_path
            and configured_path.is_dir()
            else default_scan_path()
        )
        self.storage_result: dict[str, Any] | None = None
        self._storage_cancel = threading.Event()
        self._storage_action_busy = False
        self.antivirus_path = default_scan_path()
        self.antivirus_signatures: Path | None = None
        self.antivirus_engine = "clamav"
        self.antivirus_result: dict[str, Any] | None = None
        self.antivirus_items: list[dict] = []
        self.antivirus_queue: queue.Queue = queue.Queue()
        self.antivirus_cancel = threading.Event()
        self.antivirus_busy = False
        self.antivirus_cancelable = False
        self.guard_probe_busy = False
        self._diagnostics_window = None
        self.update_busy = False
        self.update_payload: dict[str, Any] | None = None
        self._tray_enabled = tray_enabled
        self._dashboard_tray: DashboardTray | None = None
        self._tray_commands: queue.Queue[str] = queue.Queue()
        self._tray_poll_after: str | None = None
        self._presence_after: str | None = None
        self._exiting = False
        self._protection_state = "not-running"

        self._configure_root()
        self._configure_ttk()
        self._build_shell()
        self._build_pages()
        self.show_page("overview")
        self._initialize_tray()
        if background_services:
            self._start_background_services()
        if auto_refresh:
            self.refresh()

    def t(self, key: str, **values: Any) -> str:
        return self.tr.t(key, **values)

    def open_diagnostics(self) -> None:
        from .diagnostics_ui import open_diagnostics
        open_diagnostics(self, THEME)

    def _configure_root(self) -> None:
        root = self.root
        root.title(self.t("app.title"))
        root.geometry("1440x900")
        root.minsize(1180, 760)
        root.configure(bg=THEME["bg"])
        root.option_add("*Font", ("Segoe UI", 10))
        root.bind("<F5>", lambda _event: self.refresh())
        root.bind("<Control-e>", lambda _event: self.export_report())
        root.bind("<Control-E>", lambda _event: self.export_report())
        root.bind("<Control-1>", lambda _event: self.show_page("overview"))
        root.bind("<Control-2>", lambda _event: self.show_page("antivirus"))
        root.bind("<Control-3>", lambda _event: self.show_page("security"))
        root.bind("<Control-4>", lambda _event: self.show_page("system"))
        root.bind("<Control-5>", lambda _event: self.show_page("cleanup"))
        root.bind("<Control-comma>", lambda _event: self.show_page("settings"))
        root.bind("<Control-Shift-D>", lambda _event: self.open_diagnostics())
        root.bind("<Control-Shift-d>", lambda _event: self.open_diagnostics())
        root.protocol("WM_DELETE_WINDOW", self._close)
        _enable_dark_titlebar(root, self.resolved_theme == "dark")

    def _initialize_tray(self) -> None:
        if not self._tray_enabled or os.name != "nt":
            _apply_window_icon(self.root, self._protection_state)
            return
        tray = DashboardTray(
            show=lambda: self._tray_commands.put("show"),
            exit_app=lambda: self._tray_commands.put("exit"),
        )
        if not tray.start(self._protection_state):
            _apply_window_icon(self.root, self._protection_state)
            return
        self._dashboard_tray = tray
        mark_dashboard_presence()
        self._presence_after = self.root.after(5000, self._presence_heartbeat)
        self._tray_poll_after = self.root.after(150, self._poll_tray_commands)
        try:
            from .guard_state import read_guard_state
            self.set_protection_state(read_guard_state())
        except Exception:
            self.set_protection_state({"state": "not-running"})

    def _start_background_services(self) -> None:
        """Self-heal installed protection, reconcile UI startup and check updates."""
        packaged = (
            os.name == "nt"
            and Path(sys.executable).name.casefold() == "antios-gui.exe"
        )
        if not packaged:
            return
        threading.Thread(
            target=self._dashboard_startup_reconcile_worker,
            daemon=True,
            name="AntiOSDashboardStartup",
        ).start()
        if self.config.protection.resident_enabled:
            threading.Thread(
                target=self._resident_autostart_worker,
                daemon=True,
                name="AntiOSResidentAutostart",
            ).start()
        if self.config.updates.auto_update:
            self._start_update_worker(download=True, automatic=True)

    def _heal_managed_engine(self, *, interactive: bool = False) -> dict:
        from .protection import collect_protection_status
        from .protection_repair import run_protection_bootstrap, run_protection_repair

        status = collect_protection_status()
        caps = status.get("capabilities", {})
        if caps.get("standalone_detection_engine"):
            return {"action": "already-ready", "status": status}

        managed = status.get("managed_runtime", {})
        managed_files = managed.get("files", {}) if isinstance(managed, dict) else {}
        repairable = bool(managed_files) and all(bool(value) for value in managed_files.values())
        from .elevation import is_administrator, request_protection_elevation

        if not is_administrator():
            if interactive:
                action = "repair" if repairable else "bootstrap"
                completion = request_protection_elevation(action)
                # The elevated process has exited successfully. Verify that
                # the service and its malware database are actually ready.
                verified = collect_protection_status()
                if not verified.get("capabilities", {}).get("standalone_detection_engine"):
                    raise RuntimeError(
                        "Administrator maintenance finished, but ClamAV is not ready. "
                        "Inspect protection status and repair logs before enabling Guard."
                    )
                return {
                    "action": "repaired" if repairable else "bootstrapped",
                    "completion": completion,
                    "verified": True,
                    "status": verified,
                }
            # Background startup must never prompt for UAC or silently modify
            # machine-wide service/ACL/engine settings.
            return {"action": "requires-elevation"}
        if repairable:
            result = run_protection_repair(apply=True, update_signatures=True)
            return {"action": "repaired", "result": result}
        result = run_protection_bootstrap()
        return {"action": "bootstrapped", "result": result}

    def _resident_autostart_worker(self) -> None:
        try:
            from .resident import ensure_resident_guard

            engine = self._heal_managed_engine()
            if engine.get("action") == "requires-elevation":
                self.antivirus_queue.put((
                    "error",
                    "Resident engine needs administrator repair. Open Antivirus and choose Repair protection.",
                ))
                return
            value = ensure_resident_guard()
            self.antivirus_queue.put(("guard-action", value))
        except Exception as exc:
            self.antivirus_queue.put(("error", f"Resident protection startup failed: {exc}"))

    def repair_protection(self) -> dict:
        """Repair/bootstrap the managed engine and restore Resident Guard."""
        from .resident import ensure_resident_guard

        engine = self._heal_managed_engine(interactive=True)
        guard = ensure_resident_guard()
        return {"engine": engine, "guard": guard}

    def set_resident_protection_enabled(self, enabled: bool) -> dict:
        """Persist Guard preference without lying about a failed transition."""
        original = self.config
        self.config = replace(
            self.config,
            protection=replace(self.config.protection, resident_enabled=bool(enabled)),
        )
        self._persist_config()
        try:
            if enabled:
                from .resident import ensure_resident_guard
                engine = self._heal_managed_engine(interactive=True)
                guard = ensure_resident_guard()
                return {"enabled": True, "engine": engine, "guard": guard}
            from .resident import disable_resident_guard
            return disable_resident_guard()
        except Exception:
            # A denied UAC prompt or failed task registration must not leave an
            # enabled/disabled preference that was never successfully applied.
            self.config = original
            self._persist_config()
            raise

    def _dashboard_startup_reconcile_worker(self) -> None:
        try:
            from .dashboard_startup import reconcile_dashboard_startup
            payload = reconcile_dashboard_startup(
                self.config.ui.start_with_windows
            )
            error = None
        except Exception as exc:
            payload = None
            error = str(exc)[:1000]

        def complete() -> None:
            if not hasattr(self, "dashboard_startup_status"):
                return
            if error:
                self.dashboard_startup_status.configure(
                    text=(
                        "Ошибка автозапуска"
                        if self.language == "ru"
                        else "Startup error"
                    ),
                    fg=THEME["warn"],
                )
                return
            enabled = bool(payload and payload.get("enabled"))
            self.dashboard_startup_status.configure(
                text=(
                    "Включён" if enabled and self.language == "ru"
                    else "Enabled" if enabled
                    else "Выключен" if self.language == "ru"
                    else "Disabled"
                ),
                fg=THEME["ok"] if enabled else THEME["muted"],
            )

        try:
            self.root.after(0, complete)
        except Exception:
            pass

    def _save_dashboard_startup_preference(self) -> None:
        enabled = bool(self.start_with_windows_var.get())
        previous = self.config.ui.start_with_windows
        self.config = replace(
            self.config,
            ui=replace(self.config.ui, start_with_windows=enabled),
        )
        if not self._persist_config():
            self.config = replace(
                self.config,
                ui=replace(self.config.ui, start_with_windows=previous),
            )
            self.start_with_windows_var.set(previous)
            self.dashboard_startup_status.configure(
                text=(
                    "Не удалось сохранить"
                    if self.language == "ru"
                    else "Could not save"
                ),
                fg=THEME["warn"],
            )
            return

        self.start_with_windows_check.configure(state="disabled")
        self.dashboard_startup_status.configure(
            text="Применяем…" if self.language == "ru" else "Applying…",
            fg=THEME["muted"],
        )

        def worker() -> None:
            try:
                from .dashboard_startup import set_dashboard_startup
                payload = set_dashboard_startup(enabled)
                error = None
            except Exception as exc:
                payload = None
                error = str(exc)[:1000]

            def complete() -> None:
                self.start_with_windows_check.configure(state="normal")
                if error:
                    self.config = replace(
                        self.config,
                        ui=replace(
                            self.config.ui,
                            start_with_windows=previous,
                        ),
                    )
                    self._persist_config()
                    self.start_with_windows_var.set(previous)
                    self.dashboard_startup_status.configure(
                        text=(
                            "Не удалось применить"
                            if self.language == "ru"
                            else "Could not apply"
                        ),
                        fg=THEME["warn"],
                    )
                    return
                active = bool(payload and payload.get("enabled"))
                self.dashboard_startup_status.configure(
                    text=(
                        "Включён" if active and self.language == "ru"
                        else "Enabled" if active
                        else "Выключен" if self.language == "ru"
                        else "Disabled"
                    ),
                    fg=THEME["ok"] if active else THEME["muted"],
                )

            self.root.after(0, complete)

        threading.Thread(
            target=worker,
            daemon=True,
            name="AntiOSDashboardStartupSetting",
        ).start()

    def _save_update_preference(self) -> None:
        enabled = bool(self.update_auto_var.get()) if hasattr(self, "update_auto_var") else True
        self.config = replace(
            self.config,
            updates=replace(self.config.updates, auto_update=enabled),
        )
        self._persist_config()

    def _set_update_status(self, text: str, *, warning: bool = False) -> None:
        if hasattr(self, "update_status"):
            try:
                self.update_status.configure(
                    text=text,
                    fg=THEME["warn"] if warning else THEME["muted"],
                )
            except Exception:
                pass

    def _start_update_worker(self, *, download: bool, automatic: bool = False) -> None:
        if self.update_busy:
            return
        self.update_busy = True
        if hasattr(self, "install_update_button"):
            self.install_update_button.configure(state="disabled")
        if not automatic:
            self._set_update_status(self.t("settings.updates.checking"))

        def worker() -> None:
            try:
                from .updater import (
                    default_update_directory,
                    download_update,
                    latest_alpha,
                )
                payload = latest_alpha()
                if download and payload.get("update_available"):
                    target = default_update_directory(str(payload.get("tag") or "latest"))
                    payload = download_update(
                        target,
                        require_signature=False,
                        replace_existing=True,
                    )
                    # Auto-check/download is allowed; silent install is not.
                    # Installing requires explicit confirmation and closing the GUI.
                error = None
            except Exception as exc:
                payload = None
                error = str(exc)[:1000]

            def complete() -> None:
                self.update_busy = False
                if error:
                    self.update_payload = None
                    self._set_update_status(
                        self.t("settings.updates.failed", error=error),
                        warning=True,
                    )
                    return
                assert payload is not None
                self.update_payload = payload
                if hasattr(self, "install_update_button"):
                    self.install_update_button.configure(
                        state="normal" if payload.get("install_ready") else "disabled"
                    )
                if not payload.get("update_available"):
                    self._set_update_status(self.t("settings.updates.latest"))
                elif payload.get("downloaded") and payload.get("install_ready"):
                    self._set_update_status(
                        self.t("settings.updates.signed_ready", version=payload.get("latest_version"))
                    )
                elif payload.get("downloaded") and payload.get("install_ready"):
                    self._set_update_status(
                        self.t(
                            "settings.updates.downloaded",
                            version=payload.get("latest_version"),
                        )
                    )
                elif payload.get("downloaded"):
                    self._set_update_status(
                        self.t(
                            "settings.updates.unsigned",
                            version=payload.get("latest_version"),
                        ),
                        warning=True,
                    )
                else:
                    self._set_update_status(
                        self.t(
                            "settings.updates.available",
                            version=payload.get("latest_version"),
                        )
                    )

            try:
                self.root.after(0, complete)
            except Exception:
                pass

        threading.Thread(
            target=worker,
            daemon=True,
            name="AntiOSUpdateCheck",
        ).start()


    def _install_update_now(self) -> None:
        """Hand off a verified update only after explicit user confirmation."""
        from tkinter import messagebox
        from .updater import schedule_install

        payload = self.update_payload
        if self.update_busy or not isinstance(payload, dict) or not payload.get("install_ready"):
            self._set_update_status(self.t("settings.updates.unavailable"), warning=True)
            return
        if not messagebox.askyesno("AntiOS", self.t("settings.updates.confirm")):
            return
        try:
            schedule_install(payload["setup_path"], payload["sha256"])
        except (OSError, RuntimeError, ValueError) as exc:
            self._set_update_status(
                self.t("settings.updates.failed", error=str(exc)[:500]),
                warning=True,
            )
            return
        self._set_update_status(self.t("settings.updates.installing"))
        self._exit()

    def _open_update_folder(self) -> None:
        from .updater import default_update_directory
        target = None
        if isinstance(self.update_payload, dict):
            value = self.update_payload.get("download_directory")
            if value:
                target = Path(str(value))
        if target is None:
            target = default_update_directory()
        target.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]

    def _check_updates_now(self) -> None:
        self._start_update_worker(download=False, automatic=False)

    def _download_update_now(self) -> None:
        self._start_update_worker(download=True, automatic=False)

    def _presence_heartbeat(self) -> None:
        if self._exiting or self._dashboard_tray is None:
            return
        try:
            mark_dashboard_presence()
        finally:
            self._presence_after = self.root.after(5000, self._presence_heartbeat)

    def _poll_tray_commands(self) -> None:
        if self._exiting:
            return
        for _ in range(10):
            try:
                command = self._tray_commands.get_nowait()
            except queue.Empty:
                break
            if command == "show":
                self._show_window()
            elif command == "exit":
                self._exit()
                return
        self._tray_poll_after = self.root.after(150, self._poll_tray_commands)

    def _show_window(self) -> None:
        if self._exiting:
            return
        self.root.deiconify()
        try:
            self.root.state("normal")
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass


    def set_protection_state(self, status: dict[str, Any] | str) -> None:
        state = status.get("state") if isinstance(status, dict) else status
        state = str(state or "not-running")
        self._protection_state = state
        _apply_window_icon(self.root, state)
        if self._dashboard_tray is not None:
            self._dashboard_tray.set_state(state)

        if hasattr(self, "overview_guard_status"):
            healthy = state in {"monitoring", "scanning"}
            starting = state == "starting"
            if healthy:
                text = "Активен · мониторинг" if self.language == "ru" else "Active · monitoring"
                color = THEME["ok"]
            elif starting:
                text = "Запускается…" if self.language == "ru" else "Starting…"
                color = THEME["info"]
            else:
                text = "Не активен" if self.language == "ru" else "Not active"
                color = THEME["warn"]
            self.overview_guard_status.configure(text=text, fg=color)

    def _close(self) -> None:
        if self._dashboard_tray is not None and self._dashboard_tray.running:
            self.root.withdraw()
            return
        self._exit()

    def _exit(self) -> None:
        if self._exiting:
            return
        self._exiting = True
        self._storage_cancel.set()
        self.antivirus_cancel.set()
        for after_id in (self._tray_poll_after, self._presence_after):
            if after_id is not None:
                try:
                    self.root.after_cancel(after_id)
                except Exception:
                    pass
        if self._dashboard_tray is not None:
            self._dashboard_tray.stop()
            self._dashboard_tray = None
        clear_dashboard_presence()
        self.root.destroy()

    def _configure_ttk(self) -> None:
        style = self.ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "AntiOS.Treeview",
            background=THEME["surface"],
            fieldbackground=THEME["surface"],
            foreground=THEME["text"],
            borderwidth=0,
            relief="flat",
            rowheight=38,
            font=("Segoe UI", 10),
        )
        style.map(
            "AntiOS.Treeview",
            background=[("selected", THEME["surface_hover"])],
            foreground=[("selected", THEME["text"])],
        )
        style.configure(
            "AntiOS.Treeview.Heading",
            background=THEME["surface_alt"],
            foreground=THEME["muted"],
            borderwidth=0,
            relief="flat",
            padding=(12, 10),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "AntiOS.Treeview.Heading",
            background=[("active", THEME["surface_hover"])],
        )

        style.configure(
            "AntiOS.Horizontal.TProgressbar",
            troughcolor=THEME["surface_alt"],
            background=THEME["accent"],
            bordercolor=THEME["border"],
            lightcolor=THEME["accent"],
            darkcolor=THEME["accent"],
            thickness=6,
        )

        style.configure(
            "AntiOS.TCombobox",
            fieldbackground=THEME["surface_alt"],
            background=THEME["surface_alt"],
            foreground=THEME["text"],
            arrowcolor=THEME["muted"],
            bordercolor=THEME["border"],
            lightcolor=THEME["border"],
            darkcolor=THEME["border"],
            padding=(8, 6),
        )
        style.map(
            "AntiOS.TCombobox",
            fieldbackground=[("readonly", THEME["surface_alt"])],
            foreground=[("readonly", THEME["text"])],
            selectbackground=[("readonly", THEME["surface_alt"])],
            selectforeground=[("readonly", THEME["text"])],
        )


    def _build_shell(self) -> None:
        tk = self.tk
        self.nav_frames: dict[str, Any] = {}

        self.sidebar = tk.Frame(
            self.root,
            bg=THEME["sidebar"],
            width=SIDEBAR_WIDTH,
            highlightthickness=0,
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        brand.pack(fill="x", padx=PHI_SPACE["md"], pady=(PHI_SPACE["lg"], PHI_SPACE["lg"]))

        try:
            source = tk.PhotoImage(file=str(icon_asset("app_main.png")))
            self._sidebar_logo = source.subsample(5, 5)
            mark = tk.Label(brand, image=self._sidebar_logo, bg=THEME["sidebar"], bd=0)
        except Exception:
            mark = tk.Label(
                brand,
                text="A",
                width=3,
                bg=THEME["accent_soft"],
                fg=THEME["accent"],
                font=("Segoe UI", 16, "bold"),
                bd=0,
            )
        mark.pack(side="left")

        brand_text = tk.Frame(brand, bg=THEME["sidebar"])
        brand_text.pack(side="left", padx=(13, 0))
        tk.Label(
            brand_text,
            text="AntiOS",
            bg=THEME["sidebar"],
            fg=THEME["text"],
            font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            brand_text,
            text=self.t("brand.subtitle"),
            bg=THEME["sidebar"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(1, 0))

        nav = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        nav.pack(fill="x", padx=10)
        for key, icon, label in [
            ("overview", "⌂", self.t("nav.overview")),
            ("antivirus", "⌕", self.t("nav.antivirus")),
            ("security", "◇", self.t("nav.security")),
            ("startup", "◴", self.t("nav.startup")),
            ("system", "▣", self.t("nav.system")),
            ("cleanup", "↻", self.t("nav.cleanup")),
        ]:
            self._create_nav_button(key, f"{icon}   {label}", parent=nav)

        spacer = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        spacer.pack(fill="both", expand=True)

        divider = tk.Frame(self.sidebar, bg=THEME["border_soft"], height=1)
        divider.pack(fill="x", padx=PHI_SPACE["md"], pady=(0, 10))

        self.settings_button = self.tk.Button(
            self.sidebar,
            text=f"⚙   {self.t('nav.settings')}",
            command=lambda: self.show_page("settings"),
            anchor="w",
            padx=16,
            pady=12,
            bg=THEME["sidebar"],
            fg=THEME["muted"],
            activebackground=THEME["surface_hover"],
            activeforeground=THEME["text"],
            bd=0,
            relief="flat",
            cursor="hand2",
            takefocus=True,
            font=("Segoe UI Semibold", 10),
        )
        self.settings_button.pack(fill="x", padx=10, pady=(0, 6))

        bottom = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        bottom.pack(fill="x", padx=18, pady=(8, 18))
        self._text_link(bottom, self.t("sidebar.github"), lambda: _open_url(PROJECT_URL)).pack(anchor="w")
        self._text_link(bottom, self.t("sidebar.privacy"), lambda: _open_url(PRIVACY_URL)).pack(anchor="w", pady=(3, 0))

        self.content = tk.Frame(self.root, bg=THEME["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        self.header = tk.Frame(self.content, bg=THEME["bg"])
        self.header.pack(fill="x", padx=PHI_SPACE["lg"], pady=(PHI_SPACE["lg"], PHI_SPACE["md"]))

        title_block = tk.Frame(self.header, bg=THEME["bg"])
        title_block.pack(side="left", fill="both", expand=True)
        self.page_title = tk.Label(
            title_block,
            text=self.t("nav.overview"),
            bg=THEME["bg"],
            fg=THEME["text"],
            font=("Segoe UI", 26, "bold"),
        )
        self.page_title.pack(anchor="w")
        self.page_subtitle = tk.Label(
            title_block,
            text=self.t("page.overview.subtitle"),
            bg=THEME["bg"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
            justify="left",
        )
        self.page_subtitle.pack(anchor="w", pady=(4, 0))

        header_actions = tk.Frame(self.header, bg=THEME["bg"])
        header_actions.pack(side="right")
        self.header_actions = header_actions

        engine = tk.Frame(
            header_actions,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        engine.pack(side="left", padx=(0, 10))
        tk.Label(
            engine,
            text="◈",
            bg=THEME["surface_alt"],
            fg=THEME["info"],
            font=("Segoe UI", 12, "bold"),
            padx=10,
            pady=9,
        ).pack(side="left")
        engine_text = tk.Frame(engine, bg=THEME["surface"])
        engine_text.pack(side="left", padx=(10, 14), pady=8)
        tk.Label(
            engine_text,
            text="AntiOS Engine",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI Semibold", 9),
        ).pack(anchor="w")
        tk.Label(
            engine_text,
            text=f"v{__version__}  •  Alpha",
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
        ).pack(anchor="w")

        self.export_button = self._button(
            header_actions,
            self.t("button.export"),
            self.export_report,
            kind="secondary",
        )
        self.export_button.pack(side="left", padx=(0, 8))
        self.refresh_button = self._button(
            header_actions,
            self.t("button.refresh"),
            self.refresh,
            kind="primary",
        )
        self.refresh_button.pack(side="left")

        self.page_host = tk.Frame(self.content, bg=THEME["bg"])
        self.page_host.pack(
            fill="both",
            expand=True,
            padx=PHI_SPACE["lg"],
            pady=(0, PHI_SPACE["lg"]),
        )

    def _build_pages(self) -> None:
        for name in ("overview", "security", "antivirus", "startup", "system", "cleanup", "settings"):
            frame = self.tk.Frame(self.page_host, bg=THEME["bg"])
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[name] = frame

        self._build_overview(self.pages["overview"])
        self._build_security(self.pages["security"])
        self.antivirus_panel = AntivirusPanel(self, self.pages["antivirus"], THEME)
        self._build_startup(self.pages["startup"])
        self._build_system(self.pages["system"])
        self._build_cleanup(self.pages["cleanup"])
        self._build_settings(self.pages["settings"])


    def _build_overview(self, parent: Any) -> None:
        tk = self.tk
        scroll = ScrollFrame(parent, tk)
        scroll.frame.pack(fill="both", expand=True)
        body = scroll.inner

        hero = tk.Frame(
            body,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        hero.pack(fill="x", pady=(0, PHI_SPACE["sm"]))
        hero.grid_columnconfigure(1, weight=1)
        hero.grid_columnconfigure(2, minsize=260)

        visual = tk.Canvas(
            hero,
            width=220,
            height=215,
            bg=THEME["surface"],
            highlightthickness=0,
            bd=0,
        )
        visual.grid(row=0, column=0, rowspan=2, padx=(24, 8), pady=16)
        # A restrained logarithmic-spiral motif: progressively smaller arcs
        # follow approximately golden-ratio radii without overwhelming status.
        orbit = THEME["accent"]
        rings = [
            (15, 14, 205, 204, 198, 270, 3),
            (35, 34, 186, 185, 18, 250, 2),
            (55, 54, 166, 165, 210, 220, 2),
            (72, 71, 149, 148, 42, 185, 1),
        ]
        for x1, y1, x2, y2, start, extent, width in rings:
            visual.create_arc(
                x1, y1, x2, y2,
                start=start,
                extent=extent,
                style="arc",
                outline=orbit,
                width=width,
            )
        visual.create_oval(69, 66, 151, 148, fill=THEME["accent_soft"], outline=THEME["accent"], width=2)
        self.overview_shield = visual.create_text(
            110, 107,
            text="✓",
            fill=THEME["accent"],
            font=("Segoe UI", 34, "bold"),
        )

        hero_center = tk.Frame(hero, bg=THEME["surface"])
        hero_center.grid(row=0, column=1, sticky="nsew", padx=(8, 24), pady=(28, 14))
        self.hero_kicker = tk.Label(
            hero_center,
            text=self.t("overview.checking_kicker"),
            bg=THEME["surface"],
            fg=THEME["accent"],
            font=("Segoe UI Semibold", 9),
        )
        self.hero_kicker.pack(anchor="w")
        self.status_title = tk.Label(
            hero_center,
            text=self.t("overview.checking_title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 24, "bold"),
            anchor="w",
            justify="left",
        )
        self.status_title.pack(fill="x", pady=(6, 4))
        self.status_summary = tk.Label(
            hero_center,
            text=self.t("overview.checking_detail"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=520,
        )
        self.status_summary.pack(fill="x")

        hero_actions = tk.Frame(hero_center, bg=THEME["surface"])
        hero_actions.pack(fill="x", pady=(18, 0))
        self._button(
            hero_actions,
            "▶  " + (self.t("nav.antivirus") if self.language != "ru" else "Запустить проверку"),
            lambda: self.show_page("antivirus"),
            kind="primary",
        ).pack(side="left")
        self._button(
            hero_actions,
            self.t("button.windows_security"),
            lambda: _open_settings("windowsdefender:"),
            kind="secondary",
        ).pack(side="left", padx=(8, 0))

        score = tk.Frame(hero, bg=THEME["surface_soft"])
        score.grid(row=0, column=2, rowspan=2, sticky="nsew", padx=(0, 20), pady=20)
        tk.Label(
            score,
            text="УРОВЕНЬ ЗАЩИТЫ" if self.language == "ru" else "PROTECTION LEVEL",
            bg=THEME["surface_soft"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(pady=(22, 8))
        self.overview_score = tk.Label(
            score,
            text="—",
            bg=THEME["surface_soft"],
            fg=THEME["accent"],
            font=("Segoe UI", 32, "bold"),
        )
        self.overview_score.pack()
        self.overview_score_caption = tk.Label(
            score,
            text="из 100" if self.language == "ru" else "of 100",
            bg=THEME["surface_soft"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        )
        self.overview_score_caption.pack()
        self.overview_score_note = tk.Label(
            score,
            text="Проверяем состояние компонентов…" if self.language == "ru" else "Checking protection components…",
            bg=THEME["surface_soft"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
            wraplength=210,
            justify="center",
        )
        self.overview_score_note.pack(padx=18, pady=(12, 20))

        features = tk.Frame(body, bg=THEME["bg"])
        features.pack(fill="x", pady=(0, PHI_SPACE["sm"]))
        for i in range(4):
            features.grid_columnconfigure(i, weight=1, uniform="overview-feature")

        feature_specs = [
            ("◇", "Резидентная защита" if self.language == "ru" else "Resident protection",
             "Контроль файлов и процессов в реальном времени." if self.language == "ru" else "Real-time file and process monitoring.",
             lambda: self.show_page("antivirus")),
            ("⌕", "Проверка файлов" if self.language == "ru" else "File scanning",
             "Быстрая, полная и выборочная проверка." if self.language == "ru" else "Quick, full and selected scans.",
             lambda: self.show_page("antivirus")),
            ("⊞", "Интеграция с Windows" if self.language == "ru" else "Windows integration",
             "Совместная работа с Microsoft Defender." if self.language == "ru" else "Coexists with Microsoft Defender.",
             lambda: self.show_page("security")),
            ("↻", "Обновления" if self.language == "ru" else "Updates",
             "Движок и база угроз поддерживаются актуальными." if self.language == "ru" else "Engine and threat database stay current.",
             lambda: self.show_page("settings")),
        ]
        self.overview_feature_status: dict[str, Any] = {}
        for index, (icon, title, detail, command) in enumerate(feature_specs):
            card = tk.Frame(
                features,
                bg=THEME["surface"],
                highlightthickness=1,
                highlightbackground=THEME["border"],
            )
            card.grid(
                row=0, column=index, sticky="nsew",
                padx=(0 if index == 0 else 5, 0 if index == 3 else 5),
            )
            tk.Label(
                card,
                text=icon,
                bg=THEME["surface"],
                fg=THEME["accent"] if index < 2 else THEME["info"],
                font=("Segoe UI", 17, "bold"),
            ).pack(anchor="w", padx=16, pady=(16, 8))
            tk.Label(
                card,
                text=title,
                bg=THEME["surface"],
                fg=THEME["text"],
                font=("Segoe UI Semibold", 10),
            ).pack(anchor="w", padx=16)
            tk.Label(
                card,
                text=detail,
                bg=THEME["surface"],
                fg=THEME["muted"],
                font=("Segoe UI", 8),
                justify="left",
                wraplength=220,
            ).pack(anchor="w", padx=16, pady=(5, 10))
            self._button(card, self.t("button.open"), command, kind="ghost").pack(anchor="w", padx=14, pady=(0, 14))

        lower = tk.Frame(body, bg=THEME["bg"])
        lower.pack(fill="both", expand=True)
        lower.grid_columnconfigure(0, weight=3)
        lower.grid_columnconfigure(1, weight=2)
        lower.grid_rowconfigure(0, weight=1)

        checks_card = tk.Frame(
            lower,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        checks_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        checks_head = tk.Frame(checks_card, bg=THEME["surface"])
        checks_head.pack(fill="x", padx=18, pady=(16, 8))
        tk.Label(
            checks_head,
            text="Последние проверки" if self.language == "ru" else "Latest checks",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 12, "bold"),
        ).pack(side="left")
        self.check_scroll = ScrollFrame(checks_card, tk)
        self.check_scroll.frame.configure(height=260)
        self.check_scroll.frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        status_card = tk.Frame(
            lower,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        status_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        tk.Label(
            status_card,
            text="Состояние системы" if self.language == "ru" else "System status",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=18, pady=(16, 10))

        self.overview_guard_status = self._overview_status_row(
            status_card, "◇", "AntiOS Guard", "Проверяем…" if self.language == "ru" else "Checking…"
        )
        self.overview_defender_status = self._overview_status_row(
            status_card, "⊞", "Microsoft Defender", "Проверяем…" if self.language == "ru" else "Checking…"
        )
        self.overview_signature_status = self._overview_status_row(
            status_card, "↻", "Сигнатуры" if self.language == "ru" else "Signatures", "Проверяем…" if self.language == "ru" else "Checking…"
        )
        self.overview_engine_status = self._overview_status_row(
            status_card, "◈", "AntiOS Engine", f"v{__version__}"
        )
        self.summary_chips = {}

    def _build_security(self, parent: Any) -> None:
        self.security_grid = self.tk.Frame(parent, bg=THEME["bg"])
        self.security_grid.pack(fill="both", expand=True)

        for col in range(2):
            self.security_grid.grid_columnconfigure(col, weight=1, uniform="security")

        self.security_cards: dict[str, dict[str, Any]] = {}
        specs = [
            ("defender", self.t("security.defender.title"), self.t("security.defender.subtitle"), 0, 0),
            ("encryption", self.t("security.encryption.title"), self.t("security.encryption.subtitle"), 0, 1),
            ("secure_boot", self.t("security.secure_boot.title"), self.t("security.secure_boot.subtitle"), 1, 0),
            ("tpm", self.t("security.tpm.title"), self.t("security.tpm.subtitle"), 1, 1),
        ]
        for key, title, subtitle, row, col in specs:
            card = self._metric_card(
                self.security_grid,
                title,
                subtitle,
            )
            card["frame"].grid(
                row=row,
                column=col,
                sticky="nsew",
                padx=(0 if col == 0 else 8, 8 if col == 0 else 0),
                pady=(0 if row == 0 else 8, 8 if row == 0 else 0),
            )
            self.security_grid.grid_rowconfigure(row, weight=1)
            self.security_cards[key] = card

        actions = self.tk.Frame(parent, bg=THEME["bg"])
        actions.pack(fill="x", pady=(18, 0))
        self._button(
            actions,
            self.t("button.windows_security"),
            lambda: _open_settings("windowsdefender:"),
            kind="primary",
        ).pack(side="left")

    def _build_startup(self, parent: Any) -> None:
        tk = self.tk

        summary = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        summary.pack(fill="x", pady=(0, 14))

        left = tk.Frame(summary, bg=THEME["surface"])
        left.pack(side="left", padx=18, pady=15)

        self.startup_count = tk.Label(
            left,
            text="—",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 20, "bold"),
        )
        self.startup_count.pack(side="left")

        tk.Label(
            left,
            text=self.t("startup.entries"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
        ).pack(side="left", pady=(5, 0))

        self._button(
            summary,
            self.t("button.startup_apps"),
            lambda: _open_settings("ms-settings:startupapps"),
            kind="secondary",
        ).pack(side="right", padx=14, pady=12)

        table = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        table.pack(fill="both", expand=True)

        self.startup_tree = self.ttk.Treeview(
            table,
            columns=("name", "location", "user"),
            show="headings",
            style="AntiOS.Treeview",
        )
        self.startup_tree.heading("name", text=self.t("startup.application"))
        self.startup_tree.heading("location", text=self.t("startup.location"))
        self.startup_tree.heading("user", text=self.t("startup.user"))
        self.startup_tree.column("name", width=280)
        self.startup_tree.column("location", width=360)
        self.startup_tree.column("user", width=170)

        scrollbar = tk.Scrollbar(
            table,
            orient="vertical",
            command=self.startup_tree.yview,
            width=10,
            bd=0,
            relief="flat",
        )
        self.startup_tree.configure(yscrollcommand=scrollbar.set)

        self.startup_tree.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        scrollbar.pack(side="right", fill="y")

    def _build_system(self, parent: Any) -> None:
        tk = self.tk

        self.system_grid = tk.Frame(parent, bg=THEME["bg"])
        self.system_grid.pack(fill="both", expand=True)

        for col in range(2):
            self.system_grid.grid_columnconfigure(col, weight=1, uniform="system")

        self.system_cards: dict[str, dict[str, Any]] = {}
        specs = [
            ("windows", self.t("system.windows.title"), self.t("system.windows.subtitle"), 0, 0),
            ("computer", self.t("system.computer.title"), self.t("system.computer.subtitle"), 0, 1),
            ("storage", self.t("system.storage.title"), self.t("system.storage.subtitle"), 1, 0),
            ("session", self.t("system.session.title"), self.t("system.session.subtitle"), 1, 1),
        ]
        for key, title, subtitle, row, col in specs:
            card = self._metric_card(
                self.system_grid,
                title,
                subtitle,
                multiline=True,
            )
            card["frame"].grid(
                row=row,
                column=col,
                sticky="nsew",
                padx=(0 if col == 0 else 8, 8 if col == 0 else 0),
                pady=(0 if row == 0 else 8, 8 if row == 0 else 0),
            )
            self.system_grid.grid_rowconfigure(row, weight=1)
            self.system_cards[key] = card

        actions = tk.Frame(parent, bg=THEME["bg"])
        actions.pack(fill="x", pady=(18, 0))

        self._button(
            actions,
            self.t("button.storage_settings"),
            lambda: _open_settings("ms-settings:storagesense"),
            kind="secondary",
        ).pack(side="left")

    def _build_cleanup(self, parent: Any) -> None:
        tk = self.tk

        controls = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        controls.pack(fill="x", pady=(0, 12))

        left = tk.Frame(controls, bg=THEME["surface"])
        left.pack(side="left", fill="x", expand=True, padx=18, pady=14)

        tk.Label(
            left,
            text=self.t("cleanup.path"),
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w")

        self.cleanup_path_label = tk.Label(
            left,
            text=str(self.storage_path),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 10),
            anchor="w",
        )
        self.cleanup_path_label.pack(fill="x", pady=(4, 0))

        buttons = tk.Frame(controls, bg=THEME["surface"])
        buttons.pack(side="right", padx=14, pady=12)

        self.cleanup_choose_button = self._button(
            buttons,
            self.t("cleanup.choose"),
            self._choose_cleanup_folder,
            kind="secondary",
        )
        self.cleanup_choose_button.pack(side="left")

        self.cleanup_scan_button = self._button(
            buttons,
            self.t("cleanup.scan"),
            self._start_cleanup_scan,
            kind="primary",
        )
        self.cleanup_scan_button.pack(side="left", padx=(8, 0))

        self.cleanup_cancel_button = self._button(
            buttons,
            self.t("cleanup.cancel"),
            self._cancel_cleanup_scan,
            kind="secondary",
        )
        self.cleanup_cancel_button.configure(state="disabled")
        self.cleanup_cancel_button.pack(side="left", padx=(8, 0))

        status_row = tk.Frame(parent, bg=THEME["bg"])
        status_row.pack(fill="x", pady=(0, 8))
        self.cleanup_status = tk.Label(
            status_row,
            text=self.t("cleanup.status.ready"),
            bg=THEME["bg"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        )
        self.cleanup_status.pack(side="left", fill="x", expand=True)
        self.cleanup_selection_label = tk.Label(
            status_row,
            text=self.t("cleanup.selection_none"),
            bg=THEME["bg"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 9),
            anchor="e",
        )
        self.cleanup_selection_label.pack(side="right")

        self.cleanup_progress = self.ttk.Progressbar(
            parent,
            mode="indeterminate",
            style="AntiOS.Horizontal.TProgressbar",
        )
        self.cleanup_progress.pack(fill="x", pady=(0, 12))

        summary = tk.Frame(parent, bg=THEME["bg"])
        summary.pack(fill="x", pady=(0, 12))
        for column in range(5):
            summary.grid_columnconfigure(column, weight=1, uniform="cleanup")

        self.cleanup_summary: dict[str, Any] = {}
        summary_specs = [
            ("duplicate_groups", self.t("cleanup.summary.duplicates")),
            ("duplicate_reclaimable_bytes", self.t("cleanup.summary.reclaimable")),
            ("old_large_files", self.t("cleanup.summary.old")),
            ("installer_archives", self.t("cleanup.summary.archives")),
            ("empty_files", self.t("cleanup.summary.empty")),
        ]
        for column, (key, title) in enumerate(summary_specs):
            card = tk.Frame(
                summary,
                bg=THEME["surface"],
                highlightthickness=1,
                highlightbackground=THEME["border"],
            )
            card.grid(
                row=0,
                column=column,
                sticky="nsew",
                padx=(0 if column == 0 else 4, 0 if column == 4 else 4),
            )
            tk.Frame(card, bg=THEME["accent"], height=2).pack(fill="x")
            value = tk.Label(
                card,
                text="—",
                bg=THEME["surface"],
                fg=THEME["text"],
                font=("Segoe UI", 15, "bold"),
            )
            value.pack(anchor="w", padx=13, pady=(10, 2))
            tk.Label(
                card,
                text=title,
                bg=THEME["surface"],
                fg=THEME["muted"],
                font=("Segoe UI", 8),
                wraplength=150,
                justify="left",
            ).pack(anchor="w", padx=13, pady=(0, 11))
            self.cleanup_summary[key] = value

        tk.Label(
            parent,
            text=self.t(
                "cleanup.note",
                days=self.config.cleanup.old_days,
            ),
            bg=THEME["bg"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=900,
        ).pack(fill="x", pady=(0, 10))

        self.cleanup_intelligence_label = tk.Label(
            parent, text="MemoryMap / TimeDebt: awaiting first scan",
            bg=THEME["bg"], fg=THEME["muted"],
            font=("Segoe UI", 9), anchor="w", wraplength=900,
        )
        self.cleanup_intelligence_label.pack(fill="x", pady=(0, 10))

        intelligence_actions = tk.Frame(parent, bg=THEME["bg"])
        intelligence_actions.pack(fill="x", pady=(0, 9))
        for caption, action in (
            (("Проверить резервную копию" if self.language == "ru" else "RecoveryProof"), self._proof_cleanup_backup),
            (("Отчёт о восстановимости" if self.language == "ru" else "Survival report"), self._show_cleanup_survival),
            (("Предпочитать категорию" if self.language == "ru" else "Prefer category"), lambda: self._cleanup_preference("prefer")),
            (("Скрыть категорию" if self.language == "ru" else "Hide category"), lambda: self._cleanup_preference("hide")),
            (("Сбросить приоритеты" if self.language == "ru" else "Reset preferences"), self._cleanup_reset_preferences),
        ):
            self._button(intelligence_actions, caption, action, kind="secondary").pack(side="left", padx=(0, 6))

        history_actions = tk.Frame(parent, bg=THEME["bg"])
        history_actions.pack(fill="x", pady=(0, 9))
        self._button(
            history_actions,
            "Настроить историю MemoryMap" if self.language == "ru" else "Toggle MemoryMap history",
            self._toggle_cleanup_history,
            kind="secondary",
        ).pack(side="left", padx=(0, 6))
        self._button(
            history_actions,
            "Удалить историю" if self.language == "ru" else "Erase MemoryMap history",
            self._clear_cleanup_history,
            kind="secondary",
        ).pack(side="left")

        table_header = tk.Frame(parent, bg=THEME["bg"])
        table_header.pack(fill="x", pady=(0, 6))
        tk.Label(
            table_header,
            text=self.t("cleanup.results"),
            bg=THEME["bg"],
            fg=THEME["text"],
            font=("Segoe UI Semibold", 10),
        ).pack(side="left")
        tk.Label(
            table_header,
            text=self.t("cleanup.multi_hint"),
            bg=THEME["bg"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
        ).pack(side="right")

        table = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        table.pack(fill="both", expand=True)
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)

        self.cleanup_tree = self.ttk.Treeview(
            table,
            columns=("type", "size", "modified", "path"),
            show="headings",
            style="AntiOS.Treeview",
            selectmode="extended",
        )
        self.cleanup_tree.heading("type", text=self.t("cleanup.column.type"))
        self.cleanup_tree.heading("size", text=self.t("cleanup.column.size"))
        self.cleanup_tree.heading("modified", text=self.t("cleanup.column.modified"))
        self.cleanup_tree.heading("path", text=self.t("cleanup.column.path"))
        self.cleanup_tree.column("type", width=165, stretch=False)
        self.cleanup_tree.column("size", width=105, stretch=False, anchor="e")
        self.cleanup_tree.column("modified", width=115, stretch=False, anchor="center")
        self.cleanup_tree.column("path", width=520)

        vertical = tk.Scrollbar(table, orient="vertical", command=self.cleanup_tree.yview, width=10, bd=0)
        horizontal = tk.Scrollbar(table, orient="horizontal", command=self.cleanup_tree.xview, bd=0)
        self.cleanup_tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )
        self.cleanup_tree.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=(1, 0))
        vertical.grid(row=0, column=1, sticky="ns", pady=(1, 0))
        horizontal.grid(row=1, column=0, sticky="ew", padx=(1, 0), pady=(0, 1))
        self.cleanup_tree.bind("<Double-1>", lambda _event: self._open_cleanup_selection())
        self.cleanup_tree.bind("<<TreeviewSelect>>", lambda _event: self._cleanup_selection_changed())

        actions = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        actions.pack(fill="x", pady=(10, 0))
        left_actions = tk.Frame(actions, bg=THEME["surface"])
        left_actions.pack(side="left", padx=10, pady=10)
        right_actions = tk.Frame(actions, bg=THEME["surface"])
        right_actions.pack(side="right", padx=10, pady=10)

        self.cleanup_open_button = self._button(
            left_actions,
            self.t("cleanup.open_folder"),
            self._open_cleanup_selection,
            kind="secondary",
        )
        self.cleanup_open_button.pack(side="left")

        self.cleanup_duplicate_select_button = self._button(
            left_actions,
            self.t("cleanup.select_duplicate_copies"),
            self._select_cleanup_duplicate_copies,
            kind="secondary",
        )
        self.cleanup_duplicate_select_button.pack(side="left", padx=(6, 0))

        self.cleanup_select_all_button = self._button(
            left_actions,
            self.t("cleanup.select_all"),
            self._select_cleanup_all,
            kind="secondary",
        )
        self.cleanup_select_all_button.pack(side="left", padx=(6, 0))

        self.cleanup_clear_button = self._button(
            left_actions,
            self.t("cleanup.clear_selection"),
            self._clear_cleanup_selection,
            kind="secondary",
        )
        self.cleanup_clear_button.pack(side="left", padx=(6, 0))

        self.cleanup_backup_button = self._button(
            right_actions,
            self.t("cleanup.delete_backup"),
            lambda: self._run_cleanup_action("backup"),
            kind="primary",
        )
        self.cleanup_backup_button.pack(side="left")

        self.cleanup_delete_button = self._button(
            right_actions,
            self.t("cleanup.delete_permanent"),
            lambda: self._run_cleanup_action("delete"),
            kind="danger",
        )
        self.cleanup_delete_button.pack(side="left", padx=(8, 0))

        self.cleanup_rows: dict[str, dict[str, Any]] = {}
        self._cleanup_selection_changed()

        if self.storage_result:
            self._render_cleanup_result(self.storage_result)

    def _choose_cleanup_folder(self) -> None:
        from tkinter import filedialog

        selected = filedialog.askdirectory(
            title=self.t("cleanup.dialog.title"),
            initialdir=str(self.storage_path),
            mustexist=True,
        )
        if not selected:
            return
        self.storage_path = Path(selected)
        self.cleanup_path_label.configure(text=str(self.storage_path))
        self.cleanup_status.configure(text=self.t("cleanup.status.ready"))

        if self.config.cleanup.remember_folder:
            self.config = replace(
                self.config,
                cleanup=replace(
                    self.config.cleanup,
                    last_path=str(self.storage_path),
                ),
            )
            self._persist_config()

    def _set_cleanup_busy(self, busy: bool, *, scanning: bool = False) -> None:
        for button in (
            self.cleanup_choose_button,
            self.cleanup_scan_button,
            self.cleanup_open_button,
            self.cleanup_duplicate_select_button,
            self.cleanup_select_all_button,
            self.cleanup_clear_button,
            self.cleanup_backup_button,
            self.cleanup_delete_button,
        ):
            button.configure(state="disabled" if busy else "normal")
        self.cleanup_cancel_button.configure(state="normal" if scanning else "disabled")
        self.cleanup_scan_button.configure(
            text=self.t("cleanup.scanning") if scanning else self.t("cleanup.scan")
        )
        if busy:
            self.cleanup_progress.start(12)
        else:
            self.cleanup_progress.stop()
        if not busy:
            self._cleanup_selection_changed()

    def _start_cleanup_scan(self) -> None:
        if self._storage_action_busy:
            return
        self._storage_cancel = threading.Event()
        self._set_cleanup_busy(True, scanning=True)
        self.cleanup_status.configure(
            text=self.t("cleanup.status.progress", count=0)
        )

        def progress(payload: dict[str, Any]) -> None:
            phase = payload.get("phase")
            if phase == "hashing":
                message = self.t(
                    "cleanup.status.hashing",
                    count=payload.get("files_hashed", 0),
                )
            else:
                message = self.t(
                    "cleanup.status.progress",
                    count=payload.get("files_scanned", 0),
                )
            self.root.after(
                0,
                lambda text=message: self.cleanup_status.configure(text=text)
                if self.cleanup_status.winfo_exists()
                else None,
            )

        def worker() -> None:
            try:
                result = scan_storage(
                    self.storage_path,
                    old_days=self.config.cleanup.old_days,
                    large_bytes=self.config.cleanup.large_mb * 1024 * 1024,
                    duplicate_min_bytes=(
                        self.config.cleanup.duplicate_min_mb * 1024 * 1024
                    ),
                    progress=progress,
                    cancelled=self._storage_cancel.is_set,
                )
                if not result.get("cancelled"):
                    result["intelligence"] = insights_for_scan(result)
            except Exception as exc:
                self.root.after(
                    0,
                    lambda error=str(exc): self._finish_cleanup_error(error),
                )
                return
            self.root.after(0, lambda: self._finish_cleanup_scan(result))

        threading.Thread(target=worker, daemon=True).start()

    def _cancel_cleanup_scan(self) -> None:
        self._storage_cancel.set()
        self.cleanup_status.configure(text=self.t("cleanup.status.cancelled"))

    def _finish_cleanup_error(self, error: str) -> None:
        self._set_cleanup_busy(False)
        self.cleanup_status.configure(
            text=self.t("cleanup.status.error", error=error)
        )

    def _finish_cleanup_scan(self, result: dict[str, Any]) -> None:
        self._set_cleanup_busy(False)

        if result.get("cancelled"):
            self.cleanup_status.configure(text=self.t("cleanup.status.cancelled"))
            return

        self.storage_result = result
        self._render_cleanup_result(result)
        self.cleanup_status.configure(
            text=self.t(
                "cleanup.status.done",
                count=result.get("summary", {}).get("files_scanned", 0),
            )
        )


    def _render(self, data: dict[str, Any]) -> None:
        self.data = data
        self.refresh_button.configure(state="normal", text=self.t("button.refresh"))

        evaluation = data["evaluation"]
        health = data["health"]
        scan_data = data["scan"]
        overall = evaluation.get("overall")
        summary = evaluation.get("summary", {})

        if overall == "needs-attention":
            kicker = (self.t("overview.needs_attention"), THEME["warn"])
            score = max(20, 100 - int(summary.get("warn", 0)) * 24 - int(summary.get("advisory", 0)) * 8)
            score_note = "Требуется внимание" if self.language == "ru" else "Attention required"
        elif overall == "review":
            kicker = (self.t("overview.review"), THEME["review"])
            score = max(45, 100 - int(summary.get("advisory", 0)) * 8)
            score_note = "Есть рекомендации" if self.language == "ru" else "Recommendations available"
        else:
            kicker = (self.t("overview.all_clear"), THEME["ok"])
            score = 100
            score_note = "Критичных проблем не обнаружено" if self.language == "ru" else "No critical issues detected"

        self.hero_kicker.configure(text=kicker[0], fg=kicker[1])
        self.status_title.configure(text=evaluation.get("headline", "Check complete"))
        self.status_summary.configure(
            text=self.t("overview.completed", count=summary.get("info", 0))
        )
        if hasattr(self, "overview_score"):
            self.overview_score.configure(text=str(score), fg=kicker[1])
            self.overview_score_note.configure(text=score_note)

        for row in self._check_rows:
            row.destroy()
        self._check_rows.clear()
        for check in evaluation.get("checks", [])[:8]:
            card = self._status_card(self.check_scroll.inner, check)
            card.pack(fill="x", pady=(0, 8))
            self._check_rows.append(card)

        defender = health.get("defender", {}) if isinstance(health, dict) else {}
        defender_ok = defender.get("antivirus_enabled") is True and defender.get("real_time_protection") is True
        if hasattr(self, "overview_defender_status"):
            self.overview_defender_status.configure(
                text=("Активен · совместная работа" if defender_ok else "Требует проверки")
                     if self.language == "ru" else
                     ("Active · coexistence" if defender_ok else "Needs review"),
                fg=THEME["ok"] if defender_ok else THEME["review"],
            )
        if hasattr(self, "overview_signature_status"):
            age = defender.get("signature_age_days")
            signature_text = (
                f"Defender: {age} дн." if self.language == "ru" and age is not None
                else f"Defender: {age} d" if age is not None
                else ("Управляется движком" if self.language == "ru" else "Managed by engine")
            )
            self.overview_signature_status.configure(text=signature_text)
        if hasattr(self, "overview_engine_status"):
            self.overview_engine_status.configure(text=f"v{__version__} · Alpha", fg=THEME["accent"])

        self._render_security(scan_data, health)
        self.antivirus_panel.render_provider_status(health)
        self._render_startup(health)
        self._render_system(scan_data, health)


    def _render_cleanup_result(self, result: dict[str, Any]) -> None:
        """Render bounded, opt-in storage scan rows (missing in Alpha 28)."""
        summary = result.get("summary", {})
        for key, widget in self.cleanup_summary.items():
            value = summary.get(key, 0)
            widget.configure(text=format_bytes(value) if key.endswith("_bytes") else str(value))
        if result.get("limit_reached"):
            self.cleanup_intelligence_label.configure(
                text=("Лимит сканирования: выберите меньшую папку. Очистка заблокирована."
                      if self.language == "ru" else
                      "Scan limit reached: choose a smaller folder; deletion is blocked."),
                fg=THEME["warn"],
            )
        else:
            info = result.get("intelligence", {})
            history = info.get("history", {})
            trend = history.get("bytes_per_day")
            note = (
                ("MemoryMap: данных пока недостаточно" if self.language == "ru"
                 else "MemoryMap: insufficient history")
                if trend is None else
                (("TimeDebt: изменение папки около " if self.language == "ru"
                  else "TimeDebt: estimated folder change ")
                 + format_bytes(abs(trend)) + ("/день" if self.language == "ru" else "/day")
                 + (" (рост)" if trend > 0 and self.language == "ru" else
                    " (снижение)" if trend < 0 and self.language == "ru" else ""))
            )
            forecast = history.get("predicted_bytes_30_days")
            if forecast is not None:
                note += (" · через 30 дн. ~" if self.language == "ru"
                         else " · 30-day folder estimate ~") + format_bytes(forecast)
            self.cleanup_intelligence_label.configure(text=note, fg=THEME["muted"])
        existing = self.cleanup_tree.get_children()
        if existing:
            self.cleanup_tree.delete(*existing)
        self.cleanup_rows.clear()
        categories = candidate_categories(result)
        meta = result.get("candidate_snapshots", {})
        preferences = result.get("intelligence", {}).get("preferences", {})
        recommendations = result.get("intelligence", {}).get("recommendations", [])
        order = [row["path"] for row in recommendations] or sorted(categories)
        labels = {
            "duplicate": self.t("cleanup.type.duplicate"),
            "old": self.t("cleanup.type.old"),
            "archive": self.t("cleanup.type.archive"),
            "empty": self.t("cleanup.type.empty"),
        }
        shown = 0
        for path in order:
            kinds = categories.get(path, [])
            if kinds and all(preferences.get(cat, {}).get("choice") == "hide" for cat in kinds):
                continue
            snapshot = meta.get(path)
            if not isinstance(snapshot, dict):
                continue
            modified_ns = snapshot.get("modified_ns", 0)
            try:
                date = datetime.fromtimestamp(int(modified_ns) / 1e9).strftime("%Y-%m-%d")
            except (ValueError, OverflowError, OSError, TypeError):
                date = "—"
            size = int(snapshot.get("size_bytes", 0))
            iid = self.cleanup_tree.insert(
                "", "end", values=(", ".join(labels[k] for k in kinds),
                                   format_bytes(size), date, path),
            )
            self.cleanup_rows[iid] = {
                "path": path, "size": size, "categories": kinds,
            }
            shown += 1
            if shown >= 1500:  # Tk must not freeze on huge inventories.
                break
        self._cleanup_selection_changed()
        if shown < len(categories):
            self.cleanup_status.configure(
                text=(f"Показано {shown} из {len(categories)} кандидатов"
                      if self.language == "ru" else
                      f"Showing {shown} of {len(categories)} candidates")
            )

    def _toggle_cleanup_history(self) -> None:
        from tkinter import messagebox
        try:
            with StorageJournal() as store:
                enabled = not store.history_enabled()
                store.set_history_enabled(enabled)
            messagebox.showinfo(
                "MemoryMap",
                ("История сканирований включена." if enabled else
                 "История сканирований отключена. Старые снимки можно удалить отдельно.")
                if self.language == "ru" else
                ("Scan history enabled." if enabled else
                 "Scan history disabled. Existing snapshots can be erased separately."),
            )
            if self.storage_result:
                self.storage_result["intelligence"] = insights_for_scan(self.storage_result)
                self._render_cleanup_result(self.storage_result)
        except (OSError, ValueError) as exc:
            messagebox.showerror("MemoryMap", str(exc))

    def _clear_cleanup_history(self) -> None:
        from tkinter import messagebox
        if not messagebox.askyesno(
            "MemoryMap",
            ("Безвозвратно удалить сохранённые агрегированные снимки?"
             if self.language == "ru" else
             "Permanently delete saved aggregate snapshots?"),
        ):
            return
        try:
            with StorageJournal() as store:
                store.clear_history()
            # Do not immediately recreate the record being deleted.
            if self.storage_result:
                self.storage_result.get("intelligence", {})["history"] = {
                    "forecast": "insufficient-history", "samples": [],
                }
            self.cleanup_intelligence_label.configure(
                text=("История очищена; следующий запуск анализа создаст новый снимок."
                      if self.language == "ru" else
                      "History erased; the next scan may create a new snapshot.")
            )
        except (OSError, ValueError) as exc:
            messagebox.showerror("MemoryMap", str(exc))

    def _show_cleanup_survival(self) -> None:
        from tkinter import messagebox
        if not self.storage_result:
            return
        report = self.storage_result.get("intelligence", {}).get("survival")
        if not report:
            return
        text = (
            (f"Проверено кандидатов: {report['assessed_cleanup_candidates']}\n"
             f"Без подтверждённой независимой копии: "
             f"{report['candidates_without_verified_independent_copy']}\n\n"
             "Проверены только файлы внутри выбранной папки. "
             "Это не означает, что копий больше нигде нет.")
            if self.language == "ru" else
            (f"Candidates: {report['assessed_cleanup_candidates']}\n"
             f"Without another verified file in this scan: "
             f"{report['candidates_without_verified_independent_copy']}\n\n"
             "Only this scanned folder was checked; no claim of uniqueness.")
        )
        messagebox.showinfo("AntiOS Survival / LastCopy", text)

    def _cleanup_preference(self, choice: str) -> None:
        from tkinter import messagebox
        categories = {
            cat for row in self._selected_cleanup_rows() for cat in row.get("categories", [])
        }
        if not categories:
            messagebox.showinfo("CleanupDNA", "Select a cleanup candidate first.")
            return
        try:
            with StorageJournal() as journal:
                for category in categories:
                    journal.set_preference(category, choice)
            self.storage_result["intelligence"] = insights_for_scan(self.storage_result)
            self._render_cleanup_result(self.storage_result)
        except (OSError, ValueError) as exc:
            messagebox.showerror("CleanupDNA", str(exc))

    def _cleanup_reset_preferences(self) -> None:
        from tkinter import messagebox
        try:
            with StorageJournal() as journal:
                for category in ("duplicate", "old", "archive", "empty"):
                    journal.set_preference(category, "normal")
            if self.storage_result:
                self.storage_result["intelligence"] = insights_for_scan(self.storage_result)
                self._render_cleanup_result(self.storage_result)
        except (OSError, ValueError) as exc:
            messagebox.showerror("CleanupDNA", str(exc))

    def _proof_cleanup_backup(self) -> None:
        from tkinter import filedialog, messagebox
        if self._storage_action_busy:
            return
        chosen = filedialog.askdirectory(
            title="AntiOS RecoveryProof: select a Storage Cleanup backup",
            mustexist=True,
        )
        if not chosen:
            return
        self._storage_action_busy = True
        self._set_cleanup_busy(True)

        def worker() -> None:
            try:
                report = prove_cleanup_backup(chosen)
                message = (
                    f"Status: {report['status']}\n"
                    f"Verified: {report['verified']} / {report['entries']}\n"
                    f"Test-restored in sandbox: {report['sandbox_restored']}\n"
                    + "\n".join(report["errors"][:5])
                )
                failed = bool(report["errors"])
            except Exception as exc:
                message, failed = str(exc), True
            def finish() -> None:
                self._storage_action_busy = False
                self._set_cleanup_busy(False)
                if failed:
                    messagebox.showwarning("AntiOS RecoveryProof", message)
                else:
                    messagebox.showinfo("AntiOS RecoveryProof", message)
            self.root.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _selected_cleanup_rows(self) -> list[dict[str, Any]]:
        return [
            self.cleanup_rows[iid]
            for iid in self.cleanup_tree.selection()
            if iid in self.cleanup_rows
        ]

    def _cleanup_selection_changed(self) -> None:
        if not hasattr(self, "cleanup_tree"):
            return
        selected = self._selected_cleanup_rows()
        size = sum(int(row.get("size", 0)) for row in selected)
        if selected:
            self.cleanup_selection_label.configure(
                text=self.t(
                    "cleanup.selection",
                    count=len(selected),
                    size=format_bytes(size),
                ),
                fg=THEME["text"],
            )
        else:
            self.cleanup_selection_label.configure(
                text=self.t("cleanup.selection_none"),
                fg=THEME["muted_2"],
            )

        can_act = bool(selected) and not self._storage_action_busy
        state = "normal" if can_act else "disabled"
        self.cleanup_open_button.configure(state=state)
        self.cleanup_backup_button.configure(state=state)
        self.cleanup_delete_button.configure(state=state)
        self.cleanup_clear_button.configure(state=state)

    def _select_cleanup_all(self) -> None:
        children = self.cleanup_tree.get_children()
        if children:
            self.cleanup_tree.selection_set(children)
            self._cleanup_selection_changed()

    def _clear_cleanup_selection(self) -> None:
        self.cleanup_tree.selection_remove(self.cleanup_tree.selection())
        self._cleanup_selection_changed()

    def _select_cleanup_duplicate_copies(self) -> None:
        if not self.storage_result:
            return
        disposable: set[str] = set()
        for group in self.storage_result.get("duplicates", []):
            paths = [str(path) for path in group.get("paths", [])]
            disposable.update(paths[1:])
        matches = [
            iid
            for iid, row in self.cleanup_rows.items()
            if str(row.get("path")) in disposable
        ]
        if matches:
            self.cleanup_tree.selection_set(matches)
        else:
            self.cleanup_tree.selection_remove(self.cleanup_tree.selection())
        self._cleanup_selection_changed()

    def _open_cleanup_selection(self) -> None:
        selected = self._selected_cleanup_rows()
        if not selected:
            return
        path = Path(str(selected[0]["path"]))
        target = path.parent if path.parent.exists() else self.storage_path
        if os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]

    def _run_cleanup_action(self, mode: str) -> None:
        from tkinter import filedialog, messagebox

        if self._storage_action_busy or not self.storage_result:
            return
        selected = self._selected_cleanup_rows()
        if not selected:
            return

        total = sum(int(row.get("size", 0)) for row in selected)
        paths = [str(row["path"]) for row in selected]
        backup_root = None

        if mode == "backup":
            if not messagebox.askyesno(
                self.t("cleanup.confirm_backup_title"),
                self.t(
                    "cleanup.confirm_backup",
                    count=len(paths),
                    size=format_bytes(total),
                ),
            ):
                return
            chosen = filedialog.askdirectory(
                title=self.t("cleanup.backup_dialog_title"),
                initialdir=str(default_cleanup_backup_path().parent.parent),
                mustexist=False,
            )
            if not chosen:
                return
            backup_root = chosen
        else:
            # LastCopy never declares a file unique, but it can warn that
            # no independent copy was verified within the scanned folder.
            evidence = copy_evidence(self.storage_result, paths)
            unverified = sum(v['status'] == 'no-independent-copy-verified'
                             for v in evidence.values())
            if unverified and not messagebox.askyesno(
                "AntiOS LastCopy",
                (f"{unverified} selected files have no independently verified copy "
                 "inside the scanned folder. Other backups were not checked. "
                 "Continue to permanent deletion?"), icon="warning",
            ):
                return
            if not messagebox.askyesno(
                self.t("cleanup.confirm_permanent_title"),
                self.t(
                    "cleanup.confirm_permanent",
                    count=len(paths),
                    size=format_bytes(total),
                ),
                icon="warning",
            ):
                return

        self._storage_action_busy = True
        self._set_cleanup_busy(True)
        self.cleanup_status.configure(text=self.t("cleanup.action_working"))

        def worker() -> None:
            try:
                result = cleanup_files(
                    self.storage_result,
                    paths,
                    mode=mode,
                    backup_root=backup_root,
                )
            except Exception as exc:
                self.root.after(
                    0,
                    lambda error=str(exc): self._finish_cleanup_action_error(error),
                )
                return
            self.root.after(0, lambda: self._finish_cleanup_action(result))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_cleanup_action_error(self, error: str) -> None:
        from tkinter import messagebox

        self._storage_action_busy = False
        self._set_cleanup_busy(False)
        self.cleanup_status.configure(
            text=self.t("cleanup.action_error", error=error)
        )
        messagebox.showerror(
            self.t("cleanup.action_error_title"),
            self.t("cleanup.action_error", error=error),
        )

    def _finish_cleanup_action(self, result: dict[str, Any]) -> None:
        from tkinter import messagebox

        self._storage_action_busy = False
        self._set_cleanup_busy(False)
        deleted = int(result.get("deleted", 0))
        errors = len(result.get("errors", []))
        # CleanupDNA learns only from confirmed successful deletions, never
        # from files that the user simply ignored.
        if deleted and self.storage_result:
            categories = candidate_categories(self.storage_result)
            chosen_kinds = [kind for item in result.get("items", [])
                            if item.get("status") == "deleted"
                            for kind in categories.get(item.get("path"), [])]
            if chosen_kinds:
                try:
                    with StorageJournal() as journal:
                        journal.confirmed_cleanup(chosen_kinds)
                except (OSError, ValueError):
                    pass
        freed = format_bytes(result.get("bytes_freed", 0))

        if result.get("mode") == "backup":
            message = self.t(
                "cleanup.action_done_backup",
                count=deleted,
                size=freed,
                backup=result.get("backup_dir") or "—",
                errors=errors,
            )
        else:
            message = self.t(
                "cleanup.action_done",
                count=deleted,
                size=freed,
                errors=errors,
            )

        self.cleanup_status.configure(text=message)
        if errors:
            messagebox.showwarning(self.t("cleanup.action_result_title"), message)
        else:
            messagebox.showinfo(self.t("cleanup.action_result_title"), message)

        # Refresh candidates from disk after a destructive action so the table
        # never presents stale files as still selectable.
        self._start_cleanup_scan()


    def _build_settings(self, parent: Any) -> None:
        tk = self.tk
        scroll = ScrollFrame(parent, tk)
        scroll.frame.pack(fill="both", expand=True)
        body = scroll.inner

        tabs = tk.Frame(
            body,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        tabs.pack(fill="x", pady=(0, 12))
        for index, label in enumerate([
            "Основные" if self.language == "ru" else "General",
            "Обновления" if self.language == "ru" else "Updates",
            "Защита" if self.language == "ru" else "Protection",
            "Дополнительно" if self.language == "ru" else "Advanced",
        ]):
            active = index == 0
            tk.Label(
                tabs,
                text=label,
                bg=THEME["accent_soft"] if active else THEME["surface"],
                fg=THEME["accent"] if active else THEME["muted"],
                font=("Segoe UI Semibold", 9),
                padx=18,
                pady=11,
            ).pack(side="left", padx=(1 if index == 0 else 0, 0), pady=1)

        grid = tk.Frame(body, bg=THEME["bg"])
        grid.pack(fill="both", expand=True)
        grid.grid_columnconfigure(0, weight=3, uniform="settings")
        grid.grid_columnconfigure(1, weight=2, uniform="settings")

        left = tk.Frame(grid, bg=THEME["bg"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        right = tk.Frame(grid, bg=THEME["bg"])
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        appearance = tk.Frame(
            left,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        appearance.pack(fill="x", pady=(0, 12))
        tk.Label(
            appearance,
            text="Внешний вид и язык" if self.language == "ru" else "Appearance and language",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=18, pady=(17, 3))
        tk.Label(
            appearance,
            text="Настройте оформление AntiOS под систему и рабочее окружение."
                 if self.language == "ru" else
                 "Match AntiOS to your system and workspace.",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=18, pady=(0, 14))

        appearance_grid = tk.Frame(appearance, bg=THEME["surface"])
        appearance_grid.pack(fill="x", padx=18, pady=(0, 18))
        appearance_grid.grid_columnconfigure(0, weight=1)
        appearance_grid.grid_columnconfigure(1, weight=1)

        auto_language = self.t("settings.language.auto")
        self.language_display_to_code = {auto_language: "auto"}
        self.language_display_to_code.update({label: code for code, label in LANGUAGE_NAMES.items()})
        language_value = auto_language if self.language_setting == "auto" else LANGUAGE_NAMES.get(self.language_setting, auto_language)
        self.language_var = tk.StringVar(value=language_value)

        lang_group = tk.Frame(appearance_grid, bg=THEME["surface"])
        lang_group.grid(row=0, column=0, sticky="ew", padx=(0, 7))
        tk.Label(
            lang_group,
            text=self.t("settings.language"),
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", pady=(0, 6))
        self.language_combo = self.ttk.Combobox(
            lang_group,
            textvariable=self.language_var,
            values=list(self.language_display_to_code),
            state="readonly",
            style="AntiOS.TCombobox",
        )
        self.language_combo.pack(fill="x")
        self.language_combo.bind("<<ComboboxSelected>>", self._on_language_selected)

        self.theme_display_to_code = {
            self.t("settings.theme.system"): "system",
            self.t("settings.theme.dark"): "dark",
            self.t("settings.theme.light"): "light",
        }
        theme_code_to_display = {code: label for label, code in self.theme_display_to_code.items()}
        self.theme_var = tk.StringVar(
            value=theme_code_to_display.get(self.theme_mode, self.t("settings.theme.system"))
        )
        theme_group = tk.Frame(appearance_grid, bg=THEME["surface"])
        theme_group.grid(row=0, column=1, sticky="ew", padx=(7, 0))
        tk.Label(
            theme_group,
            text=self.t("settings.theme"),
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", pady=(0, 6))
        self.theme_combo = self.ttk.Combobox(
            theme_group,
            textvariable=self.theme_var,
            values=list(self.theme_display_to_code),
            state="readonly",
            style="AntiOS.TCombobox",
        )
        self.theme_combo.pack(fill="x")
        self.theme_combo.bind("<<ComboboxSelected>>", self._on_theme_selected)

        protection = tk.Frame(
            left,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        protection.pack(fill="x", pady=(0, 12))
        tk.Label(
            protection,
            text="Запуск защиты" if self.language == "ru" else "Protection startup",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=18, pady=(17, 3))
        tk.Label(
            protection,
            text="Резидентная защита запускается вместе с Windows и восстанавливается автоматически."
                 if self.language == "ru" else
                 "Resident protection starts with Windows and self-heals when possible.",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
            wraplength=600,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 12))
        protection_row = tk.Frame(protection, bg=THEME["surface_alt"])
        protection_row.pack(fill="x", padx=18, pady=(0, 18))
        tk.Label(
            protection_row,
            text="●",
            bg=THEME["surface_alt"],
            fg=THEME["accent"] if self.config.protection.resident_enabled else THEME["muted_2"],
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=(12, 8), pady=12)
        tk.Label(
            protection_row,
            text=("Автозапуск Resident Guard включён" if self.config.protection.resident_enabled
                  else "Автозапуск Resident Guard выключен")
                 if self.language == "ru" else
                 ("Resident Guard auto-start is enabled" if self.config.protection.resident_enabled
                  else "Resident Guard auto-start is disabled"),
            bg=THEME["surface_alt"],
            fg=THEME["text"],
            font=("Segoe UI Semibold", 9),
        ).pack(side="left", fill="x", expand=True)
        self._button(
            protection_row,
            self.t("button.open"),
            lambda: self.show_page("antivirus"),
            kind="ghost",
        ).pack(side="right", padx=10, pady=6)

        control_center_row = tk.Frame(protection, bg=THEME["surface_alt"])
        control_center_row.pack(fill="x", padx=18, pady=(0, 18))
        self.start_with_windows_var = tk.BooleanVar(
            value=self.config.ui.start_with_windows
        )
        self.start_with_windows_check = tk.Checkbutton(
            control_center_row,
            text=(
                "Запускать AntiOS вместе с Windows (в трей)"
                if self.language == "ru"
                else "Start AntiOS with Windows (notification area)"
            ),
            variable=self.start_with_windows_var,
            command=self._save_dashboard_startup_preference,
            bg=THEME["surface_alt"],
            fg=THEME["text"],
            activebackground=THEME["surface_alt"],
            activeforeground=THEME["text"],
            selectcolor=THEME["surface_alt"],
            highlightthickness=0,
            bd=0,
            font=("Segoe UI Semibold", 9),
        )
        self.start_with_windows_check.pack(
            side="left", fill="x", expand=True, padx=10, pady=10
        )
        self.dashboard_startup_status = tk.Label(
            control_center_row,
            text="",
            bg=THEME["surface_alt"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
        )
        self.dashboard_startup_status.pack(side="right", padx=(8, 12))

        cleanup = tk.Frame(
            left,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        cleanup.pack(fill="x")
        tk.Label(
            cleanup,
            text=self.t("settings.cleanup.title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=18, pady=(17, 3))
        tk.Label(
            cleanup,
            text=self.t("settings.cleanup.subtitle"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=18, pady=(0, 14))

        cleanup_grid = tk.Frame(cleanup, bg=THEME["surface"])
        cleanup_grid.pack(fill="x", padx=18)
        for column in range(3):
            cleanup_grid.grid_columnconfigure(column, weight=1, uniform="cleanup")

        self.cleanup_old_days_var = tk.StringVar(value=str(self.config.cleanup.old_days))
        self.cleanup_large_mb_var = tk.StringVar(value=str(self.config.cleanup.large_mb))
        self.cleanup_duplicate_min_var = tk.StringVar(value=str(self.config.cleanup.duplicate_min_mb))
        for column, (label, variable) in enumerate([
            (self.t("settings.cleanup.old_days"), self.cleanup_old_days_var),
            (self.t("settings.cleanup.large_mb"), self.cleanup_large_mb_var),
            (self.t("settings.cleanup.duplicate_min_mb"), self.cleanup_duplicate_min_var),
        ]):
            group = tk.Frame(cleanup_grid, bg=THEME["surface"])
            group.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 6, 0 if column == 2 else 6))
            tk.Label(
                group,
                text=label,
                bg=THEME["surface"],
                fg=THEME["muted_2"],
                font=("Segoe UI Semibold", 8),
            ).pack(anchor="w", pady=(0, 6))
            spin = tk.Spinbox(
                group,
                from_=1,
                to=1000000,
                textvariable=variable,
                bg=THEME["surface_alt"],
                fg=THEME["text"],
                buttonbackground=THEME["surface_alt"],
                insertbackground=THEME["text"],
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground=THEME["border"],
                highlightcolor=THEME["accent"],
                font=("Segoe UI", 10),
            )
            spin.pack(fill="x", ipady=7)

        self.cleanup_remember_var = tk.BooleanVar(value=self.config.cleanup.remember_folder)
        tk.Checkbutton(
            cleanup,
            text=self.t("settings.cleanup.remember_folder"),
            variable=self.cleanup_remember_var,
            bg=THEME["surface"],
            fg=THEME["text"],
            activebackground=THEME["surface"],
            activeforeground=THEME["text"],
            selectcolor=THEME["surface_alt"],
            highlightthickness=0,
            bd=0,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=18, pady=(14, 10))

        cleanup_actions = tk.Frame(cleanup, bg=THEME["surface"])
        cleanup_actions.pack(fill="x", padx=18, pady=(0, 18))
        self._button(cleanup_actions, self.t("settings.save"), self._save_cleanup_settings, kind="primary").pack(side="left")
        self._button(cleanup_actions, self.t("settings.reset"), self._reset_settings, kind="secondary").pack(side="left", padx=(8, 0))
        self.settings_status = tk.Label(
            cleanup_actions,
            text="",
            bg=THEME["surface"],
            fg=THEME["ok"],
            font=("Segoe UI", 8),
        )
        self.settings_status.pack(side="left", padx=(12, 0))

        updates = tk.Frame(
            right,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        updates.pack(fill="x", pady=(0, 12))
        tk.Label(
            updates,
            text=self.t("settings.updates.title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=18, pady=(17, 3))
        tk.Label(
            updates,
            text="Безопасная проверка релизов GitHub, контроль хэша и подписи установщика."
                 if self.language == "ru" else
                 "Safe GitHub release checks with hash and installer signature validation.",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
            wraplength=420,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 14))

        update_summary = tk.Frame(updates, bg=THEME["accent_soft"])
        update_summary.pack(fill="x", padx=18, pady=(0, 14))
        tk.Label(
            update_summary,
            text="✓",
            bg=THEME["accent_soft"],
            fg=THEME["accent"],
            font=("Segoe UI", 17, "bold"),
        ).pack(side="left", padx=(12, 10), pady=12)
        update_summary_text = tk.Frame(update_summary, bg=THEME["accent_soft"])
        update_summary_text.pack(side="left", fill="x", expand=True, pady=10)
        tk.Label(
            update_summary_text,
            text=f"AntiOS {__version__}",
            bg=THEME["accent_soft"],
            fg=THEME["text"],
            font=("Segoe UI Semibold", 10),
        ).pack(anchor="w")
        tk.Label(
            update_summary_text,
            text="Канал Alpha" if self.language == "ru" else "Alpha channel",
            bg=THEME["accent_soft"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(2, 0))

        self.update_auto_var = tk.BooleanVar(value=self.config.updates.auto_update)
        tk.Checkbutton(
            updates,
            text=self.t("settings.updates.auto"),
            variable=self.update_auto_var,
            command=self._save_update_preference,
            bg=THEME["surface"],
            fg=THEME["text"],
            activebackground=THEME["surface"],
            activeforeground=THEME["text"],
            selectcolor=THEME["surface_alt"],
            bd=0,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=18, pady=(0, 12))

        update_actions = tk.Frame(updates, bg=THEME["surface"])
        update_actions.pack(fill="x", padx=18, pady=(0, 10))
        self._button(update_actions, self.t("settings.updates.check"), self._check_updates_now, kind="primary").pack(side="left")
        self._button(update_actions, self.t("settings.updates.download"), self._download_update_now, kind="secondary").pack(side="left", padx=(8, 0))
        self.install_update_button = self._button(
            update_actions, self.t("settings.updates.install"),
            self._install_update_now, kind="secondary"
        )
        self.install_update_button.configure(state="disabled")
        self.install_update_button.pack(side="left", padx=(8, 0))
        self._button(
            update_actions,
            "Открыть папку" if self.language == "ru" else "Open folder",
            self._open_update_folder,
            kind="ghost",
        ).pack(side="left", padx=(8, 0))

        self.update_status = tk.Label(
            updates,
            text=self.t("settings.updates.current", version=__version__),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
            wraplength=420,
            justify="left",
        )
        self.update_status.pack(anchor="w", padx=18, pady=(0, 18))

        about = tk.Frame(
            right,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        about.pack(fill="x")
        tk.Label(
            about,
            text=self.t("settings.about.title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=18, pady=(17, 3))
        tk.Label(
            about,
            text=f"AntiOS {__version__}\nDargonITP · Apache-2.0\nWindows 10 22H2 x64 и Windows 11",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 14))
        about_actions = tk.Frame(about, bg=THEME["surface"])
        about_actions.pack(fill="x", padx=18, pady=(0, 18))
        self._button(about_actions, "GitHub", lambda: _open_url(PROJECT_URL), kind="secondary").pack(side="left")
        self._button(about_actions, self.t("sidebar.privacy"), lambda: _open_url(PRIVACY_URL), kind="ghost").pack(side="left", padx=(8, 0))

    def _persist_config(self) -> bool:
        try:
            save_config(self.config, self.config_path)
            return True
        except OSError:
            return False

    def _rebuild_ui(self, active_page: str | None = None) -> None:
        existing = self.data
        target_page = active_page or self.active_page
        self._storage_cancel.set()
        diagnostics_open = False
        previous_console = getattr(self, "_diagnostics_window", None)
        if previous_console is not None:
            try:
                diagnostics_open = bool(previous_console.win.winfo_exists())
                if diagnostics_open:
                    previous_console.close()
            except Exception:
                pass

        for child in self.root.winfo_children():
            child.destroy()

        self.pages = {}
        self.nav_buttons = {}
        self._check_rows = []

        self._configure_root()
        self._configure_ttk()
        self._build_shell()
        self._build_pages()
        self.show_page(target_page)
        if diagnostics_open:
            self.open_diagnostics()

        if existing:
            localized = {
                "scan": existing["scan"],
                "health": existing["health"],
                "evaluation": evaluate_health(
                    existing["scan"],
                    existing["health"],
                    language=self.language,
                ),
            }
            self._render(localized)

    def _save_cleanup_settings(self) -> None:
        try:
            old_days = int(self.cleanup_old_days_var.get())
            large_mb = int(self.cleanup_large_mb_var.get())
            duplicate_min_mb = int(self.cleanup_duplicate_min_var.get())
            if min(old_days, large_mb, duplicate_min_mb) < 1:
                raise ValueError
        except (TypeError, ValueError):
            self.settings_status.configure(
                text=self.t("settings.invalid_number"),
                fg=THEME["warn"],
            )
            return

        remember = bool(self.cleanup_remember_var.get())
        last_path = str(self.storage_path) if remember else ""
        cleanup = CleanupConfig(
            old_days=old_days,
            large_mb=large_mb,
            duplicate_min_mb=duplicate_min_mb,
            remember_folder=remember,
            last_path=last_path,
        )
        self.config = replace(self.config, cleanup=cleanup)
        if self._persist_config():
            self.settings_status.configure(
                text=self.t("settings.saved"),
                fg=THEME["ok"],
            )
        else:
            self.settings_status.configure(
                text=self.t("settings.status.save_failed"),
                fg=THEME["warn"],
            )

    def _reset_settings(self) -> None:
        from tkinter import messagebox

        if not messagebox.askyesno(
            "AntiOS",
            self.t("settings.reset.confirm"),
        ):
            return

        self.config = replace(
            self.config,
            ui=UIConfig(),
            cleanup=CleanupConfig(),
        )
        self.language_setting = self.config.ui.language
        self.language = normalize_language(detect_language())
        self.tr = Translator(self.language)
        self.theme_mode = self.config.ui.theme
        self.resolved_theme = _apply_theme_palette(self.theme_mode)
        self.storage_path = default_scan_path()
        self._persist_config()
        self._rebuild_ui("settings")
        if hasattr(self, "settings_status"):
            self.settings_status.configure(
                text=self.t("settings.reset.done"),
                fg=THEME["ok"],
            )


    def _create_nav_button(self, key: str, text: str, parent: Any | None = None) -> None:
        host = parent or self.sidebar
        holder = self.tk.Frame(host, bg=THEME["sidebar"])
        holder.pack(fill="x", pady=2)
        stripe = self.tk.Frame(holder, bg=THEME["sidebar"], width=3)
        stripe.pack(side="left", fill="y")
        stripe.pack_propagate(False)

        button = self.tk.Button(
            holder,
            text=text,
            command=lambda: self.show_page(key),
            anchor="w",
            padx=14,
            pady=12,
            bg=THEME["sidebar"],
            fg=THEME["muted"],
            activebackground=THEME["surface_hover"],
            activeforeground=THEME["text"],
            bd=0,
            relief="flat",
            cursor="hand2",
            font=("Segoe UI Semibold", 10),
        )
        button.pack(side="left", fill="x", expand=True)
        button.bind(
            "<Enter>",
            lambda _event, widget=button, nav_key=key: (
                widget.configure(bg=THEME["surface_hover"])
                if self.active_page != nav_key else None
            ),
        )
        button.bind(
            "<Leave>",
            lambda _event, widget=button, nav_key=key: (
                widget.configure(
                    bg=THEME["accent_soft"] if self.active_page == nav_key else THEME["sidebar"]
                )
            ),
        )
        self.nav_buttons[key] = button
        self.nav_frames[key] = (holder, stripe)


    def _button(
        self,
        parent: Any,
        text: str,
        command: Callable[[], Any],
        *,
        kind: str = "secondary",
    ) -> Any:
        if kind == "primary":
            bg = THEME["accent"]
            fg = THEME["accent_text"]
            active_bg = THEME["accent_hover"]
            border = THEME["accent"]
        elif kind == "danger":
            bg = THEME["warn"]
            fg = "#FFFFFF"
            active_bg = "#FA7B87"
            border = THEME["warn"]
        elif kind == "ghost":
            bg = THEME["surface"]
            fg = THEME["info"]
            active_bg = THEME["surface_hover"]
            border = THEME["surface"]
        else:
            bg = THEME["surface_alt"]
            fg = THEME["text"]
            active_bg = THEME["surface_hover"]
            border = THEME["border"]

        button = self.tk.Button(
            parent,
            text=text,
            command=command,
            padx=16,
            pady=9,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            disabledforeground=THEME["muted_2"],
            bd=0,
            relief="flat",
            highlightthickness=1 if kind != "ghost" else 0,
            highlightbackground=border,
            highlightcolor=border,
            cursor="hand2",
            takefocus=True,
            font=("Segoe UI Semibold", 9),
        )
        button.bind(
            "<Enter>",
            lambda _event, widget=button, color=active_bg: (
                widget.configure(bg=color)
                if str(widget.cget("state")) != "disabled" else None
            ),
        )
        button.bind(
            "<Leave>",
            lambda _event, widget=button, color=bg: (
                widget.configure(bg=color)
                if str(widget.cget("state")) != "disabled" else None
            ),
        )
        return button


    def _overview_status_row(self, parent: Any, icon: str, title: str, status: str) -> Any:
        row = self.tk.Frame(parent, bg=THEME["surface"])
        row.pack(fill="x", padx=16, pady=0)
        self.tk.Label(
            row,
            text=icon,
            bg=THEME["surface"],
            fg=THEME["info"],
            font=("Segoe UI", 12, "bold"),
            width=2,
        ).pack(side="left", pady=11)
        text = self.tk.Frame(row, bg=THEME["surface"])
        text.pack(side="left", fill="x", expand=True, padx=(8, 8), pady=9)
        self.tk.Label(
            text,
            text=title,
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI Semibold", 9),
        ).pack(anchor="w")
        value = self.tk.Label(
            text,
            text=status,
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
        )
        value.pack(anchor="w", pady=(2, 0))
        self.tk.Frame(parent, bg=THEME["border_soft"], height=1).pack(fill="x", padx=16)
        return value

    def _text_link(
        self,
        parent: Any,
        text: str,
        command: Callable[[], Any],
    ) -> Any:
        return self.tk.Button(
            parent,
            text=text,
            command=command,
            bg=THEME["sidebar"],
            fg=THEME["muted"],
            activebackground=THEME["sidebar"],
            activeforeground=THEME["text"],
            bd=0,
            relief="flat",
            cursor="hand2",
            font=("Segoe UI", 8),
        )


    def _metric_card(
        self,
        parent: Any,
        title: str,
        subtitle: str,
        *,
        multiline: bool = False,
    ) -> dict[str, Any]:
        tk = self.tk
        frame = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        header = tk.Frame(frame, bg=THEME["surface"])
        header.pack(fill="x", padx=18, pady=(16, 6))
        tk.Label(
            header,
            text=title,
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI Semibold", 11),
        ).pack(anchor="w")
        tk.Label(
            header,
            text=subtitle,
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(3, 0))
        value = tk.Label(
            frame,
            text="Checking…",
            justify="left",
            anchor="nw",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 16 if not multiline else 10, "bold" if not multiline else "normal"),
        )
        value.pack(fill="both", expand=True, padx=18, pady=(8, 5))
        detail = tk.Label(
            frame,
            text="",
            justify="left",
            anchor="nw",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 8),
            wraplength=360,
        )
        detail.pack(fill="x", padx=18, pady=(0, 16))
        return {"frame": frame, "value": value, "detail": detail}

    def _status_card(
        self,
        parent: Any,
        check: dict[str, Any],
    ) -> Any:
        tk = self.tk
        level = str(check.get("level") or "info")
        _fallback_label, color, badge_bg = STATUS_STYLE.get(
            level,
            STATUS_STYLE["info"],
        )
        status_key = "advisory" if level == "advisory" else level
        label = self.t(f"status.{status_key}")

        card = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )

        stripe = tk.Frame(card, bg=color, width=4)
        stripe.pack(side="left", fill="y")
        stripe.pack_propagate(False)

        body = tk.Frame(card, bg=THEME["surface"])
        body.pack(side="left", fill="both", expand=True, padx=16, pady=14)

        top = tk.Frame(body, bg=THEME["surface"])
        top.pack(fill="x")

        badge = tk.Label(
            top,
            text=label,
            bg=badge_bg,
            fg=color,
            padx=8,
            pady=3,
            font=("Segoe UI Semibold", 8),
        )
        badge.pack(side="left")

        tk.Label(
            top,
            text=str(check.get("title") or "Check"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left", padx=(10, 0))

        detail = tk.Label(
            body,
            text=str(check.get("detail") or ""),
            justify="left",
            anchor="w",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
            wraplength=650,
        )
        detail.pack(fill="x", pady=(9, 0))

        action = check.get("action")
        if action:
            tk.Label(
                body,
                text=str(action),
                justify="left",
                anchor="w",
                bg=THEME["surface"],
                fg=THEME["muted_2"],
                font=("Segoe UI", 9),
                wraplength=650,
            ).pack(fill="x", pady=(5, 0))

        uri = check.get("settings_uri")
        if uri:
            self._button(
                card,
                self.t("button.open"),
                lambda u=str(uri): _open_settings(u),
                kind="secondary",
            ).pack(side="right", padx=14, pady=14)

        return card

    def _on_language_selected(self, _event: Any = None) -> None:
        selected = self.language_var.get()
        setting = self.language_display_to_code.get(selected)
        if not setting or setting == self.language_setting:
            return

        self.language_setting = setting
        self.language = normalize_language(
            detect_language() if setting == "auto" else setting
        )
        self.tr = Translator(self.language)
        self.config = replace(
            self.config,
            ui=UIConfig(
                language=self.language_setting,
                theme=self.theme_mode,
                start_with_windows=self.config.ui.start_with_windows,
            ),
        )
        self._persist_config()
        self._rebuild_ui("settings")

    def _on_theme_selected(self, _event: Any = None) -> None:
        selected = self.theme_var.get()
        mode = self.theme_display_to_code.get(selected)
        if not mode or mode == self.theme_mode:
            return

        self.theme_mode = mode
        self.resolved_theme = _apply_theme_palette(mode)
        self.config = replace(
            self.config,
            ui=UIConfig(
                language=self.language_setting,
                theme=self.theme_mode,
                start_with_windows=self.config.ui.start_with_windows,
            ),
        )
        self._persist_config()
        self._rebuild_ui("settings")


    def show_page(self, name: str) -> None:
        if name not in self.pages:
            return

        titles = {
            "overview": (self.t("nav.overview"), self.t("page.overview.subtitle")),
            "security": (self.t("nav.security"), self.t("page.security.subtitle")),
            "antivirus": (self.t("nav.antivirus"), self.t("av.subtitle")),
            "startup": (self.t("nav.startup"), self.t("page.startup.subtitle")),
            "system": (self.t("nav.system"), self.t("page.system.subtitle")),
            "cleanup": (self.t("nav.cleanup"), self.t("page.cleanup.subtitle")),
            "settings": (self.t("nav.settings"), self.t("page.settings.subtitle")),
        }
        self.active_page = name
        self.pages[name].tkraise()
        title, subtitle = titles[name]
        self.page_title.configure(text=title)
        self.page_subtitle.configure(text=subtitle)

        if name in {"antivirus", "cleanup", "settings"}:
            self.export_button.pack_forget()
            self.refresh_button.pack_forget()
        else:
            if not self.export_button.winfo_manager():
                self.export_button.pack(side="left", padx=(0, 8))
            if not self.refresh_button.winfo_manager():
                self.refresh_button.pack(side="left")

        for key, button in self.nav_buttons.items():
            selected = key == name
            button.configure(
                bg=THEME["accent_soft"] if selected else THEME["sidebar"],
                fg=THEME["accent"] if selected else THEME["muted"],
            )
            holder, stripe = self.nav_frames.get(key, (None, None))
            if holder is not None:
                holder.configure(bg=THEME["accent_soft"] if selected else THEME["sidebar"])
            if stripe is not None:
                stripe.configure(bg=THEME["accent"] if selected else THEME["sidebar"])

        if hasattr(self, "settings_button"):
            selected = name == "settings"
            self.settings_button.configure(
                bg=THEME["accent_soft"] if selected else THEME["sidebar"],
                fg=THEME["accent"] if selected else THEME["muted"],
            )

    def refresh(self) -> None:
        self.refresh_button.configure(
            state="disabled",
            text=self.t("button.checking"),
        )
        self.hero_kicker.configure(
            text=self.t("overview.checking_kicker"),
            fg=THEME["accent"],
        )
        self.status_title.configure(
            text=self.t("overview.checking_title")
        )
        self.status_summary.configure(
            text=self.t("overview.checking_detail")
        )
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self) -> None:
        try:
            data = collect_dashboard_data(self.language)
        except Exception as exc:
            self.root.after(0, lambda message=str(exc): self._show_error(message))
            return
        self.root.after(0, lambda: self._render(data))

    def _show_error(self, message: str) -> None:
        record_event("UI", "ERROR", message,
                     code=classify_error(message, component="UI"),
                     context={"operation": "dashboard-refresh"})
        self.refresh_button.configure(
            state="normal",
            text=f"↻  {self.t('button.refresh')}",
        )
        self.hero_kicker.configure(
            text=self.t("overview.check_failed"),
            fg=THEME["warn"],
        )
        self.status_title.configure(
            text=self.t("error.failed_title")
        )
        self.status_summary.configure(text=message)

    def _render(self, data: dict[str, Any]) -> None:
        self.data = data
        self.refresh_button.configure(
            state="normal",
            text=self.t("button.refresh"),
        )

        evaluation = data["evaluation"]
        health = data["health"]
        scan_data = data["scan"]

        overall = evaluation.get("overall")
        if overall == "needs-attention":
            kicker = (self.t("overview.needs_attention"), THEME["warn"])
        elif overall == "review":
            kicker = (self.t("overview.review"), THEME["review"])
        else:
            kicker = (self.t("overview.all_clear"), THEME["ok"])

        self.hero_kicker.configure(text=kicker[0], fg=kicker[1])
        self.status_title.configure(
            text=evaluation.get("headline", "Check complete")
        )

        summary = evaluation.get("summary", {})
        self.status_summary.configure(
            text=self.t(
                "overview.completed",
                count=summary.get("info", 0),
            )
        )
        for key, widget in self.summary_chips.items():
            widget.configure(text=str(summary.get(key, 0)))

        for row in self._check_rows:
            row.destroy()
        self._check_rows.clear()

        for check in evaluation.get("checks", []):
            card = self._status_card(self.check_scroll.inner, check)
            card.pack(fill="x", pady=(0, 10))
            self._check_rows.append(card)

        self._render_security(scan_data, health)
        self.antivirus_panel.render_provider_status(health)
        self._render_startup(health)
        self._render_system(scan_data, health)

    def _render_security(
        self,
        scan_data: dict[str, Any],
        health: dict[str, Any],
    ) -> None:
        security = scan_data.get("system", {}).get("security", {})
        defender = health.get("defender", {})
        bitlocker = health.get("bitlocker", {})

        defender_enabled = defender.get("antivirus_enabled")
        realtime = defender.get("real_time_protection")
        defender_value = (
            self.t("security.protected")
            if defender_enabled is True and realtime is True
            else self.t("security.needs_review")
            if defender.get("available")
            else self.t("security.unavailable")
        )
        defender_detail = self.t(
            "security.defender.detail",
            antivirus=_friendly_bool(defender_enabled, self.tr),
            realtime=_friendly_bool(realtime, self.tr),
            age=defender.get("signature_age_days", self.t("value.unknown")),
        )

        self.security_cards["defender"]["value"].configure(
            text=defender_value,
            fg=THEME["ok"]
            if defender_enabled is True and realtime is True
            else THEME["review"],
        )
        self.security_cards["defender"]["detail"].configure(text=defender_detail)

        protection = bitlocker.get("protection_status")
        encryption = bitlocker.get("encryption_percentage")
        self.security_cards["encryption"]["value"].configure(
            text=str(protection or "Unavailable"),
            fg=THEME["ok"] if str(protection).lower() == "on" else THEME["review"],
        )
        self.security_cards["encryption"]["detail"].configure(
            text=self.t(
                "security.encryption.detail",
                percent=encryption
                if encryption is not None
                else self.t("value.unknown"),
            )
        )

        secure_boot = security.get("secure_boot", {}).get("enabled")
        self.security_cards["secure_boot"]["value"].configure(
            text=_friendly_bool(secure_boot, self.tr),
            fg=THEME["ok"] if secure_boot is True else THEME["review"],
        )
        self.security_cards["secure_boot"]["detail"].configure(
            text=self.t("security.secure_boot.detail")
        )

        tpm = security.get("tpm", {})
        tpm_ready = tpm.get("ready")
        tpm_present = tpm.get("present")
        tpm_value = (
            self.t("security.tpm.ready")
            if tpm_present is True and tpm_ready is True
            else self.t("security.tpm.present_not_ready")
            if tpm_present is True
            else self.t("security.tpm.not_detected")
            if tpm_present is False
            else self.t("security.tpm.unknown")
        )
        self.security_cards["tpm"]["value"].configure(
            text=tpm_value,
            fg=THEME["ok"]
            if tpm_present is True and tpm_ready is True
            else THEME["review"],
        )
        self.security_cards["tpm"]["detail"].configure(
            text=self.t("security.tpm.detail")
        )

    def _render_startup(self, health: dict[str, Any]) -> None:
        startup = health.get("startup", {})
        count = startup.get("count")
        self.startup_count.configure(
            text=str(count) if isinstance(count, int) else "—"
        )

        for item in self.startup_tree.get_children():
            self.startup_tree.delete(item)

        for index, entry in enumerate(startup.get("entries", [])):
            tag = "even" if index % 2 == 0 else "odd"
            self.startup_tree.insert(
                "",
                "end",
                values=(
                    entry.get("name") or "(unnamed)",
                    entry.get("location") or "",
                    entry.get("user") or "",
                ),
                tags=(tag,),
            )

        self.startup_tree.tag_configure("even", background=THEME["surface"])
        self.startup_tree.tag_configure("odd", background=THEME["surface_alt"])

    def _render_system(
        self,
        scan_data: dict[str, Any],
        health: dict[str, Any],
    ) -> None:
        system = scan_data.get("system", {})
        win = system.get("windows", {})
        host = system.get("host", {})
        storage = health.get("storage", {})
        uptime = health.get("uptime", {})
        reboot = health.get("pending_reboot", {})

        self.system_cards["windows"]["value"].configure(
            text=self.t(
                "system.windows.value",
                generation=win.get("generation") or self.t("value.windows"),
                edition=win.get("edition_id") or self.t("value.edition_unknown"),
                version=win.get("display_version") or self.t("value.unknown"),
                build=win.get("full_build") or self.t("value.unknown"),
            )
        )
        self.system_cards["windows"]["detail"].configure(
            text=self.t("system.windows.detail")
        )

        self.system_cards["computer"]["value"].configure(
            text=self.t(
                "system.computer.value",
                name=host.get("computer_name") or self.t("value.computer_unknown"),
                architecture=host.get("architecture") or self.t("value.arch_unknown"),
                processor=host.get("processor") or self.t("value.processor_unknown"),
            )
        )
        self.system_cards["computer"]["detail"].configure(
            text=self.t("system.computer.detail")
        )

        free = _format_bytes(storage.get("free_bytes"), self.tr)
        total = _format_bytes(storage.get("total_bytes"), self.tr)
        percent = storage.get("percent_free")
        self.system_cards["storage"]["value"].configure(
            text=self.t(
                "system.storage.value",
                free=free,
                total=total,
                percent=percent
                if percent is not None
                else self.t("value.unknown"),
            )
        )
        self.system_cards["storage"]["detail"].configure(
            text=self.t("system.storage.detail")
        )

        self.system_cards["session"]["value"].configure(
            text=self.t(
                "system.session.value",
                days=uptime.get("days", self.t("value.unknown")),
                pending=_friendly_bool(reboot.get("pending"), self.tr),
            )
        )
        self.system_cards["session"]["detail"].configure(
            text=self.t("system.session.detail")
        )

    def export_report(self) -> None:
        from tkinter import filedialog, messagebox

        if not self.data:
            messagebox.showinfo("AntiOS", self.t("export.no_data"))
            return

        target = filedialog.asksaveasfilename(
            title=self.t("export.title"),
            defaultextension=".json",
            filetypes=[(self.t("export.filetype"), "*.json")],
            initialfile="antios-report.json",
        )
        if not target:
            return

        payload = dict(self.data)
        if self.storage_result is not None:
            payload["storage_cleanup"] = self.storage_result
        if self.antivirus_result is not None:
            payload["antivirus"] = self.antivirus_result

        Path(target).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        messagebox.showinfo(
            "AntiOS",
            self.t("export.saved", path=target),
        )


def launch(language: str | None = None, *, background: bool = False) -> int:
    if sys.platform.startswith("linux"):
        from .linux_dashboard import launch as launch_linux
        return launch_linux(language, background=background)
    tr = Translator(normalize_language(language or detect_language()))
    if not is_windows():
        raise RuntimeError(tr.t("error.dashboard_windows"))

    import tkinter as tk

    if os.name == "nt":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        _configure_windows_identity()

    root = tk.Tk()
    if background:
        root.withdraw()
    _apply_window_icon(root, "not-running")
    dashboard = Dashboard(root, language=language)
    if background and (
        dashboard._dashboard_tray is None
        or not dashboard._dashboard_tray.running
    ):
        root.deiconify()
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AntiOS Antivirus Companion & Diagnostics Dashboard"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate dashboard imports without opening a window.",
    )
    parser.add_argument(
        "--ui-self-test",
        action="store_true",
        help="Build the platform GUI without starting background services, then exit.",
    )
    parser.add_argument(
        "--lang",
        choices=list(LANGUAGE_NAMES),
        help="UI language: en, ru, es, zh-CN, fi, pl, mn. Defaults to Windows locale.",
    )
    parser.add_argument(
        "--background",
        action="store_true",
        help="Start the AntiOS Control Center in the notification area.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        assert "bg" in THEME and "ok" in STATUS_STYLE
        if sys.platform.startswith("linux"):
            from .linux_dashboard import validate_runtime
            validate_runtime()
        return 0
    if args.ui_self_test:
        if sys.platform.startswith("linux"):
            from .linux_dashboard import launch as launch_linux
            return launch_linux(args.lang, self_test=True)
        if not is_windows():
            return 0
        import tkinter as tk

        _configure_windows_identity()
        root = tk.Tk()
        root.withdraw()
        _apply_window_icon(root, "not-running")
        dashboard = Dashboard(
            root,
            language=args.lang,
            auto_refresh=False,
            tray_enabled=False,
            background_services=False,
        )
        dashboard.show_page("settings")
        root.update_idletasks()
        dashboard.show_page("antivirus")
        root.update_idletasks()
        root.destroy()
        return 0
    # The control center is an asInvoker application: monitoring, quarantine
    # and ordinary diagnostics must use the *interactive user's* identity.
    # Privileged service repair is requested only after explicit user action.
    return launch(args.lang, background=args.background)
