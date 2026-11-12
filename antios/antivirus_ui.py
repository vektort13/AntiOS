"""Modern Antivirus page.

The primary surface is intentionally consumer-facing: protection state, scanning,
Resident Guard, results and quarantine. Engine/provider controls live under the
collapsed advanced section instead of competing with the main actions.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable

from .antivirus import DEFAULT_SCAN_PROFILE, MAX_SCAN_WORKERS, SCAN_PROFILE_WORKERS
from .diagnostics import classify_error, explanation, record_event, recent_events
from .diagnostics_ui import open_diagnostics
from .quarantine import Quarantine
from .scan_process import run_scan_process
from .windows_defender import defender_action


_ACTIVE_GUARD_STATES = {
    "starting",
    "scanning",
    "monitoring",
    "degraded",
    "attention",
}
_HEALTHY_GUARD_STATES = {"monitoring", "scanning"}


def _diagnostic_changed(panel, key: str, value, *, repeat_after=None) -> bool:
    """Keep bounded probe history across panel rebuilds within one app."""
    owner = getattr(panel, "app", panel)
    cache = getattr(owner, "_protection_diagnostics", None)
    if cache is None:
        cache = owner._protection_diagnostics = {}
    now = time.monotonic()
    previous = cache.get(key)
    if (previous is not None and previous[0] == value and
            (repeat_after is None or now - previous[1] < repeat_after)):
        return False
    cache[key] = (value, now)
    return True


def _record_scan_completion(value: dict) -> None:
    """Report scan coverage/errors, never invent a child process exit code."""
    summary = value.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    record_event(
        "Scanner",
        "WARNING" if value.get("coverage") == "limited"
        or summary.get("errors") else "INFO",
        "On-demand file scan finished",
        code="SCAN_COMPLETED",
        context={
            "state": str(value.get("verdict") or "unknown"),
            "coverage": str(value.get("coverage") or "unknown"),
            "errors": str(summary.get("errors", 0)),
        },
    )


class AntivirusPanel:
    def __init__(self, app: Any, parent: Any, palette: dict) -> None:
        self.app, self.parent, self.palette = app, parent, palette
        self.rows: dict[str, dict] = {}
        self.items: dict[str, dict] = {}
        self.mode = "findings"
        self.after_id = None
        self.last_guard_probe = 0.0
        self.last_protection_probe = 0.0
        self.protection_probe_busy = False
        self.layered_active = False
        self.guard_state = "not-running"
        self.advanced_visible = False
        self.buttons: list[Any] = []
        # All user-facing scans use the independent AntiOS Engine.
        self.engine_var = self.app.tk.StringVar(value="antios")
        self.app.antivirus_engine = "antios"
        profile = getattr(app, "antivirus_scan_profile", DEFAULT_SCAN_PROFILE)
        workers = getattr(app, "antivirus_scan_workers", None)
        self.profile_labels = {name: self.t("scan_profile_" + name) for name in SCAN_PROFILE_WORKERS}
        self.scan_profile_var = app.tk.StringVar(value=self.profile_labels[profile])
        self.scan_workers_var = app.tk.StringVar(value=str(workers) if workers else self.t("scan_workers_auto"))
        self._build()
        parent.bind("<Destroy>", self._destroy, add="+")
        parent.bind("<Configure>", self._resize, add="+")
        self._render_result()
        self._render_items()
        self._set_busy()
        self._poll()

    def t(self, key: str, **values: Any) -> str:
        return self.app.t("av." + key, **values)

    def _card(self, parent: Any, *, bg: str | None = None) -> Any:
        return self.app.tk.Frame(
            parent,
            bg=bg or self.palette["surface"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            bd=0,
        )

    def _label(
        self,
        parent: Any,
        text: str,
        *,
        bg: str | None = None,
        color: str = "text",
        font: tuple | None = None,
        **kwargs: Any,
    ) -> Any:
        return self.app.tk.Label(
            parent,
            text=text,
            bg=bg or self.palette["surface"],
            fg=self.palette[color],
            anchor="w",
            justify="left",
            font=font or ("Segoe UI", 9),
            **kwargs,
        )

    def _resize(self, event: Any) -> None:
        if event.widget != self.parent or event.width <= 150:
            return
        self.scan_path_label.configure(wraplength=max(180, event.width - self.target_actions.winfo_reqwidth() - 65))
        self.status.configure(wraplength=max(180, event.width - 20))

    def _build(self) -> None:
        outer = self.parent
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(2, weight=1)
        self.hero_accent = self.app.guard_accent
        self.protection_dot = self.app.guard_dot
        self.protection_title = self.app.guard_title
        self.protection_detail = self.app.guard_detail
        self.guard_start_button = self.app.guard_control_button
        self.guard_status = self.app.guard_details
        self.engine_chip = self.app.overview_engine_status
        self.engine_component_status = self.engine_chip
        self.buttons.append(self.guard_start_button)

        self._build_scan_form(outer)
        self._build_results(outer)
        self._build_scan_options(outer)
        if self.app.data:
            self.render_provider_status(self.app.data.get("health", {}))
        self._sync_tabs()

    def _build_scan_form(self, outer: Any) -> None:
        tk = self.app.tk
        background = self.palette["surface"]
        self.scan_card = self._card(outer)
        self.scan_card.grid(row=0, column=0, sticky="ew")
        form = tk.Frame(self.scan_card, bg=background)
        form.pack(fill="x", padx=16, pady=15)
        form.grid_columnconfigure(0, weight=1)

        self._label(form, self.t("scan_target"), color="muted", font=("Segoe UI Semibold", 9)).grid(
            row=0, column=0, sticky="w")
        self.scan_path_label = self._label(form, str(self.app.antivirus_path), font=("Segoe UI", 10))
        self.scan_path_label.grid(row=1, column=0, sticky="ew", padx=(0, 14))
        self.target_actions = tk.Frame(form, bg=background)
        self.target_actions.grid(row=0, column=1, rowspan=2, sticky="e")
        targets = [("file", lambda: self._choose(False)), ("folder", lambda: self._choose(True))]
        if os.name == "nt":
            targets.append(("system_drive", self._select_system_drive))
        for index, (label, command) in enumerate(targets):
            button = self.app._button(self.target_actions, self.t(label), command)
            button.pack(side="left", padx=(5 if index else 0, 0))
            self.buttons.append(button)

        tk.Frame(form, bg=self.palette["border_soft"], height=1).grid(
            row=2, column=0, columnspan=2, sticky="ew", pady=11)

        settings = tk.Frame(form, bg=background)
        settings.grid(row=3, column=0, sticky="ew", columnspan=2)
        settings.grid_columnconfigure(2, weight=1)
        for column, label in enumerate(("scan_profile", "scan_workers")):
            self._label(settings, self.t(label), color="muted", font=("Segoe UI Semibold", 9)).grid(
                row=0, column=column, sticky="w", pady=(0, 4))
        self.scan_profile_choice = self.app.ttk.Combobox(
            settings, textvariable=self.scan_profile_var, values=tuple(self.profile_labels.values()),
            state="readonly", width=23, style="AntiOS.TCombobox",
        )
        self.scan_profile_choice.grid(row=1, column=0, sticky="w", padx=(0, 10))
        self.scan_workers_choice = self.app.ttk.Combobox(
            settings, textvariable=self.scan_workers_var, state="readonly", width=7,
            style="AntiOS.TCombobox",
            values=(self.t("scan_workers_auto"), *(str(n) for n in range(1, MAX_SCAN_WORKERS + 1))),
        )
        self.scan_workers_choice.grid(row=1, column=1, sticky="w")

        actions = tk.Frame(settings, bg=background)
        actions.grid(row=0, column=2, rowspan=2, sticky="se", padx=(12, 0))
        self.cancel_button = self.app._button(actions, self.t("stop"), self._cancel, kind="secondary")
        self.scan_button = self.app._button(actions, self.t("scan"), self._scan, kind="primary")
        self.scan_button.pack(side="left")
        self.buttons.append(self.scan_button)

        strip = tk.Frame(outer, bg=self.palette["bg"])
        strip.grid(row=1, column=0, sticky="ew", pady=(6, 10))
        self.status = self._label(strip, self.t("ready"), bg=self.palette["bg"], color="muted")
        self.status.pack(fill="x", pady=4)
        self.scan_progress = self.app.ttk.Progressbar(
            strip, orient="horizontal", mode="indeterminate", style="AntiOS.Horizontal.TProgressbar")
        self._progress_running = False

    def _build_results(self, outer: Any) -> None:
        tk = self.app.tk
        results = self._card(outer)
        results.grid(row=2, column=0, sticky="nsew")
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(1, weight=1)
        header = tk.Frame(results, bg=self.palette["surface"])
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=9)
        self.findings_tab = self.app._button(header, self.t("findings"), lambda: self._show("findings"))
        self.findings_tab.pack(side="left")
        self.vault_tab = self.app._button(header, self.t("vault"), lambda: self._show("vault"))
        self.vault_tab.pack(side="left", padx=(5, 0))

        self.filter_labels = {
            "all": self.app.t("work.filter_all"), "threat": self.app.t("work.filter_threats"),
            "review": self.app.t("work.filter_review"), "issue": self.app.t("work.filter_issues"),
        }
        self.filter_var = tk.StringVar(value=self.filter_labels["all"])
        self.filter_choice = self.app.ttk.Combobox(
            header, textvariable=self.filter_var, values=tuple(self.filter_labels.values()),
            state="readonly", style="AntiOS.TCombobox", width=20,
        )
        self.filter_choice.pack(side="right")
        self.filter_choice.bind("<<ComboboxSelected>>", lambda _event: self._render_result())
        self.results_hint = self._label(header, "", color="muted")
        self.results_hint.pack(side="right", padx=10)

        table = tk.Frame(results, bg=self.palette["surface"])
        table.grid(row=1, column=0, sticky="nsew")
        table.grid_columnconfigure(0, weight=1)
        table.grid_rowconfigure(0, weight=1)
        self.tree = self.app.ttk.Treeview(
            table, columns=("kind", "name", "path"), show="headings", height=4,
            selectmode="browse", style="AntiOS.Treeview",
        )
        for name, width in (("kind", 135), ("name", 245), ("path", 320)):
            self.tree.heading(name, text=self.t("column_" + name), anchor="w")
            self.tree.column(name, width=width, minwidth=85, stretch=name == "path")
        self.tree.tag_configure("threat", foreground=self.palette["warn"])
        self.tree.tag_configure("review", foreground=self.palette["review"])
        self.tree.tag_configure("issue", foreground=self.palette["muted"])
        vertical = self.app.ttk.Scrollbar(table, command=self.tree.yview, style="AntiOS.Vertical.TScrollbar")
        horizontal = self.app.ttk.Scrollbar(
            table, orient="horizontal", command=self.tree.xview, style="AntiOS.Horizontal.TScrollbar")
        def update_scrollbar(bar, first, last):
            bar.set(first, last)
            needed = float(first) > 0.0 or float(last) < 1.0
            visible = bool(bar.winfo_manager())
            if visible and not needed:
                bar.grid_remove()
            elif needed and not visible:
                bar.grid()

        self.tree.configure(
            yscrollcommand=lambda first, last: update_scrollbar(vertical, first, last),
            xscrollcommand=lambda first, last: update_scrollbar(horizontal, first, last),
        )
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        # Reserve both gutters so toggling one bar never changes the other
        # axis's viewport or schedules a scrollbar geometry feedback loop.
        table.grid_columnconfigure(1, minsize=vertical.winfo_reqwidth())
        table.grid_rowconfigure(1, minsize=horizontal.winfo_reqheight())
        self.empty_result = self._label(table, "", color="muted", font=("Segoe UI", 10))
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self._selection_changed())
        self.tree.bind("<Double-1>", lambda _event: self._details())
        self.tree.bind("<Return>", lambda _event: self._details())

        actions = tk.Frame(results, bg=self.palette["surface"])
        actions.grid(row=2, column=0, sticky="ew", padx=10, pady=8)
        self.details_button = self.app._button(actions, self.app.t("work.details"), self._details, kind="ghost")
        self.details_button.pack(side="left")
        self.quarantine_button = self.app._button(actions, self.t("quarantine"), self._quarantine)
        self.restore_button = self.app._button(actions, self.t("restore"), self._restore)
        self.advanced_button = self.app._button(actions, self.t("advanced"), self._toggle_advanced, kind="ghost")
        self.advanced_button.pack(side="right")
        self.incident_button = self.app._button(
            actions, self.t("incident_viewer_button"), self._incident_history, kind="ghost")
        self.incident_button.pack(side="right", padx=(0, 4))
        self.export_button = self.app._button(actions, self.t("export"), self._export, kind="ghost")
        self.export_button.pack(side="right", padx=(0, 4))
        self.buttons.append(self.incident_button)

    def _build_scan_options(self, outer: Any) -> None:
        tk = self.app.tk
        background = self.palette["surface"]
        self.advanced_frame = self._card(outer)
        panel = tk.Frame(self.advanced_frame, bg=background)
        panel.pack(fill="both", expand=True, padx=16, pady=12)
        top = tk.Frame(panel, bg=background)
        top.pack(fill="x", pady=(0, 8))
        self.app._section_title(top, self.t("advanced_title")).pack(side="left")
        self.app._button(top, self.app.t("work.close"), self._toggle_advanced, kind="ghost").pack(side="right")

        engine_row = tk.Frame(panel, bg=background)
        engine_row.pack(fill="x", pady=(0, 6))
        repair = self.app._button(engine_row, self.t("repair_protection"), self._repair_protection)
        repair.pack(side="right", padx=(6, 0))
        self.buttons.append(repair)
        self.provider_status = self._label(engine_row, self.t("managed_engine"), color="muted")
        self.provider_status.pack(side="left", fill="x", expand=True)

        signature_row = tk.Frame(panel, bg=background)
        signature_row.pack(fill="x", pady=(0, 6))
        signatures = self.app._button(signature_row, self.t("signatures"), self._choose_signatures)
        signatures.pack(side="right", padx=(6, 0))
        self.buttons.append(signatures)
        self.path_label = self._label(
            signature_row, str(self.app.antivirus_signatures) if self.app.antivirus_signatures
            else self.t("signatures_builtin"), color="muted")
        self.path_label.pack(side="left", fill="x", expand=True)

        if os.name == "nt":
            from .elevation import is_administrator
            windows = tk.Frame(panel, bg=background)
            windows.pack(fill="x", pady=(0, 6))
            for action in ("quick", "full", "update"):
                button = self.app._button(windows, self.t("defender_" + action), lambda key=action: self._defender(key))
                button.pack(side="left", padx=(0, 4))
                self.buttons.append(button)
            if not is_administrator():
                self.admin_button = self.app._button(windows, self.t("open_admin"), self._open_admin, kind="ghost")
                self.admin_button.pack(side="left")
                self.buttons.append(self.admin_button)

        last_error = tk.Frame(panel, bg=background)
        last_error.pack(fill="x")
        self.last_error_label = self._label(last_error, "", color="muted")
        self.last_error_label.pack(side="left", fill="x", expand=True)
        self.app._button(last_error, self.app.t("work.activity"), self._open_diagnostics, kind="ghost").pack(side="right")
        self._restore_diagnostic_hint()

    def _toggle_advanced(self) -> None:
        self.advanced_visible = not self.advanced_visible
        if self.advanced_visible:
            self.advanced_frame.place(
                relx=0,
                rely=1,
                anchor="sw",
                relwidth=1,
            )
            self.advanced_frame.lift()
            self.advanced_button.configure(text=self.t("advanced_hide"))
        else:
            self.advanced_frame.place_forget()
            self.advanced_button.configure(text=self.t("advanced"))

    def render_provider_status(self, _health: dict) -> None:
        # Defender is intentionally not the primary antivirus status anymore.
        if not self.app.antivirus_result:
            self.provider_status.configure(text=self.t("managed_engine"))

    def _choose(self, folder: bool) -> None:
        from tkinter import filedialog

        choose = filedialog.askdirectory if folder else filedialog.askopenfilename
        selected = choose(
            initialdir=str(
                self.app.antivirus_path.parent
                if self.app.antivirus_path.is_file()
                else self.app.antivirus_path
            )
        )
        if selected:
            self.app.antivirus_path = Path(selected)
            self.scan_path_label.configure(text=str(self.app.antivirus_path))

    def _choose_signatures(self) -> None:
        from tkinter import filedialog
        from .antivirus import load_signatures

        selected = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not selected:
            return
        try:
            load_signatures(selected)
        except (OSError, ValueError) as exc:
            self._error(str(exc))
            return
        self.app.antivirus_signatures = Path(selected)
        self.path_label.configure(text=str(selected))

    def _run(
        self,
        kind: str,
        operation: Callable,
        *,
        cancelable: bool = False,
    ) -> None:
        if self.app.antivirus_busy:
            return
        self.app.antivirus_busy = True
        self.app.antivirus_cancelable = cancelable
        self.app.antivirus_cancel.clear()
        self.status.configure(text=self.t("working"), fg=self.palette["muted"])
        self._set_busy()

        source = {
            "scan": "Scanner", "guard-action": "Protection",
            "quarantined": "Quarantine", "restored": "Quarantine",
            "defender": "Defender", "items": "Quarantine",
        }.get(kind, "UI")
        if kind not in {"items", "incident-history"}:
            record_event(source, "INFO", "Operation started: " + kind,
                         code="OPERATION_STARTED", context={"operation": kind})

        result_queue = self.app.antivirus_queue

        def worker() -> None:
            try:
                value = operation()
                if kind not in {"items", "incident-history", "scan"}:
                    record_event(source, "INFO", "Operation returned: " + kind,
                                 code="OPERATION_COMPLETED",
                                 context={"operation": kind})
                result_queue.put((kind, value))
            except Exception as exc:
                result_queue.put(("error", {
                    "message": str(exc),
                    "component": {
                        "scan": "Scanner",
                        "guard-action": "Protection",
                        "items": "Quarantine",
                        "quarantined": "Quarantine",
                        "restored": "Quarantine",
                        "defender": "Defender",
                    }.get(kind, "UI"),
                    "details": traceback.format_exc(),
                    "operation": kind,
                }))
            finally:
                result_queue.put(("idle", None))

        threading.Thread(
            target=worker,
            daemon=kind not in {"scan", "quarantined", "restored"},
        ).start()

    def _open_admin(self) -> None:
        from .elevation import open_admin_scan_center
        language = self.app.language
        self._run("admin-window", lambda: open_admin_scan_center(language))

    def _select_system_drive(self) -> None:
        path = Path(os.environ.get("SystemRoot", r"C:\Windows")).anchor
        if path:
            self.app.antivirus_path = Path(path)
            self.scan_path_label.configure(text=path)

    def _scan(self) -> None:
        path, signatures = self.app.antivirus_path, self.app.antivirus_signatures
        engine = "antios"
        self.app.antivirus_engine = engine
        selected_label = self.scan_profile_var.get()
        profile = next(name for name, label in self.profile_labels.items() if label == selected_label)
        selected_workers = self.scan_workers_var.get()
        workers = int(selected_workers) if selected_workers.isdecimal() else None
        self.app.antivirus_scan_profile = profile
        self.app.antivirus_scan_workers = workers
        cancelled = self.app.antivirus_cancel.is_set
        result_queue = self.app.antivirus_queue
        self._run(
            "scan",
            lambda: run_scan_process(
                path,
                signature_path=signatures,
                engine=engine,
                profile=profile,
                workers=workers,
                require_verified_peer=False,
                cancelled=cancelled,
                progress=lambda data: result_queue.put(("progress", data)),
            ),
            cancelable=True,
        )

    def _cancel(self) -> None:
        if self.app.antivirus_busy and self.app.antivirus_cancelable:
            self.app.antivirus_cancel.set()
            self.status.configure(text=self.t("stopping"))
            self.cancel_button.configure(state="disabled")

    def _guard_toggle(self) -> None:
        if self.guard_state in _ACTIVE_GUARD_STATES:
            self._guard_stop()
        else:
            self._guard_start()

    def _guard_start(self) -> None:
        from tkinter import messagebox

        if messagebox.askyesno("AntiOS Guard", self.t("guard_confirm")):
            self._run(
                "guard-action",
                lambda: self.app.set_resident_protection_enabled(True),
            )

    def _guard_stop(self) -> None:
        self._run(
            "guard-action",
            lambda: self.app.set_resident_protection_enabled(False),
        )

    def _incident_history(self) -> None:
        from .guard_state import read_incident_history

        self._run("incident-history", lambda: read_incident_history(limit=50))

    def _guard_history(self) -> None:
        # Compatibility alias: the old raw JSON popup is now the structured
        # Incident Viewer.
        self._incident_history()

    def _repair_protection(self) -> None:
        self._run("guard-action", self.app.repair_protection)

    def _defender(self, action: str) -> None:
        from tkinter import messagebox

        if messagebox.askyesno("AntiOS", self.t("defender_confirm")):
            self._run("defender", lambda: defender_action(action))

    def _selected(self) -> dict | None:
        selected = self.tree.selection()
        source = self.rows if self.mode == "findings" else self.items
        return source.get(selected[0]) if selected else None

    def _quarantine(self) -> None:
        from tkinter import messagebox

        finding = self._selected()
        if (
            self.mode != "findings"
            or not finding
            or finding.get("kind") != "threat"
            or finding.get("quarantined")
        ):
            return
        if messagebox.askyesno(
            "AntiOS", self.t("quarantine_confirm", path=finding["path"])
        ):
            def isolate():
                vault = Quarantine()
                item = vault.add(finding, dry_run=False)
                return {
                    "item": item,
                    "items": vault.list_items(),
                    "finding": finding,
                }

            self._run("quarantined", isolate)

    def _restore(self) -> None:
        from tkinter import messagebox

        item = self._selected()
        if self.mode != "vault" or not item or item.get("error"):
            return
        if messagebox.askyesno(
            "AntiOS", self.t("restore_confirm", path=item["original_path"])
        ):
            def restore():
                vault = Quarantine()
                value = vault.restore(item["id"], dry_run=False)
                return {"restored": value, "items": vault.list_items()}

            self._run("restored", restore)

    def _sync_tabs(self) -> None:
        findings = self.mode == "findings"
        for button, selected in ((self.findings_tab, findings), (self.vault_tab, not findings)):
            background = self.palette["accent_soft" if selected else "surface_alt"]
            button.configure(bg=background,
                             fg=self.palette["accent" if selected else "text"])
            button.bind("<Leave>", lambda _event, tab=button, color=background: tab.configure(bg=color))
        self.quarantine_button.pack_forget()
        self.restore_button.pack_forget()
        if findings:
            self.scan_card.grid()
            self.filter_choice.pack(side="right", before=self.results_hint)
            self.quarantine_button.pack(side="left", padx=(5, 0))
            if not self.export_button.winfo_manager():
                self.export_button.pack(side="right", padx=(0, 4))
        else:
            self.scan_card.grid_remove()
            self.filter_choice.pack_forget()
            self.export_button.pack_forget()
            self.restore_button.pack(side="left", padx=(5, 0))
            if self.advanced_visible:
                self._toggle_advanced()

    def _show(self, mode: str) -> None:
        self.mode = mode
        self._sync_tabs()
        if mode == "vault":
            self._render_items()
            if not self.app.antivirus_busy:
                self._run("items", lambda: Quarantine().list_items())
        else:
            self._render_result()
            if self.app.antivirus_result is None and not self.app.antivirus_busy:
                self.status.configure(text=self.t("ready"))

    def _show_result_count(self, count: int, empty_text: str, *, total: int | None = None) -> None:
        text = self.t("result_count", count=count) if count else ""
        if total is not None and total > count:
            text = self.app.t("work.visible_results", shown=count, total=total)
        self.results_hint.configure(text=text)
        if count:
            self.empty_result.place_forget()
        else:
            self.empty_result.configure(text=empty_text)
            self.empty_result.place(relx=0.5, rely=0.57, anchor="center")

    def _render_items(self) -> None:
        if self.mode != "vault":
            return
        self.tree.delete(*self.tree.get_children())
        self.items = {}
        for index, item in enumerate(self.app.antivirus_items):
            key = str(index)
            self.items[key] = item
            self.tree.insert(
                "",
                "end",
                iid=key,
                values=(
                    self.t("error_kind") if item.get("error") else self.t(item.get("state", "vault")),
                    item.get("name", item.get("error", "")),
                    item.get("original_path", item["id"]),
                ),
            )
        self._show_result_count(len(self.items), self.t("vault_empty"))
        self._selection_changed()

    def _render_result(self) -> None:
        result = self.app.antivirus_result
        if result:
            metadata = result.get("engine", {})
            engine_text = metadata.get("version") or self.t("managed_engine")
            freshness = metadata.get("database_freshness")
            if freshness:
                engine_text += " · " + self.t("db_" + freshness)
            if metadata.get("signature_catalog_version") is not None:
                engine_text += " · " + self.t("catalog_version").format(
                    version=metadata["signature_catalog_version"],
                )
            if metadata.get("signature_catalog_warning"):
                engine_text += " · " + self.t("catalog_fallback")
            if metadata.get("detail"):
                engine_text += " · " + metadata["detail"]
            self.provider_status.configure(text=engine_text)

            summary = result["summary"]
            verdict_key = "stopped" if summary.get("cancelled") else result["verdict"]
            pieces = [
                self.t(verdict_key),
                self.t(
                    "summary_result",
                    scanned=summary["files_scanned"],
                    threats=summary["threats"],
                ),
            ]
            if summary.get("reviews"):
                pieces.append(self.app.t("work.review_count", count=summary["reviews"]))
            if summary["skipped"] or summary["errors"]:
                pieces.append(
                    self.t(
                        "summary_issues",
                        skipped=summary["skipped"],
                        errors=summary["errors"],
                    )
                )
            if result["coverage"] == "limited":
                pieces.append(self.t("limited"))
            self.status.configure(
                text=" · ".join(pieces),
                fg=self.palette["warn"] if summary["threats"] or summary["errors"] else self.palette["muted"],
            )

        if self.mode != "findings":
            return
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        values = (
            result["findings"]
            + [dict(item, kind="issue", name=item["reason"]) for item in result["issues"]]
            if result
            else []
        )
        label = self.filter_var.get()
        selected_filter = next((key for key, value in self.filter_labels.items() if value == label), "all")
        if selected_filter != "all":
            values = [item for item in values if item["kind"] == selected_filter]
        for index, finding in enumerate(values[:1000]):
            key = str(index)
            self.rows[key] = finding
            kind = "isolated" if finding.get("quarantined") else finding["kind"]
            self.tree.insert(
                "",
                "end",
                iid=key,
                tags=(finding["kind"],),
                values=(self.t(kind), finding["name"], finding["path"]),
            )
        empty = self.app.t("work.filter_empty") if result and selected_filter != "all" else self.t("results_empty")
        self._show_result_count(len(self.rows), empty, total=len(values))
        self._selection_changed()

    def _selection_changed(self) -> None:
        selected = self._selected()
        active = not self.app.antivirus_busy and selected is not None
        self.details_button.configure(state="normal" if active else "disabled")
        self.export_button.configure(state="normal" if self.app.antivirus_result else "disabled")
        self.quarantine_button.configure(
            state=(
                "normal"
                if active
                and self.mode == "findings"
                and selected.get("kind") == "threat"
                and not selected.get("quarantined")
                else "disabled"
            )
        )
        self.restore_button.configure(
            state=(
                "normal"
                if active
                and self.mode == "vault"
                and not selected.get("error")
                else "disabled"
            )
        )

    def _details(self) -> None:
        from tkinter import messagebox

        selected = self._selected()
        if selected:
            messagebox.showinfo(
                "AntiOS",
                json.dumps(selected, indent=2, ensure_ascii=False),
            )

    def _export(self) -> None:
        from tkinter import filedialog

        if not self.app.antivirus_result:
            return
        target = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="antios-antivirus.json",
            filetypes=[("JSON", "*.json")],
        )
        if target:
            try:
                Path(target).write_text(
                    json.dumps(
                        self.app.antivirus_result,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
            except OSError as exc:
                self._error(str(exc))

    def _diagnose_scan_result(self, result: dict) -> None:
        """Surface engine failures returned as data, not only raised exceptions.

        scan_files returns a limited-coverage result when native inspection cannot
        complete. That must still create an ERROR event,
        otherwise the console can miss the exact failure reported in the UI.
        """
        engine = result.get("engine")
        if not isinstance(engine, dict):
            return
        detail = str(engine.get("detail") or "").strip()
        if engine.get("available") is False:
            self._error({
                "message": detail or "AntiOS Engine unavailable",
                "component": "AntiOS Engine",
                "operation": "scan-engine-start",
            })
        elif engine.get("failed_during_scan") is True:
            self._error({
                "message": detail or "AntiOS Engine failed while scanning files",
                "component": "AntiOS Engine",
                "operation": "scan-engine-runtime",
            })

    def _open_diagnostics(self) -> None:
        open_diagnostics(self.app, self.palette)

    def _restore_diagnostic_hint(self) -> None:
        for event in recent_events(limit=30):
            if event.get("level") in {"ERROR", "CRITICAL"}:
                label = explanation(str(event.get("code", "")), self.app.language)[0]
                self.last_error_label.configure(
                    text=label + " · " + str(event.get("component", "")),
                    fg=self.palette["warn"],
                )
                return

    def _error(self, message: str | dict) -> None:
        payload = message if isinstance(message, dict) else {"message": str(message)}
        text = str(payload.get("message", "") or "Unknown error")
        component = str(payload.get("component") or "Protection")
        code = classify_error(text, component=component)
        event = record_event(
            component, "ERROR", text, code=code,
            details=str(payload.get("details") or ""),
            context={"operation": str(payload.get("operation") or "antivirus")},
        )
        heading, _cause, recommended = explanation(code, self.app.language)
        self.status.configure(
            text=heading + " · " + recommended,
            fg=self.palette["warn"],
        )
        if hasattr(self, "last_error_label"):
            self.last_error_label.configure(
                text=heading + " · " + event["component"], fg=self.palette["warn"]
            )
        if payload.get("operation") == "guard-action" and self.app.active_page == "overview":
            self.protection_detail.configure(text=heading + " · " + recommended)

    def _sync_guard_ui(self, value: dict) -> None:
        state = str(value.get("state") or "unavailable")
        self.guard_state = state
        if _diagnostic_changed(self, "guard-state", state):
            # Poll every 3 s, but never flood the journal with unchanged state.
            record_event(
                "Guard",
                "ERROR" if state in {"failed", "unresponsive"} else
                "WARNING" if state in {"degraded", "attention", "unavailable"} else "INFO",
                "Resident Guard: " + state,
                code="GUARD_UNRESPONSIVE" if state in {"unresponsive", "failed"}
                else "GUARD_STATE_CHANGED",
                context={"state": state},
            )
        self.app.set_protection_state(value)
        healthy = state in _HEALTHY_GUARD_STATES

        if healthy:
            color = self.palette["ok"]
            title = self.t("protection_active")
            detail = self.t("protection_layered_detail") if self.layered_active else self.t("protection_active_detail")
        elif state == "starting":
            color = self.palette["info"]
            title = self.t("protection_starting")
            detail = self.t("protection_starting_detail")
        elif state in {"attention", "degraded", "failed", "unresponsive", "unavailable"}:
            color = self.palette["review"]
            title = self.t("protection_attention")
            detail = self.t("protection_attention_detail") if state == "attention" else self.t("guard_state_" + state)
        else:
            color = self.palette["warn"]
            title = self.t("protection_off")
            detail = self.t("protection_off_detail")

        self.hero_accent.configure(bg=color)
        self.protection_dot.configure(fg=color)
        self.protection_title.configure(text=title)
        self.protection_detail.configure(text=detail)
        emblem = self.app.guard_emblem
        emblem.itemconfigure("hull", outline=color)
        emblem.itemconfigure("mark", text="✓" if healthy else "·" if state == "starting" else "!", fill=color)
        behavior = value.get("behavior") if isinstance(value.get("behavior"), dict) else {}
        behavior_state = str(behavior.get("state") or "unavailable")
        if os.name == "nt" and behavior.get("collector") not in {"toolhelp-snapshot", "injected"}:
            # A degraded process collector must not be presented as healthy.
            behavior_state = "unavailable"
        behavior_label = self.t(
            "behavior_" + behavior_state
            if behavior_state in {"normal", "attention", "alert"}
            else "behavior_unavailable"
        )
        risk = value.get("risk") if isinstance(value.get("risk"), dict) else {}
        last_risk = risk.get("last") if isinstance(risk.get("last"), dict) else {}
        risk_class = str(last_risk.get("classification") or "unavailable")
        risk_label = self.t(
            "risk_" + risk_class
            if risk_class in {
                "low", "observe", "elevated", "high",
                "critical-behavior", "confirmed-threat"
            }
            else "risk_unavailable"
        )
        incidents = value.get("incidents") if isinstance(value.get("incidents"), dict) else {}
        latest_incident = incidents.get("latest") if isinstance(incidents.get("latest"), dict) else {}
        incident_state = str(incidents.get("state") or "unavailable")
        incident_label = self.t(
            "incident_" + incident_state
            if incident_state in {"normal", "attention", "alert"}
            else "incident_unavailable"
        )
        self.guard_status.configure(
            text=self.t(
                "guard_status",
                state=self.t("guard_state_" + state),
                count=value.get("detections", 0),
            ) + "\n" + self.t(
                "behavior_status",
                state=behavior_label,
                score=behavior.get("highest_score", 0),
                count=behavior.get("recent_findings", 0),
            ) + "\n" + self.t(
                "risk_status",
                state=risk_label,
                score=last_risk.get("score", 0),
            ) + "\n" + self.t(
                "incident_status",
                state=incident_label,
                count=incidents.get("active_incidents", 0),
                score=incidents.get("highest_score", 0),
                nodes=latest_incident.get("node_count", 0),
                edges=latest_incident.get("edge_count", 0),
            )
        )

        running = state in _ACTIVE_GUARD_STATES
        self.guard_start_button.configure(
            text=self.t("guard_stop") if running else self.t("guard_start")
        )

    def _sync_protection_ui(self, value: dict) -> None:
        caps = value.get("capabilities") if isinstance(value, dict) else {}
        if not isinstance(caps, dict):
            caps = {}
        # Engine probe failures are recorded once per distinct reason; a
        # twenty-second heartbeat must never generate a flood of duplicates.
        reason = str(value.get("error") or "") if isinstance(value, dict) else ""
        component = "Protection"
        guard = value.get("guard") if isinstance(value, dict) else None
        if not reason and isinstance(guard, dict) and guard.get("state") == "unavailable":
            reason = str(guard.get("detail") or "")
            component = "Guard"
        failure_key = component + ":" + reason
        if reason and _diagnostic_changed(self, "probe-error", failure_key, repeat_after=300):
            # A probe failure may originate from the Guard status database, not
            # the engine. Preserve component attribution and bound duplicate noise.
            self._error({"message": reason, "component": component,
                         "operation": "status-probe"})
        # An incomplete aggregate response says nothing about engine health.
        ready = caps.get("standalone_detection_engine")
        if hasattr(self, "app") and isinstance(ready, bool):
            if _diagnostic_changed(self, "engine-ready", ready):
                record_event(
                    "AntiOS Engine", "INFO" if ready else "WARNING",
                    "AntiOS Engine ready" if ready else "AntiOS Engine not ready",
                    code="OPERATION_COMPLETED" if ready else "ENGINE_NOT_READY",
                    context={"state": "ready" if ready else "unavailable"},
                )
                if not ready and hasattr(self, "last_error_label"):
                    self.last_error_label.configure(
                        text=explanation("ENGINE_NOT_READY", self.app.language)[0],
                        fg=self.palette["review"],
                    )
        vendor = value.get("windows_vendor_companion", {}) if isinstance(value, dict) else {}
        vendor_coexist = vendor.get("coexistence", {}) if isinstance(vendor, dict) else {}
        detected_vendors = vendor_coexist.get("vendor_products_detected") or []
        confirmed_vendors = vendor_coexist.get("vendor_realtime_confirmed") or []
        vendor_names = [
            "Kaspersky" if item == "kaspersky" else "Dr.Web" if item == "drweb" else str(item)
            for item in detected_vendors
        ]
        layered = bool(
            caps.get("standalone_detection_engine") and
            (
                (
                    caps.get("layered_with_defender") and
                    (
                        caps.get("resident_post_write_detection") or
                        caps.get("pre_execution_blocking")
                    )
                )
                or caps.get("layered_with_vendor")
            )
        )
        self.layered_active = layered
        self.engine_chip.configure(
            text=self.t("layered_engine") if layered else self.t("managed_engine"),
            fg=self.palette["ok"] if layered else self.palette["muted"],
        )
        if hasattr(self, "engine_component_status"):
            if vendor_names:
                companion_label = ", ".join(vendor_names)
                companion_text = (
                    f"Готов · рядом с {companion_label}"
                    if self.app.language == "ru"
                    else f"Ready · alongside {companion_label}"
                )
                if not confirmed_vendors:
                    companion_text += (
                        " · realtime не подтверждён"
                        if self.app.language == "ru"
                        else " · real-time unconfirmed"
                    )
            else:
                companion_text = (
                    "Готов · рядом с Defender" if self.app.language == "ru"
                    else "Ready · alongside Defender"
                )
            self.engine_component_status.configure(
                text=(
                    companion_text if layered or vendor_names
                    else "Движок доступен" if caps.get("standalone_detection_engine") and self.app.language == "ru"
                    else "Engine available" if caps.get("standalone_detection_engine")
                    else "Требует проверки" if self.app.language == "ru"
                    else "Needs review"
                ),
                fg=self.palette["ok"] if caps.get("standalone_detection_engine") else self.palette["review"],
            )
        if hasattr(self, "app") and isinstance(value, dict):
            engine = value.get("engine") or {}
            version = engine.get("signature_catalog_version")
            if version is not None:
                fallback = engine.get("signature_catalog_status") == "fallback"
                text = self.t("catalog_version", version=version)
                if fallback:
                    text += " · " + self.t("catalog_fallback")
                self.app.overview_signature_status.configure(
                    text=text, fg=self.palette["review" if fallback else "ok"],
                )
        if self.guard_state in _HEALTHY_GUARD_STATES:
            self.protection_detail.configure(
                text=self.t("protection_layered_detail") if layered
                else self.t("protection_active_detail")
            )

    def _set_busy(self) -> None:
        busy = self.app.antivirus_busy
        scanning = busy and self.app.antivirus_cancelable
        if scanning and not self._progress_running:
            self.cancel_button.pack(side="left", before=self.scan_button, padx=(0, 6))
            self.scan_progress.pack(fill="x")
            self.scan_progress.start(15)
        elif not scanning and self._progress_running:
            self.cancel_button.pack_forget()
            self.scan_progress.stop()
            self.scan_progress.pack_forget()
        self._progress_running = scanning
        for button in self.buttons:
            button.configure(state="disabled" if busy else "normal")
        for choice in (self.scan_profile_choice, self.scan_workers_choice):
            choice.configure(state="disabled" if busy else "readonly")

        guard_companion_missing = (
            getattr(sys, "frozen", False)
            and not (Path(sys.executable).parent / "AntiOS-Guard.exe").is_file()
        )
        if (
            not busy
            and guard_companion_missing
            and self.guard_state not in _ACTIVE_GUARD_STATES
        ):
            self.guard_start_button.configure(state="disabled")

        self.cancel_button.configure(
            state=(
                "normal"
                if busy
                and self.app.antivirus_cancelable
                and not self.app.antivirus_cancel.is_set()
                else "disabled"
            )
        )
        self._selection_changed()

    def _poll(self) -> None:
        result_queue = self.app.antivirus_queue
        if (
            os.name == "nt"
            and time.monotonic() - self.last_protection_probe >= 20
            and not self.protection_probe_busy
        ):
            self.last_protection_probe = time.monotonic()
            self.protection_probe_busy = True

            def probe_protection() -> None:
                from .protection import collect_protection_status

                try:
                    value = collect_protection_status()
                except Exception as exc:
                    value = {"error": str(exc)}
                result_queue.put(("protection-state", value))

            threading.Thread(target=probe_protection, daemon=True).start()

        if (
            time.monotonic() - self.last_guard_probe >= 3
            and not self.app.guard_probe_busy
        ):
            self.last_guard_probe = time.monotonic()
            self.app.guard_probe_busy = True

            def probe_guard() -> None:
                from .guard_state import read_guard_state

                try:
                    value = read_guard_state()
                except Exception as exc:
                    value = {"state": "unavailable", "detail": str(exc)}
                result_queue.put(("guard-state", value))

            threading.Thread(target=probe_guard, daemon=True).start()

        for _ in range(100):
            try:
                kind, value = self.app.antivirus_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "guard-state":
                self.app.guard_probe_busy = False
                self._sync_guard_ui(value)
                self._set_busy()
            elif kind == "protection-state":
                self.protection_probe_busy = False
                self._sync_protection_ui(value)
            elif kind == "admin-window":
                self.status.configure(text=self.t("admin_opened"), fg=self.palette["muted"])
            elif kind == "guard-action":
                self.last_guard_probe = 0
                engine = value.get("engine") if isinstance(value, dict) else None
                if isinstance(engine, dict) and engine.get("verified") is True:
                    # Refresh actual engine and Defender coexistence status.
                    self.last_protection_probe = 0
                    self.status.configure(
                        text=(
                            "Проверка AntiOS Engine завершена. Обновляю состояние защиты."
                            if self.app.language == "ru"
                            else "AntiOS Engine checked. Refreshing protection status."
                        ),
                        fg=self.palette["ok"],
                    )
            elif kind == "incident-history":
                from .incident_viewer import IncidentViewer

                IncidentViewer(self.app, self.palette, value, self.t)
            elif kind == "idle":
                self.app.antivirus_busy = False
                self._set_busy()
            elif kind == "error":
                self._error(value)
            elif kind == "progress" and not self.app.antivirus_cancel.is_set():
                self.status.configure(
                    text=self.t("progress", count=value["files_scanned"]),
                    fg=self.palette["muted"],
                )
            elif kind == "scan":
                _record_scan_completion(value)
                self.app.antivirus_result = value
                self.app._update_overview_scan()
                self.mode = "findings"
                self.filter_var.set(self.filter_labels["all"])
                self._sync_tabs()
                self._render_result()
                self._diagnose_scan_result(value)
            elif kind == "defender":
                self.status.configure(
                    text=self.t("defender_done"),
                    fg=self.palette["muted"],
                )
                self.app.refresh()
            elif kind in {"quarantined", "restored"}:
                self.app.antivirus_items = value["items"]
                if kind == "quarantined":
                    value["finding"]["quarantined"] = value["item"]["id"]
                elif self.app.antivirus_result:
                    for finding in self.app.antivirus_result["findings"]:
                        if finding.get("quarantined") == value["restored"]["id"]:
                            finding.pop("quarantined")
                self._render_result()
                self._render_items()
                self.status.configure(
                    text=self.t("done"),
                    fg=self.palette["muted"],
                )
            elif kind == "items":
                self.app.antivirus_items = value
                self._render_items()
                self.status.configure(
                    text=self.t("ready"),
                    fg=self.palette["muted"],
                )

        self.after_id = self.app.root.after(100, self._poll)

    def _destroy(self, event: Any) -> None:
        if event.widget == self.parent:
            if self.after_id is not None:
                self.app.root.after_cancel(self.after_id)
                self.after_id = None
            # Dispose Tk variables on the UI thread even while a job survives
            # a theme/language rebuild. A worker must never finalize them.
            self.engine_var = None
