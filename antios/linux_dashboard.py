"""Minimal Linux desktop dashboard for AntiOS companion mode."""
from __future__ import annotations

import json
from pathlib import Path
import threading
from typing import Any

from .antivirus import render_antivirus_scan, scan_files
from .linux_health import collect_linux_health


def summarize(status: dict[str, Any]) -> list[tuple[str, str]]:
    coexist = status["coexistence"]["coexistence"]
    products = status["coexistence"]["products"]

    def product(name: str) -> str:
        item = products[name]
        if not item.get("installed"):
            return "Not detected"
        realtime = item.get("realtime_confirmed")
        state = "Realtime active" if realtime is True else "Realtime inactive" if realtime is False else "Realtime unconfirmed"
        return f"{item.get('version') or 'version unknown'} · {state}"

    return [
        ("System", status["platform"]["distribution"]),
        ("Kernel", f"{status['platform']['kernel']} · {status['platform']['architecture']}"),
        ("Kaspersky", product("kaspersky")),
        ("Dr.Web", product("drweb")),
        ("AntiOS role", coexist["antios_role"]),
        ("Mode", coexist["mode"]),
    ]


def validate_runtime() -> None:
    try:
        import tkinter  # noqa: F401 -- load the actual Tcl/Tk shared libraries
    except ImportError as exc:
        raise RuntimeError(
            "Linux dashboard requires a compatible Tcl/Tk runtime "
            f"(for example package python3-tk): {exc}. CLI companion mode works without Tk."
        ) from exc


def launch(language: str | None = None, *, background: bool = False, self_test: bool = False) -> int:
    if background:
        raise RuntimeError("Linux companion dashboard does not provide tray/background mode yet")
    validate_runtime()
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    if self_test:
        root.withdraw()
    root.title("AntiOS — Linux Companion")
    root.geometry("820x560")
    root.minsize(680, 460)

    tk.Label(root, text="AntiOS Linux Companion", font=("Sans", 20, "bold")).pack(
        anchor="w", padx=24, pady=(22, 4)
    )
    tk.Label(
        root,
        text="Supplemental mode: AntiOS does not disable or reconfigure Kaspersky / Dr.Web.",
        justify="left",
        anchor="w",
    ).pack(fill="x", padx=24, pady=(0, 18))

    status_frame = tk.Frame(root)
    status_frame.pack(fill="x", padx=24)
    rows: dict[str, Any] = {}
    for index, key in enumerate(("System", "Kernel", "Kaspersky", "Dr.Web", "AntiOS role", "Mode")):
        tk.Label(status_frame, text=key + ":", font=("Sans", 10, "bold"), anchor="w").grid(
            row=index, column=0, sticky="nw", padx=(0, 16), pady=4
        )
        value = tk.Label(status_frame, text="…", anchor="w", justify="left", wraplength=560)
        value.grid(row=index, column=1, sticky="nw", pady=4)
        rows[key] = value
    status_frame.grid_columnconfigure(1, weight=1)

    output = tk.Text(root, height=12, wrap="word")
    output.pack(fill="both", expand=True, padx=24, pady=(18, 12))
    output.insert("1.0", "Ready.\n")
    output.configure(state="disabled")

    buttons = tk.Frame(root)
    buttons.pack(fill="x", padx=24, pady=(0, 22))

    def set_output(text: str) -> None:
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.configure(state="disabled")

    def refresh() -> None:
        try:
            status = collect_linux_health()
            for key, value in summarize(status):
                rows[key].configure(text=value)
        except Exception as exc:
            messagebox.showerror("AntiOS", str(exc))

    def scan_target(path: str) -> None:
        def worker() -> None:
            try:
                result = scan_files(path, engine="clamav")
                rendered = render_antivirus_scan(result)
            except Exception as exc:
                rendered = f"Scan failed: {exc}"
            root.after(0, lambda: set_output(rendered))
        set_output("Scanning with AntiOS ClamAV second-opinion layer…")
        threading.Thread(target=worker, daemon=True).start()

    def choose_file() -> None:
        path = filedialog.askopenfilename(title="Scan file with AntiOS")
        if path:
            scan_target(path)

    def choose_folder() -> None:
        path = filedialog.askdirectory(title="Scan folder with AntiOS", mustexist=True)
        if path:
            scan_target(path)

    def export_status() -> None:
        target = filedialog.asksaveasfilename(
            title="Export AntiOS Linux status",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile="antios-linux-status.json",
        )
        if not target:
            return
        Path(target).write_text(
            json.dumps(collect_linux_health(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        messagebox.showinfo("AntiOS", f"Saved: {target}")

    tk.Button(buttons, text="Refresh status", command=refresh).pack(side="left")
    tk.Button(buttons, text="Scan file", command=choose_file).pack(side="left", padx=(8, 0))
    tk.Button(buttons, text="Scan folder", command=choose_folder).pack(side="left", padx=(8, 0))
    tk.Button(buttons, text="Export status JSON", command=export_status).pack(side="left", padx=(8, 0))

    if self_test:
        try:
            root.update_idletasks()
        finally:
            root.destroy()
        return 0
    refresh()
    root.mainloop()
    return 0
