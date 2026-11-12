"""A local workspace linking functional checks, snapshots and incident explanations."""
from __future__ import annotations

import queue
import threading

from .protection_check import describe_check, run_checks


class ProtectionLab:
    def __init__(self, app, palette):
        self.app, self.palette = app, palette
        self.ru = app.language == "ru"
        self.closed = self.busy = self.closing = False
        self.cancelled = threading.Event()
        self.events = queue.Queue(maxsize=16)
        self.controls, self.rows = [], {}
        tk, ttk = app.tk, app.ttk
        style = ttk.Style(app.root)
        style.configure("Lab.AntiOS.Treeview", borderwidth=0, relief="flat", rowheight=34,
                        bordercolor=palette["border"], lightcolor=palette["border"], darkcolor=palette["border"])
        style.layout("Lab.AntiOS.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.configure("Lab.Vertical.TScrollbar", background=palette["surface"],
                        troughcolor=palette["bg"], bordercolor=palette["bg"],
                        lightcolor=palette["surface"], darkcolor=palette["surface"],
                        arrowcolor=palette["muted"])
        style.map("Lab.Vertical.TScrollbar", background=[("active", palette["surface_hover"]),
                                                         ("!active", palette["surface"])])
        self.window = tk.Toplevel(app.root)
        self.window.title(self.text("AntiOS · Помощник защиты", "AntiOS · Protection assistant"))
        self.window.geometry("1000x800")
        self.window.minsize(900, 650)
        self.window.configure(bg=palette["bg"])
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.window.bind("<Destroy>", self._destroy, add="+")
        body = tk.Frame(self.window, bg=palette["bg"])
        body.pack(fill="both", expand=True, padx=24, pady=22)
        tk.Label(body, text="AntiOS / " + self.text("ПРОВЕРИТЬ · ПОНЯТЬ · ВОССТАНОВИТЬ", "VERIFY · UNDERSTAND · RECOVER"),
                 bg=palette["bg"], fg=palette["accent"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(body, text=self.text("Уверенность начинается с проверки", "Confidence starts with verification"),
                 bg=palette["bg"], fg=palette["text"], font=("Segoe UI", 23, "bold")).pack(anchor="w", pady=(8, 5))
        tk.Label(body, text=self.text(
            "Работа движка, изменения файлов и причины тревог — в одном рабочем пространстве.",
            "Engine operation, file changes and the reasons behind alerts in one workspace."),
            bg=palette["bg"], fg=palette["muted"], font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 20))
        cards = tk.Frame(body, bg=palette["bg"])
        cards.pack(fill="x")
        entries = [
            ("01", self.text("Самопроверка", "Self-check"), self.text(
                "Проверяет движок безопасными образцами и выполняет пробное восстановление копии.",
                "Tests the engine with harmless controls and verifies a temporary backup round trip."),
                self.text("Проверить защиту", "Run self-check"), self.start_check),
            ("02", self.text("Снимки файлов", "File snapshots"), self.text(
                "Сравнивайте версии, находите изменения и извлекайте нужные прежние копии.",
                "Compare versions, inspect changes and recover the earlier copies you need."),
                self.text("Открыть снимки", "Open snapshots"), self.open_recovery),
            ("03", self.text("Объяснения событий", "Explain activity"), self.text(
                "Узнайте, что вызвало тревогу, что подтверждено и какой следующий шаг поможет.",
                "See what raised an alert, what is confirmed and which next step can help."),
                self.text("Разобрать события", "Review activity"), self.open_incidents),
        ]
        for column, (number, title, detail, action, command) in enumerate(entries):
            cards.grid_columnconfigure(column, weight=1, uniform="cards")
            card = tk.Frame(cards, bg=palette["surface"], highlightthickness=1,
                            highlightbackground=palette["border"], padx=16, pady=14)
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0))
            tk.Label(card, text=number, bg=palette["surface"], fg=palette["accent"],
                     font=("Consolas", 11)).pack(anchor="w")
            tk.Label(card, text=title, bg=palette["surface"], fg=palette["text"],
                     font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(6, 8))
            tk.Label(card, text=detail, bg=palette["surface"], fg=palette["muted"],
                     font=("Segoe UI", 9), wraplength=245, height=4, anchor="nw", justify="left").pack(fill="x")
            button = app._button(card, action, command, kind="primary" if column == 0 else "secondary")
            button.pack(anchor="w", pady=(10, 0))
            self.controls.append(button)
        self.status = tk.Label(body, text=self.text("Проверка ещё не запускалась", "Self-check has not run yet"),
                               bg=palette["bg"], fg=palette["text"], font=("Segoe UI", 11, "bold"), anchor="w")
        self.status.pack(fill="x", pady=(20, 9))
        table = tk.Frame(body, bg=palette["bg"])
        self.table = ttk.Treeview(table, columns=("check", "state"), show="headings", height=6,
                                  style="Lab.AntiOS.Treeview", selectmode="browse")
        self.table.heading("check", text=self.text("Что проверено", "Check"))
        self.table.heading("state", text=self.text("Результат", "Result"))
        self.table.column("check", width=560, minwidth=350)
        self.table.column("state", width=130, minwidth=120, stretch=False)
        self.table.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(table, command=self.table.yview, style="Lab.Vertical.TScrollbar")
        scroll.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=scroll.set)
        for state, color in (("passed", "ok"), ("warning", "review"), ("failed", "warn"), ("skipped", "muted")):
            self.table.tag_configure(state, foreground=palette[color])
        self.table.bind("<<TreeviewSelect>>", self.select_check)
        self.advice = tk.Label(body, text=self.text(
            "Выберите результат, чтобы увидеть объяснение и следующий шаг.",
            "Select a result to see its explanation and next step."),
            bg=palette["surface"], fg=palette["text"], font=("Segoe UI", 10), padx=12, pady=12,
            anchor="nw", justify="left", wraplength=860, height=3)
        footer = tk.Frame(body, bg=palette["bg"])
        footer.pack(side="bottom", fill="x")
        self.advice.pack(side="bottom", fill="x", pady=(10, 10))
        table.pack(fill="both", expand=True)
        tk.Label(footer, text=self.text(
            "Локально · Безопасные тестовые данные · Результат относится к моменту проверки",
            "Local · Harmless test data · Results reflect the time of this check"),
            bg=palette["bg"], fg=palette["muted"], font=("Segoe UI", 8)).pack(side="left")
        self.cancel_button = app._button(footer, self.text("Отменить", "Cancel"), self.cancel, kind="secondary")
        self.cancel_button.pack(side="right")
        self.cancel_button.configure(state="disabled")
        self.after_id = self.window.after(100, self.poll)

    def text(self, ru, en):
        return ru if self.ru else en

    def launch(self, action, operation):
        if self.busy or self.closed:
            return
        self.busy = True
        self.cancelled.clear()
        for button in self.controls:
            button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.status.configure(text=self.text("Выполняется проверка…", "Checking…"))
        events, cancelled = self.events, self.cancelled.is_set
        def progress(item):
            events.put(("progress", item, None))
        def worker():
            try:
                events.put((action, operation(cancelled, progress), None))
            except Exception as exc:
                events.put((action, None, str(exc)[:500]))
        self.worker = threading.Thread(target=worker, name="AntiOS-self-check", daemon=False)
        self.worker.start()

    def start_check(self):
        if self.busy:
            return
        self.rows.clear()
        self.table.delete(*self.table.get_children())
        self.launch("check", lambda cancelled, progress: run_checks(cancelled=cancelled, progress=progress))

    def open_recovery(self):
        from .recovery_ui import open_recovery
        open_recovery(self.app, self.palette)

    def open_incidents(self):
        from .guard_state import read_incident_history
        self.launch("incidents", lambda cancelled, progress: read_incident_history(limit=50))

    def select_check(self, _event=None):
        selected = self.table.selection()
        if selected and selected[0] in self.rows:
            _, _, advice = describe_check(self.rows[selected[0]], "ru" if self.ru else "en")
            self.advice.configure(text=advice)

    def poll(self):
        if self.closed:
            return
        while True:
            try:
                action, value, error = self.events.get_nowait()
            except queue.Empty:
                break
            if action == "progress":
                label, state, _ = describe_check(value, "ru" if self.ru else "en")
                item = self.table.insert("", "end", values=(label, state), tags=(value["state"],))
                self.rows[item] = value
                continue
            self.busy = False
            for button in self.controls:
                button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            if self.closing:
                self.window.destroy()
                return
            if error:
                self.status.configure(text=self.text("Проверка не завершена: ", "Check did not finish: ") + error)
            elif action == "incidents":
                from .incident_viewer import IncidentViewer
                incidents = value.get("incidents", []) if isinstance(value, dict) else value
                if incidents:
                    IncidentViewer(self.app, self.palette, incidents, lambda key, **kw: self.app.t("av." + key, **kw))
                    self.status.configure(text=self.text("Открыты объяснения событий", "Opened activity explanations"))
                else:
                    self.status.configure(text=self.text("В журнале пока нет связанных событий", "No linked incidents have been recorded yet"))
            else:
                labels = {"passed": ("Все проверки пройдены", "All checks passed"),
                          "attention": ("Есть пункты, требующие внимания", "Some checks need attention"),
                          "failed": ("Обнаружена проблема — выберите строку ниже", "A problem was found — select a row below"),
                          "cancelled": ("Проверка отменена", "Check cancelled")}
                self.status.configure(text=labels[value["status"]][0 if self.ru else 1])
                self.app.last_self_check = value
                first = next((key for key, row in self.rows.items() if row["state"] != "passed"), next(iter(self.rows), None))
                if first:
                    self.table.selection_set(first)
                    self.select_check()
        self.after_id = self.window.after(100, self.poll)

    def cancel(self):
        self.cancelled.set()
        self.status.configure(text=self.text("Завершаем текущий шаг…", "Finishing the current step…"))

    def close(self):
        if self.busy:
            self.closing = True
            self.cancel()
        else:
            self.window.destroy()

    def _destroy(self, event):
        if event.widget == self.window:
            self.closed = True
            self.cancelled.set()
            if self.after_id:
                self.window.after_cancel(self.after_id)


def open_protection_lab(app, palette):
    existing = getattr(app, "protection_lab", None)
    if existing and not existing.closed:
        existing.window.lift()
        return existing
    app.protection_lab = ProtectionLab(app, palette)
    return app.protection_lab
