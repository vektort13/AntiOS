"""Local recovery workspace; all Tk calls stay on the UI thread."""
from __future__ import annotations

from pathlib import Path
import queue
import threading
from typing import Callable

from . import recovery


class RecoveryWindow:
    def __init__(self, app, palette: dict) -> None:
        self.app, self.palette = app, palette
        self.ru = app.language == "ru"
        self.paths: list[Path] = []
        self.archive: Path | None = None
        self.archive_id: str | None = None
        self.entry_indices: dict[str, int] = {}
        self.changed_rows = []
        self.busy = False
        self.closed = False
        self.closing = False
        self.cancelled = threading.Event()
        self.events: queue.Queue = queue.Queue(maxsize=1)
        self.updates: queue.Queue = queue.Queue(maxsize=1)
        self.controls = []
        self.after_id = None
        tk, ttk = app.tk, app.ttk
        self.window = tk.Toplevel(app.root)
        self.window.title(self.text("AntiOS · Восстановление файлов", "AntiOS · File recovery"))
        self.window.geometry("960x760")
        self.window.minsize(800, 680)
        self.window.configure(bg=palette["bg"])
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.window.bind("<Destroy>", self._destroy, add="+")
        outer = tk.Frame(self.window, bg=palette["bg"])
        outer.pack(fill="both", expand=True, padx=24, pady=20)
        self.label(outer, self.text("Файлы, к которым можно вернуться", "Files you can return to"),
                   font=("Segoe UI", 22, "bold"), color="text").pack(anchor="w")
        self.label(outer, self.text(
            "Сохраните эталон → проверьте изменения → извлеките копии в новую папку.",
            "Save a baseline → check changes → recover copies into a new folder.")
        ).pack(anchor="w", pady=(5, 16))

        selection = tk.Frame(outer, bg=palette["surface"], padx=16, pady=12)
        selection.pack(fill="x")
        self.label(selection, self.text("01  Что сохранить", "01  Choose what to save"),
                   color="text", surface=True, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        row = tk.Frame(selection, bg=palette["surface"])
        row.pack(fill="x", pady=(10, 6))
        self.button(row, self.text("Добавить файлы", "Add files"), self.choose_files).pack(side="left")
        self.button(row, self.text("Добавить папку", "Add folder"), self.choose_folder).pack(side="left", padx=8)
        self.button(row, self.text("Убрать из списка", "Remove selection"), self.remove).pack(side="left")
        self.system = tk.BooleanVar(value=False)
        system = tk.Checkbutton(selection, text=self.text("Добавить 7 основных файлов Windows", "Include 7 Windows core files"),
                                variable=self.system, bg=palette["surface"], fg=palette["text"],
                                selectcolor=palette["surface_soft"], activebackground=palette["surface"],
                                activeforeground=palette["text"], anchor="w")
        system.pack(anchor="w")
        self.controls.append(system)
        list_frame = tk.Frame(selection, bg=palette["surface"])
        list_frame.pack(fill="x", pady=(6, 0))
        self.selection = tk.Listbox(list_frame, height=3, selectmode="extended", exportselection=False,
                                   bg=palette["surface_soft"], fg=palette["text"], bd=0,
                                   highlightthickness=0, font=("Segoe UI", 9))
        self.selection.pack(side="left", fill="x", expand=True)
        scroll = ttk.Scrollbar(list_frame, command=self.selection.yview)
        scroll.pack(side="right", fill="y")
        self.selection.configure(yscrollcommand=scroll.set)
        self.controls.append(self.selection)

        self.label(outer, self.text("02  Резервная копия", "02  Backup"), color="text",
                   font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(16, 8))
        self.archive_label = self.label(outer, self.text("Архив не выбран", "No archive selected"))
        self.archive_label.pack(fill="x")
        actions = tk.Frame(outer, bg=palette["bg"])
        actions.pack(fill="x", pady=(8, 12))
        self.button(actions, self.text("Создать эталон", "Create baseline"), self.create, primary=True).pack(side="left")
        self.button(actions, self.text("Открыть архив", "Open archive"), self.open_archive).pack(side="left", padx=8)
        self.button(actions, self.text("Дополнить эталон", "Extend baseline"), lambda: self.create(extend=True)).pack(side="left")
        self.button(actions, self.text("Проверить", "Check changes"), self.check).pack(side="left", padx=8)
        self.button(actions, self.text("Содержимое", "Contents"), self.contents).pack(side="left")
        smart = tk.Frame(outer, bg=palette["bg"])
        smart.pack(fill="x", pady=(0, 10))
        self.button(smart, self.text("Сравнить два снимка", "Compare two snapshots"), self.compare).pack(side="left")
        self.button(smart, self.text("Извлечь прежние версии изменений", "Recover earlier changed files"),
                    self.recover_changes).pack(side="left", padx=8)

        self.label(outer, self.text("03  Содержимое и изменения", "03  Contents and changes"), color="text",
                   font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        frame = tk.Frame(outer, bg=palette["bg"])
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        self.results = ttk.Treeview(frame, columns=("state", "path"), show="headings", height=6,
                                   style="AntiOS.Treeview")
        self.results.tag_configure("changed", foreground=palette["review"])
        self.results.tag_configure("missing", foreground=palette["review"])
        self.results.tag_configure("unreadable", foreground=palette["review"])
        self.results.heading("state", text=self.text("Состояние", "Status"))
        self.results.heading("path", text=self.text("Файл", "File"))
        self.results.column("state", width=140, minwidth=130, stretch=False)
        self.results.column("path", width=600, minwidth=300)
        self.results.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, command=self.results.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=self.results.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        self.results.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        footer = tk.Frame(outer, bg=palette["bg"])
        self.button(footer, self.text("Извлечь всё…", "Recover all…"), self.export).pack(side="left")
        self.button(footer, self.text("Извлечь выбранное…", "Recover selected…"),
                    lambda: self.export(selected=True)).pack(side="left", padx=8)
        self.cancel_button = app._button(footer, self.text("Отменить", "Cancel"), self.cancel, kind="ghost")
        self.cancel_button.pack(side="right")
        self.cancel_button.configure(state="disabled")
        self.status = self.label(outer, self.text("Готово к работе", "Ready"), color="text")
        self.label(outer, self.text(
            "До 32 МиБ на файл и 512 МиБ на архив. Это копии файлов, не полный откат Windows.\n"
            "Архив не зашифрован. Храните отдельную копию на отключаемом носителе.",
            "Up to 32 MiB per file and 512 MiB per archive. File backups, not a full Windows rollback.\n"
            "Archives are unencrypted. Keep a separate copy on offline storage."), font=("Segoe UI", 9)
        ).pack(side="bottom", fill="x")
        self.status.pack(side="bottom", fill="x", pady=(2, 6))
        footer.pack(side="bottom", fill="x", pady=(12, 8))
        frame.pack(fill="both", expand=True)
        self.window.bind("<Configure>", self._resize, add="+")
        self.after_id = self.window.after(100, self.poll)

    def text(self, ru: str, en: str) -> str:
        return ru if self.ru else en

    def label(self, parent, text, *, font=("Segoe UI", 10), color="muted", surface=False):
        return self.app.tk.Label(parent, text=text, bg=self.palette["surface" if surface else "bg"],
                                 fg=self.palette[color], anchor="w", justify="left", font=font,
                                 wraplength=890)

    def _resize(self, event):
        if event.widget == self.window:
            self.archive_label.configure(wraplength=max(650, event.width - 60))
            self.status.configure(wraplength=max(650, event.width - 60))

    def button(self, parent, text, command, primary=False):
        button = self.app._button(parent, text, command, kind="primary" if primary else "secondary")
        self.controls.append(button)
        return button

    def add_paths(self, paths):
        if self.busy:
            return
        for path in paths:
            path = Path(path)
            if path not in self.paths:
                self.paths.append(path)
                self.selection.insert("end", str(path))

    def choose_files(self):
        from tkinter import filedialog
        self.add_paths(filedialog.askopenfilenames(parent=self.window))

    def choose_folder(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(parent=self.window)
        if path:
            self.add_paths([path])

    def remove(self):
        if not self.busy:
            for index in reversed(self.selection.curselection()):
                del self.paths[index]
                self.selection.delete(index)

    def set_archive(self, path):
        self.archive = Path(path)
        self.archive_id = None
        self.entry_indices.clear()
        self.changed_rows.clear()
        self.archive_label.configure(text=str(path))
        self.results.delete(*self.results.get_children())

    def open_archive(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(parent=self.window, filetypes=[("AntiOS backup", "*.zip")])
        if path:
            self.set_archive(path)
            self.contents()

    def contents(self):
        if self.archive:
            archive = self.archive
            self.start("list", lambda **kw: recovery.inventory(archive, **kw))
        else:
            self.status.configure(text=self.text("Сначала откройте архив.", "Open an archive first."))

    def create(self, extend=False):
        from tkinter import filedialog
        if self.busy:
            return
        if extend and self.archive is None:
            self.status.configure(text=self.text("Сначала откройте исходный архив.", "Open the original archive first."))
            return
        try:
            paths = list(self.paths) + (recovery.system_targets() if self.system.get() else [])
        except (OSError, ValueError) as exc:
            self.status.configure(text=str(exc))
            return
        if not paths:
            self.status.configure(text=self.text("Выберите файлы или папки.", "Choose files or folders."))
            return
        path = filedialog.asksaveasfilename(parent=self.window, defaultextension=".zip",
                                          initialfile="AntiOS-baseline.zip", filetypes=[("AntiOS backup", "*.zip")])
        if path:
            previous = self.archive if extend else None
            expected_previous_id = self.archive_id if extend else None
            self.start("create", lambda **kw: recovery.create(
                paths, Path(path), previous=previous, expected_previous_id=expected_previous_id, **kw))

    def check(self):
        if self.archive:
            archive = self.archive
            self.start("check", lambda **kw: recovery.check(archive, **kw))
        else:
            self.status.configure(text=self.text("Сначала откройте архив.", "Open an archive first."))

    def compare(self):
        from tkinter import filedialog
        if self.busy:
            return
        if not self.archive:
            self.status.configure(text=self.text("Сначала откройте исходный эталон.", "Open the earlier baseline first."))
            return
        other = filedialog.askopenfilename(parent=self.window,
            title=self.text("Выберите более новый снимок", "Choose a newer snapshot"),
            filetypes=[("AntiOS backup", "*.zip")])
        if other:
            baseline = self.archive
            self.start("compare", lambda **kw: recovery.compare(baseline, Path(other), **kw))

    def recover_changes(self):
        if self.busy:
            return
        if not self.changed_rows:
            self.status.configure(text=self.text(
                "Сначала проверьте изменения или сравните снимки. Выбираются только изменённые и отсутствующие файлы эталона.",
                "Check changes or compare snapshots first. Only changed and missing baseline files are selected."))
            return
        self.results.selection_set(self.changed_rows)
        self.export(selected=True)

    def export(self, selected=False):
        from tkinter import filedialog
        if self.busy:
            return
        if not self.archive:
            self.status.configure(text=self.text("Сначала откройте архив.", "Open an archive first."))
            return
        indices = None
        if selected:
            indices = [self.entry_indices[item] for item in self.results.selection() if item in self.entry_indices]
            if not indices or self.archive_id is None:
                self.status.configure(text=self.text("Откройте содержимое архива и выделите нужные строки (Ctrl / Shift).",
                                                     "List the archive contents and select rows (Ctrl / Shift)."))
                return
        parent = filedialog.askdirectory(parent=self.window, title=self.text("Где создать папку восстановления?", "Where should the recovery folder be created?"))
        if parent:
            import uuid
            destination = Path(parent) / ("AntiOS-recovered-" + uuid.uuid4().hex[:8])
            archive = self.archive
            expected_id = self.archive_id
            self.start("export", lambda **kw: recovery.export(archive, destination, indices=indices,
                                                              named=True, expected_id=expected_id, **kw))

    def start(self, action: str, operation: Callable):
        if self.busy or self.closed:
            return
        self.busy = True
        self.cancelled.clear()
        if action != "export":
            self.results.delete(*self.results.get_children())
            self.entry_indices.clear()
            self.changed_rows.clear()
        for control in self.controls:
            control.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.status.configure(text=self.text("Выполняется…", "Working…"))

        def progress(value):
            try:
                self.updates.put_nowait(value)
            except queue.Full:
                pass

        def worker():
            try:
                result = operation(cancelled=self.cancelled.is_set, progress=progress)
                self.events.put((action, result, None))
            except Exception as exc:
                self.events.put((action, None, exc))

        self.worker = threading.Thread(target=worker, name="AntiOS-recovery", daemon=False)
        self.worker.start()

    def poll(self):
        if self.closed:
            return
        try:
            update = self.updates.get_nowait()
            self.status.configure(text=self.text("Обработано файлов: ", "Files processed: ") + str(update["files"]))
        except queue.Empty:
            pass
        try:
            action, result, error = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            for control in self.controls:
                control.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            # Drop progress from the completed job before accepting another one.
            while not self.updates.empty():
                self.updates.get_nowait()
            if isinstance(error, recovery.RecoveryCancelled):
                self.status.configure(text=self.text("Операция отменена.", "Operation cancelled."))
            elif error:
                self.status.configure(text=self.text("Ошибка: ", "Error: ") + str(error))
            else:
                self.render(action, result)
            if self.closing:
                self.window.destroy()
                return
        self.after_id = self.window.after(100, self.poll)

    def render(self, action, result):
        if action == "create":
            self.set_archive(result["archive"])
            for issue in result["errors"]:
                self.results.insert("", "end", values=(issue["error"], issue["path"]))
            self.status.configure(text=self.text("Сохранено файлов: ", "Files saved: ") + str(result["files"]) +
                                  (self.text(" · Покрытие неполное — см. ошибки выше.", " · Incomplete coverage — see errors above.") if result["errors"] else ""))
        elif action in {"check", "list", "compare"}:
            self.archive_id = result["archive_id"]
            self.archive_label.configure(text=str(self.archive) + (
                "  →  " + result["compared_archive"] if action == "compare" else ""))
            states = {"unchanged": self.text("Без изменений", "Unchanged"), "changed": self.text("Изменён", "Changed"),
                      "missing": self.text("Отсутствует", "Missing"), "unreadable": self.text("Недоступен", "Unreadable"),
                      "saved": self.text("В архиве", "Saved"),
                      "added": self.text("Новый в снимке", "Added in snapshot"),
                      "removed": self.text("Нет в новом снимке", "Missing in newer snapshot")}
            for entry in result["files"]:
                item = self.results.insert("", "end", values=(states[entry["state"]], entry["path"]), tags=(entry["state"],))
                if entry["index"] is not None:
                    self.entry_indices[item] = entry["index"]
                    if entry["state"] in {"changed", "missing", "removed"}:
                        self.changed_rows.append(item)
            if action == "compare":
                counts = result["counts"]
                self.status.configure(text=self.text(
                    f"Новых: {counts['added']} · Изменённых: {counts['changed']} · Удалённых: {counts['removed']}. "
                    "Извлечение берёт прежние версии из открытого эталона. Изменение не означает заражение.",
                    f"Added: {counts['added']} · Changed: {counts['changed']} · Removed: {counts['removed']}. "
                    "Recovery uses earlier versions from the open baseline. Changes do not mean infection.") +
                    (self.text(" Снимки неполные.", " Snapshot coverage is incomplete.") if result["coverage"] != "selected-files" else ""))
                return
            if action == "list":
                self.status.configure(text=self.text(f"В архиве: {len(result['files'])} файлов. Целостность копий проверена; это не проверка на вирусы.",
                                                     f"Saved: {len(result['files'])} files. Backup integrity verified; this is not a malware scan.") +
                                      (self.text(" Эталон неполный.", " Baseline is incomplete.") if result["coverage"] != "selected-files" else ""))
                return
            changes = sum(x["state"] != "unchanged" for x in result["files"])
            self.status.configure(text=self.text(f"Проверено: {len(result['files'])} · Отличий: {changes}. Изменение не означает заражение.",
                                                 f"Checked: {len(result['files'])} · Differences: {changes}. Changes do not mean infection.") +
                                  (self.text(" Исходный эталон неполный.", " Original baseline is incomplete.") if result["coverage"] != "selected-files" else ""))
        else:
            self.status.configure(text=self.text("Копии извлечены: ", "Copies recovered: ") + result["directory"] +
                                  self.text(". Имена сохранены в отдельных папках; карта восстановления — recovery-report.json. Проверьте копии антивирусом.",
                                            ". Filenames are kept in separate folders; see recovery-report.json. Scan copies before reuse."))

    def cancel(self):
        self.cancelled.set()
        self.cancel_button.configure(state="disabled")
        self.status.configure(text=self.text("Отмена и очистка…", "Cancelling and cleaning up…"))

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


def open_recovery(app, palette):
    existing = getattr(app, "recovery_window", None)
    if existing and not existing.closed:
        existing.window.lift()
        return existing
    app.recovery_window = RecoveryWindow(app, palette)
    return app.recovery_window
