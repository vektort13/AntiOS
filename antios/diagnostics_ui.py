"""A focused, non-executing diagnostics console for the Tk AntiOS dashboard.

Read-only events, understandable explanations, a technical inspector, fast
filters, copy and a redacted support ZIP. It never opens a terminal or runs an
event's content as code.
"""
from __future__ import annotations

from datetime import datetime
import json
import os
import platform
from pathlib import Path
import sys
from typing import Any

from . import __version__
from .diagnostics import explanation, export_report, journal_fingerprint, recent_events, redact

_SEVERITIES = ("ALL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")
_COMPONENTS = ("ALL", "Guard", "ClamAV", "Scanner", "Quarantine", "Updater", "Protection", "UI", "Installer", "Defender", "System")
_I18N = {
    "ru": {
        "title": "Центр диагностики", "subtitle": "События и ошибки компонентов AntiOS · Только чтение",
        "search": "Поиск по событиям", "search_hint": "Код, компонент или сообщение…",
        "filter": "Уровень", "source": "Источник", "events": "СОБЫТИЯ",
        "when": "ВРЕМЯ", "level": "УРОВЕНЬ", "component": "КОМПОНЕНТ",
        "message": "СООБЩЕНИЕ", "details": "Подробности", "friendly": "Объяснение",
        "technical": "Технические данные", "cause": "Что произошло", "action": "Что сделать",
        "copy": "Копировать", "export": "Экспорт отчёта", "refresh": "Обновить",
        "close": "Закрыть", "empty": "Событий по выбранным условиям нет",
        "select": "Выберите событие слева, чтобы увидеть подробности.",
        "saved": "Диагностический отчёт сохранён. Проверьте его перед отправкой.",
        "error": "Не удалось сохранить отчёт", "copied": "Сведения об ошибке скопированы.",
        "status": "Показано: {shown} · В журнале: {total}",
        "private": "При экспорте скрываются личные пути, почта и секреты.",
        "unfiltered": "Все", "default_title": "Диагностическое событие",
    },
    "en": {
        "title": "Diagnostics center", "subtitle": "AntiOS component events and errors · Read-only",
        "search": "Search events", "search_hint": "Code, component, or message…",
        "filter": "Severity", "source": "Component", "events": "EVENTS",
        "when": "TIME", "level": "LEVEL", "component": "COMPONENT",
        "message": "MESSAGE", "details": "Details", "friendly": "Explanation",
        "technical": "Technical data", "cause": "What happened", "action": "What to do",
        "copy": "Copy", "export": "Export report", "refresh": "Refresh",
        "close": "Close", "empty": "No events match these filters",
        "select": "Select an event on the left to inspect details.",
        "saved": "The diagnostics bundle was saved. Review it before sharing.",
        "error": "Unable to save diagnostics",
        "copied": "Diagnostic details copied.",
        "status": "Shown: {shown} · In journal: {total}",
        "private": "Personal paths, emails and secrets are redacted on export.",
        "unfiltered": "All", "default_title": "Diagnostic event",
    },
}


# Complete interface labels for the other supported dashboard languages.
# English remains the fallback for future optional locales.
_I18N.update({
    "es": {
        "title": "Centro de diagnóstico", "subtitle": "Eventos y errores de AntiOS · Solo lectura",
        "search": "Buscar eventos", "search_hint": "Código, componente o mensaje…",
        "filter": "Gravedad", "source": "Componente", "events": "EVENTOS",
        "when": "HORA", "level": "NIVEL", "component": "COMPONENTE",
        "message": "MENSAJE", "details": "Detalles", "friendly": "Explicación",
        "technical": "Datos técnicos", "cause": "Qué ocurrió", "action": "Qué hacer",
        "copy": "Copiar", "export": "Exportar informe", "refresh": "Actualizar",
        "close": "Cerrar", "empty": "No hay eventos con estos filtros",
        "select": "Seleccione un evento para ver los detalles.",
        "saved": "Informe guardado. Revíselo antes de compartirlo.",
        "error": "No se pudo guardar el informe", "copied": "Detalles copiados.",
        "status": "Mostrados: {shown} · En el registro: {total}",
        "private": "La exportación oculta rutas personales, correos y secretos.",
        "unfiltered": "Todos", "default_title": "Evento de diagnóstico",
    },
    "zh-CN": {
        "title": "诊断中心", "subtitle": "AntiOS 组件事件与错误 · 只读",
        "search": "搜索事件", "search_hint": "代码、组件或消息…",
        "filter": "级别", "source": "组件", "events": "事件",
        "when": "时间", "level": "级别", "component": "组件",
        "message": "消息", "details": "详细信息", "friendly": "通俗说明",
        "technical": "技术详情", "cause": "发生了什么", "action": "建议操作",
        "copy": "复制", "export": "导出报告", "refresh": "刷新",
        "close": "关闭", "empty": "没有符合筛选条件的事件",
        "select": "请在左侧选择事件以查看详情。",
        "saved": "诊断报告已保存。分享前请先检查。",
        "error": "无法保存报告", "copied": "诊断详情已复制。",
        "status": "显示：{shown} · 日志总数：{total}",
        "private": "导出时将隐藏个人路径、邮箱和密钥。",
        "unfiltered": "全部", "default_title": "诊断事件",
    },
    "fi": {
        "title": "Diagnostiikkakeskus", "subtitle": "AntiOS:n tapahtumat ja virheet · Vain luku",
        "search": "Hae tapahtumia", "search_hint": "Koodi, osa tai viesti…",
        "filter": "Vakavuus", "source": "Osa", "events": "TAPAHTUMAT",
        "when": "AIKA", "level": "TASO", "component": "OSA",
        "message": "VIESTI", "details": "Tiedot", "friendly": "Selitys",
        "technical": "Tekniset tiedot", "cause": "Mitä tapahtui", "action": "Mitä tehdä",
        "copy": "Kopioi", "export": "Vie raportti", "refresh": "Päivitä",
        "close": "Sulje", "empty": "Hakuehdoilla ei löytynyt tapahtumia",
        "select": "Valitse vasemmalta tapahtuma nähdäksesi lisätiedot.",
        "saved": "Raportti tallennettu. Tarkista se ennen jakamista.",
        "error": "Raportin tallennus epäonnistui", "copied": "Tiedot kopioitu.",
        "status": "Näytetään: {shown} · Lokissa: {total}",
        "private": "Viennissä peitetään henkilökohtaiset polut ja tunnisteet.",
        "unfiltered": "Kaikki", "default_title": "Diagnostiikkatapahtuma",
    },
    "pl": {
        "title": "Centrum diagnostyki", "subtitle": "Zdarzenia i błędy AntiOS · Tylko do odczytu",
        "search": "Szukaj zdarzeń", "search_hint": "Kod, komponent lub komunikat…",
        "filter": "Poziom", "source": "Komponent", "events": "ZDARZENIA",
        "when": "CZAS", "level": "POZIOM", "component": "KOMPONENT",
        "message": "KOMUNIKAT", "details": "Szczegóły", "friendly": "Wyjaśnienie",
        "technical": "Dane techniczne", "cause": "Co się stało", "action": "Co zrobić",
        "copy": "Kopiuj", "export": "Eksportuj raport", "refresh": "Odśwież",
        "close": "Zamknij", "empty": "Brak zdarzeń pasujących do filtrów",
        "select": "Wybierz zdarzenie z lewej, aby zobaczyć szczegóły.",
        "saved": "Zapisano raport. Sprawdź go przed udostępnieniem.",
        "error": "Nie można zapisać raportu", "copied": "Skopiowano szczegóły.",
        "status": "Wyświetlono: {shown} · W dzienniku: {total}",
        "private": "Eksport ukrywa prywatne ścieżki, adresy e-mail i sekrety.",
        "unfiltered": "Wszystkie", "default_title": "Zdarzenie diagnostyczne",
    },
    "mn": {
        "title": "Оношилгооны төв", "subtitle": "AntiOS бүрэлдэхүүний үйл явдал, алдаа · Зөвхөн унших",
        "search": "Үйл явдал хайх", "search_hint": "Код, бүрэлдэхүүн, мессеж…",
        "filter": "Түвшин", "source": "Бүрэлдэхүүн", "events": "ҮЙЛ ЯВДАЛ",
        "when": "ЦАГ", "level": "ТҮВШИН", "component": "БҮРЭЛДЭХҮҮН",
        "message": "МЭДЭЭЛЭЛ", "details": "Дэлгэрэнгүй", "friendly": "Тайлбар",
        "technical": "Техникийн мэдээлэл", "cause": "Юу болсон", "action": "Яах хэрэгтэй",
        "copy": "Хуулах", "export": "Тайлан гаргах", "refresh": "Шинэчлэх",
        "close": "Хаах", "empty": "Шүүлтүүрт тохирох үйл явдал алга",
        "select": "Дэлгэрэнгүйг үзэхийн тулд зүүнээс үйл явдал сонгоно уу.",
        "saved": "Тайлан хадгалагдлаа. Илгээхээс өмнө шалгана уу.",
        "error": "Тайлан хадгалж чадсангүй", "copied": "Мэдээллийг хууллаа.",
        "status": "Харагдаж буй: {shown} · Нийт: {total}",
        "private": "Экспортод хувийн зам, шуудан болон нууц өгөгдлийг халхална.",
        "unfiltered": "Бүгд", "default_title": "Оношилгооны үйл явдал",
    },
})


def _local_time(value: object) -> str:
    """Journal timestamps are UTC; show local wall time in the GUI."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(value).replace("T", " ")[:19]



class DiagnosticsWindow:
    def __init__(self, app: Any, palette: dict[str, str]):
        import tkinter as tk
        from tkinter import ttk

        self.app, self.tk, self.ttk, self.palette = app, tk, ttk, palette
        self.tr = _I18N.get(app.language, _I18N["en"])
        self.win = tk.Toplevel(app.root)
        self.win.title("AntiOS · " + self.tr["title"])
        self.win.geometry("1170x725")
        self.win.minsize(870, 550)
        self.win.configure(bg=palette["bg"])
        self.win.transient(app.root)
        self.win.protocol("WM_DELETE_WINDOW", self.close)
        self.win.bind("<Escape>", lambda _event: self.close())
        self.win.bind("<Control-f>", lambda _event: self.search_entry.focus_set())
        self.win.bind("<Control-c>", self._copy_shortcut)
        self.win.bind("<F5>", lambda _event: self.refresh())
        self._after_id = None
        self._journal_signature = None
        self._all: list[dict] = []
        self._rows: dict[str, dict] = {}
        self._selected: dict | None = None
        self.search_var = tk.StringVar()
        self.severity_var = tk.StringVar(value="ALL")
        self.component_var = tk.StringVar(value="ALL")
        self.mode = "friendly"
        self._build()
        self.search_var.trace_add("write", lambda *_: self._render_table())
        self.severity_var.trace_add("write", lambda *_: self._render_table())
        self.component_var.trace_add("write", lambda *_: self._render_table())
        self.refresh()
        self.win.focus_set()
        self._tick()

    def _text(self, parent: Any, text: str, *, color: str = "muted", size: int = 9,
              bold: bool = False, **kwargs: Any) -> Any:
        return self.tk.Label(
            parent, text=text, bg=self.palette["surface"],
            fg=self.palette.get(color, color),
            font=("Segoe UI", size, "bold" if bold else "normal"),
            anchor="w", justify="left", **kwargs,
        )

    def _button(self, parent: Any, title: str, command, *, primary: bool = False) -> Any:
        p = self.palette
        return self.tk.Button(
            parent, text=title, command=command,
            bg=p["accent"] if primary else p["surface_alt"],
            fg=p["accent_text"] if primary else p["text"],
            activebackground=p["accent_hover"] if primary else p["surface_hover"],
            activeforeground=p["accent_text"] if primary else p["text"],
            font=("Segoe UI Semibold", 9), relief="flat", bd=0,
            cursor="hand2", padx=14, pady=9, highlightthickness=0,
        )

    def _build(self) -> None:
        tk, p, tr = self.tk, self.palette, self.tr
        header = tk.Frame(self.win, bg=p["bg"])
        header.pack(fill="x", padx=24, pady=(20, 16))
        tk.Label(header, text=tr["title"], bg=p["bg"], fg=p["text"],
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(header, text=tr["subtitle"], bg=p["bg"], fg=p["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))

        toolbar = tk.Frame(self.win, bg=p["surface"], highlightbackground=p["border"],
                           highlightthickness=1)
        toolbar.pack(fill="x", padx=24, pady=(0, 12))
        self._text(toolbar, tr["search"], color="muted_2", size=8).pack(
            side="left", padx=(16, 8))
        self.search_entry = tk.Entry(
            toolbar, textvariable=self.search_var, bg=p["surface_alt"],
            fg=p["text"], insertbackground=p["text"], relief="flat",
            font=("Segoe UI", 10), width=29,
        )
        self.search_entry.pack(side="left", ipady=7, padx=(0, 14), pady=11)
        self._text(toolbar, tr["filter"], color="muted_2", size=8).pack(side="left", padx=(0, 7))
        self._combo(toolbar, self.severity_var, _SEVERITIES, 12).pack(side="left", padx=(0, 14))
        self._text(toolbar, tr["source"], color="muted_2", size=8).pack(side="left", padx=(0, 7))
        self._combo(toolbar, self.component_var, _COMPONENTS, 14).pack(side="left")
        self._button(toolbar, tr["refresh"], self.refresh).pack(side="right", padx=12)

        body = tk.PanedWindow(
            self.win, orient="horizontal", bg=p["bg"],
            sashwidth=7, sashrelief="flat", bd=0, showhandle=False,
        )
        body.pack(fill="both", expand=True, padx=24)
        left = tk.Frame(body, bg=p["surface"], highlightthickness=1,
                        highlightbackground=p["border"])
        right = tk.Frame(body, bg=p["surface"], highlightthickness=1,
                         highlightbackground=p["border"])
        body.add(left, minsize=425, stretch="always")
        body.add(right, minsize=305, stretch="always")

        self._text(left, tr["events"], color="muted_2", size=8, bold=True).pack(
            anchor="w", padx=14, pady=(12, 9))
        table_frame = tk.Frame(left, bg=p["surface"])
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        self.tree = self.ttk.Treeview(
            table_frame, columns=("time", "severity", "component", "message"),
            show="headings", selectmode="browse", style="AntiOS.Treeview"
        )
        for name, label, width, stretch in (
            ("time", tr["when"], 90, False),
            ("severity", tr["level"], 85, False),
            ("component", tr["component"], 90, False),
            ("message", tr["message"], 220, True),
        ):
            self.tree.heading(name, text=label)
            self.tree.column(name, width=width, stretch=stretch, anchor="w")
        scroll = self.ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.tag_configure("ERROR", foreground=p["warn"])
        self.tree.tag_configure("CRITICAL", foreground=p["warn"])
        self.tree.tag_configure("WARNING", foreground=p["review"])
        self.tree.bind("<<TreeviewSelect>>", self._select)

        details_header = tk.Frame(right, bg=p["surface"])
        details_header.pack(fill="x", padx=14, pady=(12, 10))
        self._text(details_header, tr["details"], color="text", bold=True, size=11).pack(side="left")
        self.technical_button = self._button(details_header, tr["technical"], self._toggle_mode)
        self.technical_button.pack(side="right")

        self.title = self._text(right, tr["select"], color="text", size=12, bold=True,
                                wraplength=370)
        self.title.pack(fill="x", padx=15, pady=(2, 9))
        self.summary = self._text(right, "", color="muted", size=9, wraplength=370)
        self.summary.pack(fill="x", padx=15)
        self.details = tk.Text(
            right, bg=p["surface"], fg=p["text"], relief="flat",
            wrap="word", font=("Segoe UI", 10), padx=14, pady=12,
            insertbackground=p["text"], selectbackground=p["surface_hover"],
            borderwidth=0, highlightthickness=0,
        )
        self.details.pack(fill="both", expand=True, padx=1, pady=(8, 12))
        self.details.configure(state="disabled")
        bottom = tk.Frame(self.win, bg=p["bg"])
        bottom.pack(fill="x", padx=24, pady=(10, 16))
        self.status = tk.Label(
            bottom, text="", bg=p["bg"], fg=p["muted"],
            font=("Segoe UI", 8), anchor="w",
        )
        self.status.pack(side="left", fill="x", expand=True)
        self._button(bottom, tr["close"], self.close).pack(side="right")
        self._button(bottom, tr["export"], self._export, primary=True).pack(
            side="right", padx=(0, 8))
        self._button(bottom, tr["copy"], self._copy).pack(side="right", padx=(0, 8))

    def _combo(self, parent, variable, options, width):
        return self.ttk.Combobox(parent, textvariable=variable, state="readonly",
                                  values=options, width=width)

    def _tick(self) -> None:
        if self.win.winfo_exists():
            state = journal_fingerprint()
            if state != self._journal_signature:
                self._journal_signature = state
                self.refresh()
            self._after_id = self.win.after(2300, self._tick)

    def refresh(self) -> None:
        events = recent_events(limit=700)
        signature = [(x.get("id"), x.get("timestamp")) for x in events]
        if signature != getattr(self, "_last_signature", []):
            self._last_signature = signature
            self._all = events
            self._render_table()

    def _render_table(self) -> None:
        if not hasattr(self, "tree"):
            return
        selected_id = str(self._selected.get("id")) if self._selected else ""
        search = self.search_var.get().strip().casefold()
        severity = self.severity_var.get()
        component = self.component_var.get()
        matches = [
            e for e in self._all
            if (severity == "ALL" or e.get("level") == severity)
            and (component == "ALL" or e.get("component") == component)
            and (not search or search in " ".join(
                str(e.get(field, "")) for field in
                ("timestamp", "level", "component", "code", "message", "details")
            ).casefold())
        ]
        self.tree.delete(*self.tree.get_children())
        self._rows = {}
        for i, event in enumerate(matches):
            iid = str(i)
            self._rows[iid] = event
            when = _local_time(event.get("timestamp", ""))[11:19]
            self.tree.insert("", "end", iid=iid, tags=(event.get("level", ""),),
                             values=(when, event.get("level"), event.get("component"),
                                     str(event.get("message", ""))[:125]))
            if event.get("id") == selected_id:
                self.tree.selection_set(iid)
        self.status.configure(text=self.tr["status"].format(shown=len(matches), total=len(self._all)))
        if not self.tree.selection() and matches:
            self.tree.selection_set("0")
        if not matches:
            self._selected = None
            self.title.configure(text=self.tr["empty"])
            self.summary.configure(text="")
            self._set_text("")
        else:
            self._select()

    def _select(self, _event: Any = None) -> None:
        ids = self.tree.selection()
        if not ids or ids[0] not in self._rows:
            return
        self._selected = self._rows[ids[0]]
        self._render_selected()

    def _render_selected(self) -> None:
        event = self._selected
        if not event:
            return
        title, cause, action = explanation(event.get("code", ""), self.app.language)
        self.title.configure(text=title)
        self.summary.configure(
            text="{}  ·  {}  ·  {}".format(
                _local_time(event.get("timestamp", "")),
                event.get("component", "System"), event.get("level", "INFO"))
        )
        if self.mode == "technical":
            body = json.dumps(event, ensure_ascii=False, indent=2)
        else:
            body = "\n\n".join((
                self.tr["cause"].upper() + "\n" + cause,
                self.tr["action"].upper() + "\n" + action,
                self.tr["message"].upper() + "\n" + str(event.get("message", "")),
                self.tr["private"],
            ))
        self._set_text(body)

    def _set_text(self, value: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", value)
        self.details.configure(state="disabled")

    def _toggle_mode(self) -> None:
        self.mode = "technical" if self.mode == "friendly" else "friendly"
        self.technical_button.configure(
            text=self.tr["friendly"] if self.mode == "technical" else self.tr["technical"])
        self._render_selected()

    def _copy_shortcut(self, event: Any) -> None:
        # Do not override Ctrl+C inside Entry/Text: respect native selection.
        if event.widget not in {self.search_entry, self.details}:
            self._copy()

    def _copy(self) -> None:
        if not self._selected:
            return
        event = self._selected
        title, cause, action = explanation(event.get("code", ""), self.app.language)
        value = "\n".join((title, cause, action,
                           redact(event.get("message", ""), exported=True),
                           redact(event.get("details", ""), exported=True)))
        self.win.clipboard_clear()
        self.win.clipboard_append(value)
        self.status.configure(text=self.tr["copied"])

    def _export(self) -> None:
        from tkinter import filedialog, messagebox

        target = filedialog.asksaveasfilename(
            parent=self.win, defaultextension=".zip", initialfile="antios-diagnostics.zip",
            filetypes=[("ZIP", "*.zip")],
        )
        if not target:
            return
        try:
            export_report(Path(target), metadata={
                "app_version": __version__,
                "os_name": os.name,
                "os_release": platform.release(),
                "python_version": platform.python_version(),
                "language": self.app.language,
            })
        except (OSError, ValueError) as exc:
            messagebox.showerror("AntiOS", self.tr["error"] + ": " + str(exc), parent=self.win)
        else:
            messagebox.showinfo("AntiOS", self.tr["saved"], parent=self.win)

    def focus(self) -> None:
        self.win.deiconify()
        self.win.lift()
        self.win.focus_set()

    def close(self) -> None:
        if self._after_id is not None:
            try:
                self.win.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        self.win.destroy()
        self.app._diagnostics_window = None


def open_diagnostics(app: Any, palette: dict[str, str]) -> DiagnosticsWindow:
    existing = getattr(app, "_diagnostics_window", None)
    if existing is not None:
        try:
            if existing.win.winfo_exists():
                existing.focus()
                return existing
        except Exception:
            pass
    window = DiagnosticsWindow(app, palette)
    app._diagnostics_window = window
    return window
