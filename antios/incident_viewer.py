"""Incident Graph viewer and pure presentation helpers."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import json
import math
import os
from pathlib import Path
import queue
import sys
import threading
from typing import Any

from .incident_response import (
    build_incident_report,
    confirmed_findings,
    incident_file_paths,
    isolate_confirmed_findings,
    scan_incident_files,
)
from .incident_explanation import format_explanation


_RELATION_PRIORITY = {
    "executed-as": 0,
    "spawned": 1,
    "raised-signal": 2,
    "correlated-write": 3,
    "modified": 4,
    "evaluated-as": 5,
}


def _number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    return default


def build_incident_tree(incident: dict) -> list[dict]:
    """Return a deterministic spanning forest suitable for a Treeview.

    Incident graphs can contain multiple incoming edges. The viewer picks one
    causal parent for layout while preserving all incoming relation names in the
    row metadata. This changes presentation only; the source graph is untouched.
    """
    if not isinstance(incident, dict):
        return []
    raw_nodes = incident.get("nodes")
    raw_edges = incident.get("edges")
    if not isinstance(raw_nodes, list):
        return []

    nodes = {}
    for item in raw_nodes:
        if not isinstance(item, dict):
            continue
        node_id = item.get("id")
        if isinstance(node_id, str) and node_id:
            nodes[node_id] = item

    incoming: dict[str, list[dict]] = defaultdict(list)
    outgoing: dict[str, list[dict]] = defaultdict(list)
    if isinstance(raw_edges, list):
        for edge in raw_edges:
            if not isinstance(edge, dict):
                continue
            source, target = edge.get("source"), edge.get("target")
            if source not in nodes or target not in nodes or source == target:
                continue
            incoming[target].append(edge)
            outgoing[source].append(edge)

    def edge_key(edge: dict) -> tuple:
        return (
            _RELATION_PRIORITY.get(str(edge.get("relation")), 99),
            _number(edge.get("at")),
            str(edge.get("source", "")),
        )

    parents: dict[str, str] = {}
    parent_relations: dict[str, str] = {}
    for target, edges in incoming.items():
        for edge in sorted(edges, key=edge_key):
            source = str(edge["source"])
            # Reject any candidate that would create a parent cycle.
            cursor = source
            seen = {target}
            cyclic = False
            while cursor in parents:
                if cursor in seen:
                    cyclic = True
                    break
                seen.add(cursor)
                cursor = parents[cursor]
            if cyclic or cursor == target:
                continue
            parents[target] = source
            parent_relations[target] = str(edge.get("relation") or "")
            break

    children: dict[str, list[str]] = defaultdict(list)
    for child, parent in parents.items():
        children[parent].append(child)

    def node_key(node_id: str) -> tuple:
        node = nodes[node_id]
        return (_number(node.get("at")), str(node.get("kind", "")), node_id)

    for values in children.values():
        values.sort(key=node_key)

    roots = [node_id for node_id in nodes if node_id not in parents]
    roots.sort(key=node_key)
    rows: list[dict] = []
    visited: set[str] = set()

    def walk(node_id: str, depth: int) -> None:
        if node_id in visited:
            return
        visited.add(node_id)
        node = nodes[node_id]
        relations = sorted({
            str(edge.get("relation") or "")
            for edge in incoming.get(node_id, [])
            if edge.get("relation")
        })
        rows.append({
            "id": node_id,
            "parent": parents.get(node_id, ""),
            "depth": depth,
            "relation": parent_relations.get(node_id, ""),
            "relations": relations,
            "kind": str(node.get("kind") or "unknown"),
            "label": str(node.get("label") or node_id),
            "at": _number(node.get("at")),
            "data": node.get("data") if isinstance(node.get("data"), dict) else {},
        })
        for child in children.get(node_id, []):
            walk(child, depth + 1)

    for root in roots:
        walk(root, 0)
    # Defensive fallback for malformed/cyclic source graphs.
    for node_id in sorted(nodes, key=node_key):
        walk(node_id, 0)
    return rows


def format_incident_when(incident: dict) -> str:
    value = incident.get("_journal_at") if isinstance(incident, dict) else None
    if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        return "—"
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


def format_node_details(row: dict) -> list[tuple[str, str]]:
    if not isinstance(row, dict):
        return []
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    preferred = (
        "pid", "ppid", "path", "image", "rule", "score", "severity", "summary",
        "classification", "scanner_verdict", "scanner_complete",
        "confirmed_threat", "behavior_score", "origin",
        "native_pre_execution", "automatic_enforcement_eligible", "changed_at",
    )
    result: list[tuple[str, str]] = []
    for key in preferred:
        if key not in data:
            continue
        value = data[key]
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        result.append((key, str(value)))
    for key in sorted(data):
        if key in preferred:
            continue
        value = data[key]
        if isinstance(value, (dict, list)):
            continue
        result.append((str(key), str(value)))
    return result


class IncidentViewer:
    """Small modal-style viewer for bounded local Incident Graph history."""

    def __init__(self, app: Any, palette: dict, incidents: list[dict], t) -> None:
        self.app = app
        self.palette = palette
        self.incidents = [item for item in incidents if isinstance(item, dict)]
        self.t = t
        self.rows: dict[str, dict] = {}
        self.selected_incident: dict | None = None
        self.response_scans: dict[str, dict] = {}
        self.response_isolations: dict[str, dict] = {}
        self.response_queue: queue.Queue = queue.Queue()
        self.response_cancel = threading.Event()
        self.response_busy = False
        self.response_after_id = None

        tk = app.tk
        self.window = tk.Toplevel(app.root)
        self.window.title(self.t("incident_viewer_title"))
        self.window.configure(bg=palette["bg"])
        self.window.geometry("1080x680")
        self.window.minsize(820, 520)
        try:
            self.window.transient(app.root)
        except Exception:
            pass

        header = tk.Frame(self.window, bg=palette["bg"])
        header.pack(fill="x", padx=18, pady=(16, 10))
        tk.Label(
            header,
            text=self.t("incident_viewer_title"),
            bg=palette["bg"],
            fg=palette["text"],
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text=self.t("incident_viewer_hint"),
            bg=palette["bg"],
            fg=palette["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(3, 0))

        body = tk.Frame(self.window, bg=palette["bg"])
        body.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        body.grid_columnconfigure(0, weight=2, minsize=250)
        body.grid_columnconfigure(1, weight=5, minsize=430)
        body.grid_rowconfigure(0, weight=1)

        left = tk.Frame(
            body, bg=palette["surface"], highlightthickness=1,
            highlightbackground=palette["border"],
        )
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)
        tk.Label(
            left,
            text=self.t("incident_list_title"),
            bg=palette["surface"],
            fg=palette["text"],
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(11, 7))

        self.incident_tree = app.ttk.Treeview(
            left,
            columns=("class", "score", "graph"),
            show="tree headings",
            selectmode="browse",
            style="AntiOS.Treeview",
        )
        self.incident_tree.heading("#0", text=self.t("incident_column_id"))
        self.incident_tree.heading("class", text=self.t("incident_column_class"))
        self.incident_tree.heading("score", text=self.t("incident_column_score"))
        self.incident_tree.heading("graph", text=self.t("incident_column_graph"))
        self.incident_tree.column("#0", width=120, stretch=True)
        self.incident_tree.column("class", width=110, stretch=True)
        self.incident_tree.column("score", width=55, anchor="center", stretch=False)
        self.incident_tree.column("graph", width=70, anchor="center", stretch=False)
        self.incident_tree.grid(row=1, column=0, sticky="nsew", padx=(1, 0), pady=(0, 1))
        left_scroll = tk.Scrollbar(left, command=self.incident_tree.yview, width=10, bd=0)
        left_scroll.grid(row=1, column=1, sticky="ns", pady=(0, 1))
        self.incident_tree.configure(yscrollcommand=left_scroll.set)
        self.incident_tree.bind("<<TreeviewSelect>>", self._select_incident)

        right = tk.Frame(
            body, bg=palette["surface"], highlightthickness=1,
            highlightbackground=palette["border"],
        )
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=3)
        right.grid_rowconfigure(3, weight=2)

        self.summary = tk.Label(
            right,
            text=self.t("incident_viewer_empty"),
            bg=palette["surface"],
            fg=palette["muted"],
            font=("Segoe UI Semibold", 9),
            anchor="w",
            justify="left",
        )
        self.summary.grid(row=0, column=0, sticky="ew", padx=12, pady=(11, 7))

        chain_frame = tk.Frame(right, bg=palette["surface"])
        chain_frame.grid(row=1, column=0, sticky="nsew", padx=1)
        chain_frame.grid_rowconfigure(0, weight=1)
        chain_frame.grid_columnconfigure(0, weight=1)
        self.chain = app.ttk.Treeview(
            chain_frame,
            columns=("relation", "kind", "offset"),
            show="tree headings",
            selectmode="browse",
            style="AntiOS.Treeview",
        )
        self.chain.heading("#0", text=self.t("incident_column_item"))
        self.chain.heading("relation", text=self.t("incident_column_relation"))
        self.chain.heading("kind", text=self.t("incident_column_type"))
        self.chain.heading("offset", text=self.t("incident_column_offset"))
        self.chain.column("#0", width=330, stretch=True)
        self.chain.column("relation", width=130, stretch=True)
        self.chain.column("kind", width=110, stretch=False)
        self.chain.column("offset", width=72, anchor="e", stretch=False)
        self.chain.grid(row=0, column=0, sticky="nsew")
        chain_scroll = tk.Scrollbar(chain_frame, command=self.chain.yview, width=10, bd=0)
        chain_scroll.grid(row=0, column=1, sticky="ns")
        self.chain.configure(yscrollcommand=chain_scroll.set)
        self.chain.bind("<<TreeviewSelect>>", self._select_node)

        tk.Label(
            right,
            text=self.t("incident_details_title"),
            bg=palette["surface"],
            fg=palette["text"],
            font=("Segoe UI", 10, "bold"),
        ).grid(row=2, column=0, sticky="w", padx=12, pady=(10, 5))

        detail_frame = tk.Frame(right, bg=palette["surface_alt"])
        detail_frame.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
        detail_frame.grid_rowconfigure(0, weight=1)
        detail_frame.grid_columnconfigure(0, weight=1)
        self.details = tk.Text(
            detail_frame,
            wrap="word",
            state="disabled",
            bg=palette["surface_alt"],
            fg=palette["text"],
            insertbackground=palette["text"],
            relief="flat",
            bd=0,
            padx=10,
            pady=8,
            font=("Consolas", 9),
        )
        self.details.grid(row=0, column=0, sticky="nsew")
        detail_scroll = tk.Scrollbar(detail_frame, command=self.details.yview, width=10, bd=0)
        detail_scroll.grid(row=0, column=1, sticky="ns")
        self.details.configure(yscrollcommand=detail_scroll.set)

        self.response_status = tk.Label(
            self.window,
            text=self.t("response_ready"),
            bg=palette["bg"],
            fg=palette["muted"],
            font=("Segoe UI", 8),
            anchor="w",
            justify="left",
        )
        self.response_status.pack(fill="x", padx=18, pady=(0, 6))

        footer = tk.Frame(self.window, bg=palette["bg"])
        footer.pack(fill="x", padx=18, pady=(0, 14))
        response_actions = tk.Frame(footer, bg=palette["bg"])
        response_actions.pack(side="left")

        self.rescan_button = app._button(
            response_actions, self.t("response_rescan"), self._rescan_incident,
            kind="primary",
        )
        self.rescan_button.pack(side="left")
        self.isolate_button = app._button(
            response_actions, self.t("response_isolate"), self._isolate_confirmed,
            kind="danger",
        )
        self.isolate_button.pack(side="left", padx=(6, 0))
        self.reveal_button = app._button(
            response_actions, self.t("response_reveal"), self._reveal_selected,
            kind="secondary",
        )
        self.reveal_button.pack(side="left", padx=(6, 0))
        self.report_button = app._button(
            response_actions, self.t("response_export"), self._export_incident,
            kind="secondary",
        )
        self.report_button.pack(side="left", padx=(6, 0))

        app._button(
            footer, self.t("incident_close"), self._close, kind="secondary"
        ).pack(side="right")

        self.window.protocol("WM_DELETE_WINDOW", self._close)
        self._populate_incidents()
        self._sync_response_buttons()
        self.response_after_id = self.window.after(100, self._poll_response)

    def _populate_incidents(self) -> None:
        for index, incident in enumerate(self.incidents):
            incident_id = str(incident.get("id") or f"incident-{index}")
            self.incident_tree.insert(
                "", "end", iid=incident_id,
                text=incident_id,
                values=(
                    self.t("risk_" + str(incident.get("classification")))
                    if str(incident.get("classification")) in {
                        "low", "observe", "elevated", "high",
                        "critical-behavior", "confirmed-threat",
                    }
                    else str(incident.get("classification") or "—"),
                    incident.get("score", 0),
                    f"{incident.get('node_count', 0)}/{incident.get('edge_count', 0)}",
                ),
            )
        children = self.incident_tree.get_children()
        if children:
            self.incident_tree.selection_set(children[0])
            self.incident_tree.focus(children[0])
            self._render_incident(self.incidents[0])
        else:
            self._set_details(self.t("incident_viewer_empty"))

    def _select_incident(self, _event=None) -> None:
        selected = self.incident_tree.selection()
        if not selected:
            return
        wanted = selected[0]
        for incident in self.incidents:
            if str(incident.get("id")) == wanted:
                self._render_incident(incident)
                return

    def _render_incident(self, incident: dict) -> None:
        self.selected_incident = incident
        self.rows.clear()
        self._sync_response_buttons()
        self.chain.delete(*self.chain.get_children())
        classification = str(incident.get("classification") or "unknown")
        label = (
            self.t("risk_" + classification)
            if classification in {
                "low", "observe", "elevated", "high",
                "critical-behavior", "confirmed-threat",
            }
            else classification
        )
        self.summary.configure(text=self.t(
            "incident_selected",
            id=incident.get("id", "—"),
            state=label,
            score=incident.get("score", 0),
            when=format_incident_when(incident),
            nodes=incident.get("node_count", 0),
            edges=incident.get("edge_count", 0),
        ))

        start = _number(incident.get("started_at"))
        graph_to_ui: dict[str, str] = {}
        for index, row in enumerate(build_incident_tree(incident)):
            ui_id = f"node-{index}"
            graph_to_ui[row["id"]] = ui_id
            self.rows[ui_id] = row
            parent = graph_to_ui.get(row["parent"], "")
            relation = self._relation(row["relation"])
            kind = self._kind(row["kind"])
            offset = max(0.0, row["at"] - start) if start else 0.0
            self.chain.insert(
                parent, "end", iid=ui_id,
                text=row["label"],
                values=(relation, kind, f"+{offset:.2f}s"),
                open=row["depth"] < 3,
            )
        roots = self.chain.get_children()
        if roots:
            self.chain.selection_set(roots[0])
            self.chain.focus(roots[0])
            self._show_node(self.rows[roots[0]])
        else:
            self._set_details(self.t("incident_viewer_empty"))

    def _relation(self, value: str) -> str:
        if not value:
            return self.t("incident_relation_root")
        known = {
            "executed-as", "spawned", "raised-signal", "correlated-write",
            "modified", "evaluated-as",
        }
        return self.t("incident_relation_" + value) if value in known else value

    def _kind(self, value: str) -> str:
        known = {"file", "file-change", "process", "behavior", "risk"}
        return self.t("incident_kind_" + value) if value in known else value

    def _select_node(self, _event=None) -> None:
        selected = self.chain.selection()
        if selected and selected[0] in self.rows:
            self._show_node(self.rows[selected[0]])

    def _show_node(self, row: dict) -> None:
        lines = [
            format_explanation(self.selected_incident, getattr(self.app, "language", "en")),
            "",
            row.get("label", ""),
            "",
            f"{self.t('incident_detail_type')}: {self._kind(row.get('kind', 'unknown'))}",
            f"{self.t('incident_detail_relation')}: {self._relation(row.get('relation', ''))}",
        ]
        relations = row.get("relations") or []
        if len(relations) > 1:
            lines.append(
                f"{self.t('incident_detail_links')}: " +
                ", ".join(self._relation(item) for item in relations)
            )
        for key, value in format_node_details(row):
            label_key = "incident_field_" + key
            translated = self.t(label_key)
            label = translated if translated != "av." + label_key else key.replace("_", " ")
            lines.append(f"{label}: {value}")
        self._set_details("\n".join(lines))
        self._sync_response_buttons()

    def _current_incident_id(self) -> str:
        if not isinstance(self.selected_incident, dict):
            return ""
        value = self.selected_incident.get("id")
        return str(value) if value else ""

    def _selected_path(self) -> str | None:
        selected = self.chain.selection()
        if not selected or selected[0] not in self.rows:
            return None
        data = self.rows[selected[0]].get("data")
        if not isinstance(data, dict):
            return None
        value = data.get("path")
        return value if isinstance(value, str) and value else None

    def _sync_response_buttons(self) -> None:
        if not hasattr(self, "rescan_button"):
            return
        incident_id = self._current_incident_id()
        has_incident = bool(incident_id and self.selected_incident)
        scan = self.response_scans.get(incident_id)
        threats = confirmed_findings(scan)
        state = "disabled" if self.response_busy else "normal"
        self.rescan_button.configure(state=state if has_incident else "disabled")
        self.report_button.configure(state=state if has_incident else "disabled")
        self.reveal_button.configure(
            state=state if self._selected_path() else "disabled"
        )
        self.isolate_button.configure(
            state="normal" if not self.response_busy and threats else "disabled"
        )

    def _rescan_incident(self) -> None:
        if self.response_busy or not self.selected_incident:
            return
        paths = incident_file_paths(self.selected_incident)
        if not paths:
            self.response_status.configure(text=self.t("response_no_paths"))
            return

        incident = self.selected_incident
        incident_id = self._current_incident_id()
        self.response_cancel.clear()
        self.response_busy = True
        self.response_status.configure(
            text=self.t("response_scanning", current=0, total=len(paths))
        )
        self._sync_response_buttons()

        def worker() -> None:
            try:
                result = scan_incident_files(
                    incident,
                    signature_path=getattr(self.app, "antivirus_signatures", None),
                    require_verified_peer=(sys.platform == "win32"),
                    cancelled=self.response_cancel.is_set,
                    progress=lambda current, total, path: self.response_queue.put(
                        ("scan-progress", incident_id, {
                            "current": current, "total": total, "path": path
                        })
                    ),
                )
                self.response_queue.put(("scan-done", incident_id, result))
            except Exception as exc:
                self.response_queue.put(("response-error", incident_id, str(exc)[:1000]))

        threading.Thread(target=worker, daemon=True).start()

    def _isolate_confirmed(self) -> None:
        if self.response_busy:
            return
        incident_id = self._current_incident_id()
        scan = self.response_scans.get(incident_id)
        findings = confirmed_findings(scan)
        if not findings:
            self._sync_response_buttons()
            return

        from tkinter import messagebox
        if not messagebox.askyesno(
            "AntiOS",
            self.t("response_isolate_confirm", count=len(findings)),
            parent=self.window,
        ):
            return

        self.response_busy = True
        self.response_status.configure(
            text=self.t("response_isolating", count=len(findings))
        )
        self._sync_response_buttons()

        def worker() -> None:
            try:
                result = isolate_confirmed_findings(scan)
                self.response_queue.put(("isolation-done", incident_id, result))
            except Exception as exc:
                self.response_queue.put(("response-error", incident_id, str(exc)[:1000]))

        threading.Thread(target=worker, daemon=True).start()

    def _reveal_selected(self) -> None:
        value = self._selected_path()
        if not value:
            return
        try:
            target = Path(value)
            location = target if target.is_dir() else target.parent
            if not location.exists():
                raise FileNotFoundError(str(location))
            if os.name != "nt" or not hasattr(os, "startfile"):
                raise OSError("Open location is available on Windows only")
            os.startfile(str(location))
        except (OSError, ValueError) as exc:
            self.response_status.configure(
                text=self.t("response_error", error=str(exc))
            )

    def _export_incident(self) -> None:
        if not self.selected_incident:
            return
        from tkinter import filedialog

        incident_id = self._current_incident_id()
        target = filedialog.asksaveasfilename(
            parent=self.window,
            defaultextension=".json",
            initialfile=f"antios-incident-{incident_id or 'report'}.json",
            filetypes=[("JSON", "*.json")],
        )
        if not target:
            return
        report = build_incident_report(
            self.selected_incident,
            response_scan=self.response_scans.get(incident_id),
            isolation=self.response_isolations.get(incident_id),
        )
        try:
            Path(target).write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self.response_status.configure(text=self.t("response_exported"))
        except OSError as exc:
            self.response_status.configure(
                text=self.t("response_error", error=str(exc))
            )

    def _poll_response(self) -> None:
        try:
            while True:
                kind, incident_id, value = self.response_queue.get_nowait()
                if kind == "scan-progress":
                    if incident_id == self._current_incident_id():
                        self.response_status.configure(text=self.t(
                            "response_scanning",
                            current=value["current"],
                            total=value["total"],
                        ))
                elif kind == "scan-done":
                    self.response_scans[incident_id] = value
                    self.response_busy = False
                    threats = len(confirmed_findings(value))
                    if incident_id == self._current_incident_id():
                        self.response_status.configure(text=self.t(
                            "response_scan_done",
                            scanned=len(value.get("results", [])),
                            threats=threats,
                            errors=len(value.get("errors", [])),
                        ))
                elif kind == "isolation-done":
                    self.response_isolations[incident_id] = value
                    self.response_busy = False
                    if incident_id == self._current_incident_id():
                        self.response_status.configure(text=self.t(
                            "response_isolate_done",
                            isolated=len(value.get("isolated", [])),
                            errors=len(value.get("errors", [])),
                        ))
                elif kind == "response-error":
                    self.response_busy = False
                    if incident_id == self._current_incident_id():
                        self.response_status.configure(
                            text=self.t("response_error", error=value)
                        )
                self._sync_response_buttons()
        except queue.Empty:
            pass

        try:
            if self.window.winfo_exists():
                self.response_after_id = self.window.after(100, self._poll_response)
        except Exception:
            self.response_after_id = None

    def _close(self) -> None:
        self.response_cancel.set()
        if self.response_after_id is not None:
            try:
                self.window.after_cancel(self.response_after_id)
            except Exception:
                pass
            self.response_after_id = None
        try:
            self.window.destroy()
        except Exception:
            pass

    def _set_details(self, value: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", value)
        self.details.configure(state="disabled")
