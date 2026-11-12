import importlib.util
import os
import time

import pytest

from antios.guard_state import GuardState, read_incident_history
from antios.incident_viewer import (
    IncidentViewer,
    build_incident_tree,
    format_incident_when,
    format_node_details,
)


def fixture_incident(incident_id="INC-000001", score=85):
    return {
        "id": incident_id,
        "started_at": 100.0,
        "updated_at": 104.0,
        "score": score,
        "classification": "high",
        "confirmed_threat": False,
        "automatic_enforcement_eligible": False,
        "node_count": 4,
        "edge_count": 3,
        "_journal_at": 1_700_000_000.0,
        "nodes": [
            {
                "id": "file:payload",
                "kind": "file",
                "label": r"C:\Users\A\Downloads\payload.exe",
                "at": 100.0,
                "data": {"path": r"C:\Users\A\Downloads\payload.exe"},
            },
            {
                "id": "process:500",
                "kind": "process",
                "label": "payload.exe",
                "at": 101.0,
                "data": {"pid": 500, "ppid": 100, "image": "payload.exe"},
            },
            {
                "id": "process:501",
                "kind": "process",
                "label": "powershell.exe",
                "at": 102.0,
                "data": {"pid": 501, "ppid": 500, "image": "powershell.exe"},
            },
            {
                "id": "risk:1",
                "kind": "risk",
                "label": "high",
                "at": 104.0,
                "data": {
                    "score": score,
                    "classification": "high",
                    "scanner_verdict": "no-threats-found",
                    "scanner_complete": True,
                    "origin": "downloads",
                    "native_pre_execution": "active",
                    "automatic_enforcement_eligible": False,
                },
            },
        ],
        "edges": [
            {
                "source": "file:payload",
                "target": "process:500",
                "relation": "executed-as",
                "at": 101.0,
            },
            {
                "source": "process:500",
                "target": "process:501",
                "relation": "spawned",
                "at": 102.0,
            },
            {
                "source": "file:payload",
                "target": "risk:1",
                "relation": "evaluated-as",
                "at": 104.0,
            },
        ],
    }


def test_incident_tree_builds_causal_spanning_forest_without_mutating_graph():
    incident = fixture_incident()
    original_edges = [dict(edge) for edge in incident["edges"]]
    rows = build_incident_tree(incident)
    by_id = {row["id"]: row for row in rows}

    assert by_id["file:payload"]["parent"] == ""
    assert by_id["process:500"]["parent"] == "file:payload"
    assert by_id["process:500"]["relation"] == "executed-as"
    assert by_id["process:501"]["parent"] == "process:500"
    assert by_id["process:501"]["relation"] == "spawned"
    assert by_id["risk:1"]["parent"] == "file:payload"
    assert by_id["risk:1"]["relation"] == "evaluated-as"
    assert incident["edges"] == original_edges


def test_incident_tree_preserves_extra_incoming_relations_as_metadata():
    incident = fixture_incident()
    incident["edges"].append({
        "source": "process:501",
        "target": "risk:1",
        "relation": "raised-signal",
        "at": 103.0,
    })
    row = next(item for item in build_incident_tree(incident) if item["id"] == "risk:1")
    assert set(row["relations"]) == {"evaluated-as", "raised-signal"}


def test_node_details_are_human_readable_and_bounded_to_scalar_fields():
    row = next(item for item in build_incident_tree(fixture_incident()) if item["id"] == "risk:1")
    details = dict(format_node_details(row))
    assert details["score"] == "85"
    assert details["scanner_verdict"] == "no-threats-found"
    assert details["scanner_complete"] == "True"
    assert details["origin"] == "downloads"


def test_incident_history_deduplicates_snapshots_and_uses_wall_clock_order(tmp_path):
    folder = tmp_path / "guard"
    store = GuardState(folder)
    older = fixture_incident("INC-OLD", 60)
    older["updated_at"] = 999999.0  # monotonic from a hypothetical previous boot
    newer_v1 = fixture_incident("INC-NEW", 70)
    newer_v2 = fixture_incident("INC-NEW", 90)
    newer_v2["classification"] = "critical-behavior"
    newer_v2["node_count"] = 8

    store.event("incident-update", {"reason": "first", "incident": older})
    time.sleep(0.01)
    store.event("incident-update", {"reason": "seed", "incident": newer_v1})
    time.sleep(0.01)
    store.event("incident-update", {"reason": "escalated", "incident": newer_v2})
    store.publish({
        "running": True,
        "heartbeat": time.time(),
        "incidents": {"latest": newer_v2},
    })
    store.close()

    values = read_incident_history(folder, limit=10)
    assert [item["id"] for item in values] == ["INC-NEW", "INC-OLD"]
    assert values[0]["score"] == 90
    assert values[0]["node_count"] == 8
    assert "_journal_at" in values[0]
    assert values[0]["_journal_at"] > values[1]["_journal_at"]


def test_incident_history_validates_limit_and_empty_database(tmp_path):
    assert read_incident_history(tmp_path / "missing") == []
    with pytest.raises(ValueError):
        read_incident_history(tmp_path / "missing", limit=0)
    with pytest.raises(ValueError):
        read_incident_history(tmp_path / "missing", limit=101)


def test_format_incident_when_uses_journal_wall_clock():
    value = format_incident_when({"_journal_at": 1_700_000_000.0})
    assert value != "—"
    assert len(value) == 19
    assert format_incident_when({}) == "—"


@pytest.mark.skipif(
    importlib.util.find_spec("tkinter") is None or
    (os.name != "nt" and not os.environ.get("DISPLAY")),
    reason="Native Tk display unavailable",
)
def test_real_tk_incident_viewer_renders_history_tree_and_details():
    import tkinter as tk
    from tkinter import ttk

    from antios.antivirus_i18n import MESSAGES

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Native Tk runtime unavailable: {exc}")
    root.withdraw()

    class App:
        def __init__(self):
            self.root = root
            self.tk = tk
            self.ttk = ttk

        def _button(self, parent, text, command, kind="secondary"):
            return tk.Button(parent, text=text, command=command)

    incident = fixture_incident()
    palette = {
        "bg": "#101010",
        "surface": "#181818",
        "surface_alt": "#202020",
        "border": "#333333",
        "text": "#f0f0f0",
        "muted": "#aaaaaa",
    }
    t = lambda key, **values: MESSAGES["en"].get(key, "av." + key).format(**values)

    try:
        viewer = IncidentViewer(App(), palette, [incident], t)
        root.update()
        assert len(viewer.incident_tree.get_children()) == 1
        assert len(viewer.chain.get_children()) >= 1
        assert str(viewer.rescan_button["state"]) == "normal"
        assert str(viewer.isolate_button["state"]) == "disabled"
        assert str(viewer.report_button["state"]) == "normal"

        process_item = next(
            iid for iid, row in viewer.rows.items()
            if row["id"] == "process:500"
        )
        viewer.chain.selection_set(process_item)
        viewer._select_node()
        details = viewer.details.get("1.0", "end")
        assert "PID: 500" in details
        assert "payload.exe" in details
        # A process node without an explicit data.path must not guess a target
        # from its display label.
        assert str(viewer.reveal_button["state"]) == "disabled"

        file_item = next(
            iid for iid, row in viewer.rows.items()
            if row["id"] == "file:payload"
        )
        viewer.chain.selection_set(file_item)
        viewer._select_node()
        assert str(viewer.reveal_button["state"]) == "normal"

        incident_id = incident["id"]
        viewer.response_scans[incident_id] = {
            "incident_id": incident_id,
            "results": [{
                "path": r"C:\Users\A\Downloads\payload.exe",
                "result": {
                    "findings": [{
                        "kind": "threat",
                        "name": "Inert.Test",
                        "path": r"C:\Users\A\Downloads\payload.exe",
                        "sha256": "a" * 64,
                        "fingerprint": [1, 2, 3, 4],
                    }]
                },
            }],
            "errors": [],
        }
        viewer._sync_response_buttons()
        assert str(viewer.isolate_button["state"]) == "normal"

        viewer._close()
        root.update()
    finally:
        root.destroy()
