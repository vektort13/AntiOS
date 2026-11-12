"""Guard opt-in to the shared AntiOS scan interface stays backwards compatible."""
from __future__ import annotations

import json

import pytest

from antios import guard, scan_process


def test_guard_policy_defaults_to_independent_antios(tmp_path):
    assert guard.GuardPolicy((tmp_path,)).scan_engine == "antios"
    with pytest.raises(ValueError, match="scan engine"):
        guard.GuardPolicy((tmp_path,), scan_engine="unknown").validate()


def test_guard_policy_reads_explicit_unified_mode(tmp_path):
    document = tmp_path / "guard-policy.json"
    document.write_text(json.dumps({
        "schema": 1,
        "roots": [str(tmp_path)],
        "auto_quarantine": False,
        "scan_engine": "antios",
    }), encoding="utf-8")
    policy = guard.load_policy(document)
    assert policy.scan_engine == "antios"
    assert policy.validate() == (tmp_path,)


def test_guard_can_forward_unified_mode_to_isolated_worker(tmp_path, monkeypatch):
    root = tmp_path / "watch"
    root.mkdir()
    arguments = []

    def fake_worker(path, **kwargs):
        arguments.append((path, kwargs))
        return {"summary": {"files_scanned": 0}}

    monkeypatch.setattr(guard, "run_scan_process", fake_worker)

    class SilentSampler:
        def poll(self):
            return []

    instance = guard.Guard(
        guard.GuardPolicy((root,), scan_engine="antios"),
        state_dir=tmp_path / "state",
        process_sampler=SilentSampler(),
        native_probe=lambda: None,
    )
    instance.scanner(root / "fixture", engine=instance.policy.scan_engine)
    assert arguments[0][1]["engine"] == "antios"


def test_unified_child_worker_keeps_streaming_limits(tmp_path, monkeypatch):
    request, events = tmp_path / "request.json", tmp_path / "events.jsonl"
    request.write_text(json.dumps({"path": str(tmp_path), "engine": "antios"}))
    observed = {}
    monkeypatch.setattr(
        scan_process, "scan_files",
        lambda _path, **kwargs: observed.update(kwargs),
    )
    assert scan_process.worker_main(str(request), str(events)) == 0
    assert observed["engine"] == "antios"
    assert observed["max_bytes"] is None


def test_native_guard_engine_probe_does_not_contact_clamav(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Native guard unexpectedly used ClamAV")
    import socket
    monkeypatch.setattr(socket, "create_connection", forbidden)
    metadata = guard.probe_engine(scan_engine="antios")
    assert metadata["available"] is True
    assert metadata["database_freshness"] == "local"
    assert metadata["version"].startswith("AntiOS Engine/")
