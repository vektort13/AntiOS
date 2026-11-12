import json

from antios import tray


def test_dashboard_presence_heartbeat_expires(tmp_path, monkeypatch):
    path = tmp_path / "dashboard-tray.json"
    monkeypatch.setattr(tray, "_presence_path", lambda: path)
    monkeypatch.setattr(tray.time, "time", lambda: 100.0)

    tray.mark_dashboard_presence()
    assert tray.dashboard_presence_active(now=110.0)
    assert not tray.dashboard_presence_active(now=116.0)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["pid"] > 0
    tray.clear_dashboard_presence()
    assert not path.exists()


def test_guard_tray_variant_marks_missing_protection_as_alert():
    for state in ("failed", "unresponsive", "stopped", "not-running", "degraded", "attention"):
        assert tray.tray_variant(state) == "alert"
    assert tray.tray_variant("monitoring") == "ok"
