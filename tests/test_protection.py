"""Truthful native AntiOS protection contracts, without external engine mocks."""
from __future__ import annotations

import pytest

from antios import protection


def _active_defender():
    return {
        "available": True,
        "running_mode": "Normal",
        "antivirus_enabled": True,
        "real_time_protection_enabled": True,
        "realtime_active": True,
    }


def _guard(*, state="monitoring", running=True, **overrides):
    return {"running": running, "state": state, "capacity_exceeded": False,
            "inventory_issues": [], "behavior_alerts_dropped": 0,
            **overrides}


def test_bundled_engine_reports_local_database_and_no_external_updater():
    status = protection._managed_runtime_status()
    assert status["available"] is True
    assert status["healthy"] is True
    assert status["kind"] == "bundled-antios-engine"
    assert status["updater_task"]["not_required"] is True


def test_protection_status_uses_our_engine_without_clamav_amsi_or_private_core(monkeypatch):
    from antios import windows_defender

    def forbidden(*_args, **_kwargs):
        raise AssertionError("External engine must not be invoked")

    monkeypatch.setattr(windows_defender, "defender_action", forbidden)
    monkeypatch.setattr(protection, "read_guard_state", lambda: _guard())
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    status = protection.collect_protection_status()
    assert status["engine"]["version"].startswith("AntiOS Engine/")
    assert status["engine"]["database_freshness"] == "local"
    assert status["capabilities"]["standalone_detection_engine"]
    assert status["capabilities"]["resident_post_write_detection"]
    assert status["capabilities"]["pre_execution_blocking"] is False
    assert status["capabilities"]["amsi_provider_registered"] is False
    assert status["production_primary_antivirus"] is False


def test_engine_failure_never_reports_full_protection(monkeypatch):
    def missing_signatures():
        raise ValueError("corrupt signature database")

    monkeypatch.setattr(protection, "load_managed_signatures", missing_signatures)
    monkeypatch.setattr(protection, "read_guard_state", lambda: _guard())
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    result = protection.collect_protection_status()
    assert not result["capabilities"]["standalone_detection_engine"]
    assert not result["capabilities"]["resident_post_write_detection"]
    assert result["capabilities"]["pre_execution_blocking"] is False
    assert result["engine"]["available"] is False


@pytest.mark.parametrize("state,extra", [
    ("degraded", {}),
    ("failed", {}),
    ("monitoring", {"capacity_exceeded": True}),
    ("monitoring", {"inventory_issues": ["incomplete scan"]}),
    ("monitoring", {"behavior_alerts_dropped": 1}),
])
def test_unhealthy_guard_not_counted_as_full_resident_detection(monkeypatch, state, extra):
    monkeypatch.setattr(protection, "read_guard_state", lambda: _guard(state=state, **extra))
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    status = protection.collect_protection_status()
    assert status["capabilities"]["standalone_detection_engine"]
    assert status["capabilities"]["resident_post_write_detection"] is False
    assert status["capabilities"]["layered_with_defender"] is False
    assert "resident-post-write-guard" in status["remaining_gates"]


def test_defender_is_read_only_companion_and_not_a_native_engine(monkeypatch):
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: _guard(state="not-running", running=False))
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    status = protection.collect_protection_status()
    assert status["capabilities"]["defender_realtime_active"] is True
    assert status["capabilities"]["layered_with_defender"] is False
    assert status["coexistence"]["primary_antivirus_registration"] is False
    assert status["production_primary_antivirus"] is False
    rendered = protection.render_protection_status(status)
    assert "Primary Windows antivirus registration: not claimed" in rendered
    assert "AntiOS Engine" in rendered


def test_native_pre_execution_is_never_claimed_from_an_unrelated_driver():
    old = {
        "available": True,
        "service": {"service_state": 4, "exit_code": 0},
        "driver": {"driver_available": True, "exit_code": 0, "enforcement": 1},
    }
    assert protection.native_pre_execution_active(old) is None
    native = protection._native_coexistence_health(True, old["driver"])
    assert native["configured"] is False
    assert native["observed"] is False


def test_behavior_monitoring_stays_advisory(monkeypatch):
    monkeypatch.setattr(protection, "read_guard_state", lambda: _guard(
        state="attention",
        behavior={"mode": "detect-only", "state": "attention",
                  "collector": "toolhelp-snapshot",
                  "highest_score": 85, "recent_findings": 1},
    ))
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    status = protection.collect_protection_status()
    assert status["capabilities"]["behavior_monitoring"] is True
    assert status["capabilities"]["behavior_process_visibility"] is True
    assert status["capabilities"]["pre_execution_blocking"] is False
    assert "Behavior monitor: attention" in protection.render_protection_status(status)


def test_risk_correlation_keeps_manual_only_evidence(monkeypatch):
    monkeypatch.setattr(protection, "read_guard_state", lambda: _guard(
        state="attention",
        risk={"mode": "fusion", "evaluations": 1,
              "last": {"classification": "high", "score": 80,
                       "origin": "downloads", "automatic_enforcement_eligible": False}},
        incidents={"mode": "correlation-graph", "state": "attention",
                   "latest": {"id": "INC-000001", "node_count": 2, "edge_count": 1}},
    ))
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    result = protection.collect_protection_status()
    assert result["capabilities"]["risk_fusion"]
    assert result["capabilities"]["incident_graph"]
    assert result["risk"]["last"]["automatic_enforcement_eligible"] is False
    assert result["capabilities"]["pre_execution_blocking"] is False


def test_unreadable_guard_is_not_masked_as_healthy(monkeypatch):
    def denied():
        raise PermissionError("Guard access denied")

    monkeypatch.setattr(protection, "read_guard_state", denied)
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    result = protection.collect_protection_status()
    assert result["engine"]["available"] is True
    assert result["guard"]["state"] == "unavailable"
    assert result["capabilities"]["resident_post_write_detection"] is False
    assert result["capabilities"]["layered_with_defender"] is False
