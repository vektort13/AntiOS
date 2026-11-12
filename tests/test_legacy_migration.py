"""Old engine migration is read-only, bounded and never changes AV services."""
from antios import protection


def test_no_legacy_registration_does_not_claim_unverified_full_install():
    def missing(_path, _name):
        raise FileNotFoundError("not installed")

    result = protection._legacy_registration_status(reader=missing)
    assert result["state"] == "none-observed"
    assert result["markers"] == []
    assert result["read_only"] is True


def test_old_service_binding_and_amsi_provider_require_migration():
    observed = []
    def registered(path, name):
        observed.append((path, name))
        if path == r"SOFTWARE\AntiOS" and name == "EngineServiceName":
            return "clamd"
        if path.startswith(r"SOFTWARE\Microsoft\AMSI\Providers"):
            return "legacy provider"
        raise FileNotFoundError()

    result = protection._legacy_registration_status(reader=registered)
    assert result["state"] == "attention"
    assert result["markers"] == ["amsi-registration", "service-binding"]
    assert len(observed) == 4
    assert all(name in {"EngineServiceName", ""} for _, name in observed)


def test_unreadable_registry_never_reports_clean():
    def unreadable(path, _name):
        if path == r"SOFTWARE\AntiOS":
            raise PermissionError("access denied")
        raise FileNotFoundError()

    result = protection._legacy_registration_status(reader=unreadable)
    assert result["state"] == "incomplete"
    assert result["inspection_complete"] is False


def test_legacy_registration_does_not_become_engine_capability(monkeypatch):
    monkeypatch.setattr(protection, "_legacy_registration_status",
                        lambda: {"state": "attention", "markers": ["amsi-registration"],
                                 "inspection_complete": True})
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"running": False, "state": "not-running"})
    monkeypatch.setattr(protection, "defender_status",
                        lambda: {"available": False, "realtime_active": False})
    status = protection.collect_protection_status()
    assert status["legacy_registrations"]["state"] == "attention"
    assert "legacy-engine-registration-requires-migration" in status["remaining_gates"]
    assert status["capabilities"]["amsi_provider_registered"] is False
    assert status["capabilities"]["pre_execution_blocking"] is False
    assert status["production_primary_antivirus"] is False
    assert "Legacy registration markers: attention" in protection.render_protection_status(status)
