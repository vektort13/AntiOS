from antios import coexistence


def test_layered_mode_requires_active_defender_and_never_claims_primary():
    defender = {
        "available": True,
        "service_enabled": True,
        "antivirus_enabled": True,
        "real_time_protection": True,
    }
    wsc = {"available": True, "health": "good"}
    amsi = {"registered": True, "module_exists": True}
    result = coexistence.evaluate_coexistence(defender, wsc, amsi)
    assert result["mode"] == "layered-with-defender"
    assert result["defender_active_parallel"] is True
    assert result["amsi_provider_registered"] is False
    assert result["legacy_amsi_registration_detected"] is True
    assert result["antios_primary_wsc_registration"] is False
    assert result["defender_changes_required"] is False


def test_missing_defender_realtime_never_becomes_layered():
    result = coexistence.evaluate_coexistence(
        {"available": True, "service_enabled": True, "antivirus_enabled": True,
         "real_time_protection": False},
        {"available": True, "health": "good"},
        {"registered": False, "module_exists": False},
    )
    assert result["mode"] == "defender-present-not-realtime"
    assert result["defender_active_parallel"] is False
    assert result["amsi_provider_registered"] is False


def test_render_states_invariants():
    payload = {
        "coexistence": {
            "mode": "layered-with-defender",
            "defender_active_parallel": True,
            "antios_primary_wsc_registration": False,
        },
        "defender": {"running_mode": "Normal"},
        "windows_security": {"health": "good"},
        "antios_amsi": {"registered": True},
    }
    rendered = coexistence.render_coexistence_status(payload)
    assert "AntiOS primary WSC registration: no" in rendered
    assert "Defender settings changed by AntiOS: no" in rendered
    assert "Legacy AntiOS AMSI registration: detected (requires migration)" in rendered
