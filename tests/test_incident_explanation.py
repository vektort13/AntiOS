import copy

from antios.incident_explanation import explain_incident, format_explanation


def test_high_score_never_becomes_a_confirmed_detection():
    incident = {"score": 100, "classification": "confirmed-threat", "confirmed_threat": False,
                "nodes": [{"id": "behavior1", "kind": "behavior", "data": {"rule": "mass-file-changes"}}]}
    original = copy.deepcopy(incident)
    report = explain_incident(incident)
    assert report["confirmed"] is False
    assert "не подтверждают" in report["summary"]
    assert report["reasons"][0]["node_id"] == "behavior1"
    assert any("снимком" in action for action in report["actions"])
    assert incident == original


def test_temporal_correlation_is_not_stated_as_causation():
    incident = {"nodes": [{"data": {"rule": "interpreter-with-mass-file-changes"}}]}
    assert "не доказывает" in explain_incident(incident)["reasons"][0]["text"]
    assert "does not prove" in explain_incident(incident, "en")["reasons"][0]["text"]


def test_incomplete_scan_prioritizes_self_check_and_retains_confirmed_evidence():
    report = explain_incident({"confirmed_threat": True, "nodes": [
        {"kind": "risk", "data": {"scanner_complete": False}}]})
    assert report["confirmed"] and report["incomplete_scan"]
    assert "самопроверку" in report["actions"][0]


def test_unknown_or_malformed_evidence_is_bounded_without_inventing_a_rule():
    report = explain_incident({"nodes": [None, "text", {"data": {"rule": "new-rule"}}] * 300})
    assert len(report["reasons"]) == 1
    assert report["reasons"][0]["code"] == "new-rule"
    assert "дополнительный" in report["reasons"][0]["text"]
    assert "Недостаточно данных" in format_explanation({})
