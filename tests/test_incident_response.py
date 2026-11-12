from pathlib import Path

import pytest

from antios.incident_response import (
    MAX_RESPONSE_PATHS,
    build_incident_report,
    confirmed_findings,
    incident_file_paths,
    isolate_confirmed_findings,
    scan_incident_files,
)


def incident(paths, *, score=95, classification="critical-behavior"):
    nodes = []
    for index, value in enumerate(paths):
        nodes.append({
            "id": f"file:{index}",
            "kind": "file",
            "label": value,
            "at": 1.0 + index,
            "data": {"path": value},
        })
    return {
        "id": "INC-TEST",
        "score": score,
        "classification": classification,
        "nodes": nodes,
        "edges": [],
    }


def scan_result(path, findings=None):
    return {
        "verdict": "threats-found" if findings else "no-threats-found",
        "coverage": "antios-local-inspection",
        "findings": findings or [],
        "issues": [],
        "summary": {"files_scanned": 1, "threats": len(findings or [])},
        "engine": {"provider": "AntiOS Engine", "database_freshness": "local"},
        "path": str(path),
    }


def finding(path, *, kind="threat", digest="a" * 64):
    return {
        "kind": kind,
        "engine": "AntiOS Engine",
        "name": "Inert.Test",
        "path": str(path),
        "sha256": digest,
        "size": 4,
        "fingerprint": [1, 2, 4, 5],
    }


def test_incident_paths_are_absolute_unique_bounded_and_ignore_labels():
    value = incident([
        r"C:\Users\A\Downloads\payload.exe",
        r"c:\users\a\downloads\PAYLOAD.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "relative.exe",
    ])
    value["nodes"].append({
        "id": "behavior:1",
        "kind": "behavior",
        "label": r"C:\Should\Not\Be\Used.exe",
        "data": {"path": r"C:\Should\Not\Be\Used.exe"},
    })
    assert incident_file_paths(value) == [
        r"C:\Users\A\Downloads\payload.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ]

    many = incident([fr"C:\Data\file-{index}.exe" for index in range(100)])
    assert len(incident_file_paths(many)) == MAX_RESPONSE_PATHS
    with pytest.raises(ValueError):
        incident_file_paths(value, limit=0)


def test_response_scan_is_read_only_and_collects_per_path_errors():
    value = incident([r"C:\Data\a.exe", r"C:\Data\b.exe"])
    calls = []

    def scanner(path, **kwargs):
        calls.append((str(path), kwargs))
        if str(path).lower().endswith("b.exe"):
            raise OSError("vanished")
        return scan_result(path)

    progress = []
    result = scan_incident_files(
        value,
        scanner=scanner,
        require_verified_peer=True,
        progress=lambda current, total, path: progress.append((current, total, path)),
    )
    assert len(calls) == 2
    assert all(call[1]["engine"] == "antios" for call in calls)
    assert all(call[1]["require_verified_peer"] is True for call in calls)
    assert len(result["results"]) == 1
    assert result["errors"][0]["path"].lower().endswith("b.exe")
    assert progress[0][:2] == (1, 2)
    assert progress[-1][:2] == (2, 2)


def test_behavior_only_incident_cannot_be_isolated_without_fresh_threat():
    value = incident([r"C:\Data\suspicious.exe"], score=95)
    response = {
        "incident_id": value["id"],
        "results": [{
            "path": r"C:\Data\suspicious.exe",
            "result": scan_result(r"C:\Data\suspicious.exe"),
        }],
        "errors": [],
    }

    class Vault:
        def __init__(self):
            raise AssertionError("Quarantine must not be constructed without confirmed findings")

    assert confirmed_findings(response) == []
    result = isolate_confirmed_findings(response, quarantine_factory=Vault)
    assert result["attempted"] == 0
    assert result["isolated"] == []
    assert result["errors"] == []


def test_only_confirmed_threat_findings_are_offered_for_isolation():
    threat = finding(r"C:\Data\bad.exe")
    review = finding(r"C:\Data\review.exe", kind="review", digest="b" * 64)
    response = {
        "incident_id": "INC-TEST",
        "results": [
            {"path": threat["path"], "result": scan_result(threat["path"], [threat, review])},
            # Duplicate threat must not create a second destructive attempt.
            {"path": threat["path"], "result": scan_result(threat["path"], [dict(threat)])},
        ],
        "errors": [],
    }
    assert confirmed_findings(response) == [threat]

    added = []
    class Vault:
        def add(self, value, *, dry_run):
            assert value["kind"] == "threat"
            assert dry_run is False
            added.append(value)
            return {"id": "isolated-1", "original_path": value["path"]}

    result = isolate_confirmed_findings(response, quarantine_factory=Vault)
    assert result["attempted"] == 1
    assert len(result["isolated"]) == 1
    assert added == [threat]


def test_isolation_preserves_per_file_revalidation_failures():
    threat = finding(r"C:\Data\changed.exe")
    response = {
        "incident_id": "INC-TEST",
        "results": [{"path": threat["path"], "result": scan_result(threat["path"], [threat])}],
        "errors": [],
    }

    class Vault:
        def add(self, value, *, dry_run):
            raise ValueError("File changed after scanning; rescan before quarantining")

    result = isolate_confirmed_findings(response, quarantine_factory=Vault)
    assert result["attempted"] == 1
    assert result["isolated"] == []
    assert "changed after scanning" in result["errors"][0]["error"]


def test_incident_report_records_response_and_safety_boundary():
    value = incident([r"C:\Data\a.exe"])
    response = {"incident_id": "INC-TEST", "results": [], "errors": []}
    isolation = {"incident_id": "INC-TEST", "attempted": 0, "isolated": [], "errors": []}
    report = build_incident_report(value, response_scan=response, isolation=isolation)
    assert report["kind"] == "antios-incident-report"
    assert report["incident"]["id"] == "INC-TEST"
    assert report["response"]["scan"] is response
    assert report["response"]["isolation"] is isolation
    assert report["safety"]["behavior_only_auto_enforcement"] is False
    assert report["safety"]["isolation_requires_fresh_confirmed_scan_finding"] is True



def test_malformed_threat_is_not_quarantine_eligible():
    malformed = finding(r"C:\Data\bad.exe")
    malformed.pop("fingerprint")
    response = {
        "incident_id": "INC-TEST",
        "results": [{
            "path": malformed["path"],
            "result": scan_result(malformed["path"], [malformed]),
        }],
        "errors": [],
    }
    assert confirmed_findings(response) == []
