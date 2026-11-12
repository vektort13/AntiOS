from copy import deepcopy
import hashlib
import json

import pytest

from antios import antivirus, cli
from antios.scan_verdict import replay_scan_json, replay_scan_report


@pytest.fixture
def mixed_scan(tmp_path):
    folder = tmp_path / "scanned"
    folder.mkdir()
    content = b"Inert signature fixture"
    (folder / "match.txt").write_bytes(content)
    (folder / "unsupported.7z").write_bytes(b"Inert unsupported archive")
    signatures = tmp_path / "test-signatures.json"
    signatures.write_text(json.dumps({"schema": 1, "sha256": {
        hashlib.sha256(content).hexdigest(): "Test-only signature",
    }}))
    return antivirus.scan_files(folder, signature_path=signatures, use_cache=False)


def test_receipt_replays_signature_and_partial_coverage_independently(mixed_scan):
    replayed = replay_scan_report(mixed_scan)
    assert replayed["verdict"] == "threats-found"
    assert replayed["dimensions"] == {
        "maliciousness": "confirmed-signature", "certainty": "confirmed-detection", "coverage": "limited",
        "severity": "high-priority", "remediation_confidence": "requires-file-revalidation",
    }
    assert mixed_scan["proof_receipt"]["evidence"]["advisory_findings"] == 0
    assert mixed_scan["proof_receipt"]["evidence"]["coverage"]["file_gaps"] == {"unsupported-archive-format": 1}


def test_replay_ignores_record_order_and_post_scan_annotations(mixed_scan):
    original = replay_scan_report(mixed_scan)
    mixed_scan["findings"].reverse()
    mixed_scan["finished_at"] = "updated-display-timestamp"
    match = next(item for item in mixed_scan["findings"] if item["kind"] == "threat")
    match["quarantined"] = "separate-user-action"
    assert replay_scan_report(mixed_scan) == original


@pytest.mark.parametrize("mutate", [
    lambda report: report["findings"][0].update(name="Changed finding"),
    lambda report: report["coverage_contract"].update(status="complete"),
    lambda report: report["engine"].update(signatures_sha256="0" * 64),
    lambda report: report["decision"]["dimensions"].update(severity="none-observed"),
    lambda report: report["summary"].update(threats=0),
])
def test_replay_rejects_changed_evidence_or_decision(mixed_scan, mutate):
    changed = deepcopy(mixed_scan)
    mutate(changed)
    with pytest.raises(ValueError):
        replay_scan_report(changed)


def test_cli_replays_report_after_input_is_removed(tmp_path, capsys):
    target = tmp_path / "ordinary.txt"
    target.write_bytes(b"Harmless text")
    report = antivirus.scan_files(target)
    target.unlink()
    exported = tmp_path / "scan.json"
    exported.write_text(json.dumps(report), encoding="utf-8")

    assert cli.main(["virus-scan-replay", str(exported), "--json"]) == 0
    replayed = json.loads(capsys.readouterr().out)
    assert replayed["verified"]
    assert replayed["verdict"] == "no-threats-found"
    assert replayed["receipt_sha256"] == report["proof_receipt"]["sha256"]


def test_replay_rejects_legacy_reports_and_duplicate_json_fields():
    with pytest.raises(ValueError, match="no supported proof receipt"):
        replay_scan_report({"schema": 1, "kind": "antivirus-scan"})
    with pytest.raises(ValueError, match="Invalid scan report JSON"):
        replay_scan_json(b'{"schema":1,"schema":1}')


def test_benchmark_cli_checks_all_control_cases_and_stable_replay(capsys):
    assert cli.main(["virus-scan-benchmark", "--repeat", "2", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert set(result["profiles"]) == {"light", "balanced", "heavy"}
    assert all(item["passed"] == item["total"] == 10 and item["stable_replay"]
               for item in result["profiles"].values())
