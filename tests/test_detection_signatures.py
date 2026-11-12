from antios.detection_signatures import (
    DEFAULT_DETECTION_SIGNATURES,
    behavior_findings_to_evidence,
)
from antios.evidence import Evidence
from antios.risk import evaluate_risk


def scan():
    return {
        "verdict": "no-threats-found",
        "coverage": "antios-local-inspection",
        "findings": [],
        "engine": {"available": True, "database_freshness": "local"},
    }


def rules(*items):
    findings = DEFAULT_DETECTION_SIGNATURES.evaluate(items)
    return {item.attributes["rule_id"]: item for item in findings}


def test_private_executable_pe_signature_is_high_review_signal():
    matched = rules(Evidence(
        source="memory-sensor",
        kind="memory",
        subject="pid:42",
        attributes={"private_executable": True, "embedded_pe": True},
    ))
    finding = matched["memory.private-executable-pe"]
    assert finding.risk_score >= 80
    assert finding.attributes["family"] == "in-memory-execution"


def test_remote_write_needs_execution_side_of_chain():
    write = Evidence(
        source="memory-sensor",
        kind="memory",
        subject="pid:42",
        attributes={"remote_write": True},
    )
    assert "memory.remote-write-thread" not in rules(write)

    thread = Evidence(
        source="thread-sensor",
        kind="process",
        subject="pid:42",
        attributes={"remote_thread": True},
    )
    assert "memory.remote-write-thread" in rules(write, thread)


def test_gpu_signature_requires_unsigned_hidden_high_compute():
    low = Evidence(
        source="gpu-sensor",
        kind="gpu",
        subject="miner.exe",
        attributes={"compute_percent": 70, "visible_window": False, "signed": False},
    )
    assert "gpu.hidden-compute-abuse" not in rules(low)

    high = Evidence(
        source="gpu-sensor",
        kind="gpu",
        subject="miner.exe",
        attributes={"compute_percent": 96, "visible_window": False, "signed": False},
    )
    matched = rules(high)
    assert "gpu.hidden-compute-abuse" in matched
    assert matched["gpu.hidden-compute-abuse"].risk_score < 80


def test_static_ml_requires_independent_structure_signal():
    model = Evidence(
        source="static-model",
        kind="model",
        subject="sample.exe",
        attributes={"malware_probability": .995},
    )
    assert "model.high-confidence-static-with-structure" not in rules(model)

    structural = Evidence(
        source="pe-features",
        kind="file",
        subject="sample.exe",
        attributes={"structural_anomaly": True},
    )
    assert "model.high-confidence-static-with-structure" in rules(model, structural)


def test_behavior_adapter_can_trigger_ransomware_like_signature():
    behavior = behavior_findings_to_evidence([{
        "rule": "interpreter-with-mass-file-changes",
        "score": 95,
        "severity": "critical",
        "summary": "fixture",
        "subject": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "at": 12.0,
    }])
    matched = DEFAULT_DETECTION_SIGNATURES.evaluate(behavior)
    ids = {item.attributes["rule_id"] for item in matched}
    assert "ransomware.mass-change-execution" in ids


def test_multi_sensor_signature_enters_risk_without_auto_enforcement():
    memory = Evidence(
        source="memory-sensor",
        kind="memory",
        subject="pid:42",
        attributes={"private_executable": True, "embedded_pe": True},
    )
    context = evaluate_risk(r"C:\Data\unknown.exe", scan(), evidence=[memory], now=1)
    assert "memory.private-executable-pe" in context.evidence_rules
    assert context.classification in {"high", "critical-behavior"}
    assert context.automatic_enforcement_eligible is False


def test_document_network_chain_is_review_only():
    subject = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    behavior = behavior_findings_to_evidence([{
        "rule": "document-spawns-interpreter",
        "score": 85,
        "severity": "high",
        "summary": "WINWORD started PowerShell",
        "subject": subject,
        "at": 10.0,
    }])
    network = Evidence(
        source="network-sensor",
        kind="network",
        subject=subject,
        attributes={"outbound_connection": True},
    )
    matched = DEFAULT_DETECTION_SIGNATURES.evaluate((*behavior, network))
    ids = {item.attributes["rule_id"] for item in matched}
    assert "process.document-interpreter-network" in ids


def test_packed_file_signature_requires_both_independent_observations():
    rwx = Evidence(
        source="pe-features",
        kind="file",
        subject="packed.exe",
        attributes={"writable_executable": True},
    )
    entropy = Evidence(
        source="entropy-map",
        kind="file",
        subject="packed.exe",
        attributes={"high_entropy_executable": True},
    )
    assert "file.packed-rwx-high-entropy" not in rules(rwx)
    assert "file.packed-rwx-high-entropy" in rules(rwx, entropy)


def test_similarity_rule_requires_named_malicious_reference_family():
    weak = Evidence(
        source="similarity",
        kind="model",
        subject="sample.exe",
        attributes={"malicious_similarity": .97, "reference_family": ""},
    )
    assert "similarity.malicious-family-near-match" not in rules(weak)

    strong = Evidence(
        source="similarity",
        kind="model",
        subject="sample.exe",
        attributes={"malicious_similarity": .97, "reference_family": "fixture-family"},
    )
    assert "similarity.malicious-family-near-match" in rules(strong)


def test_multi_sensor_rule_never_combines_different_subjects():
    rwx = Evidence(
        source="pe-features",
        kind="file",
        subject="a.exe",
        attributes={"writable_executable": True},
    )
    entropy = Evidence(
        source="entropy-map",
        kind="file",
        subject="b.exe",
        attributes={"high_entropy_executable": True},
    )
    assert "file.packed-rwx-high-entropy" not in rules(rwx, entropy)
