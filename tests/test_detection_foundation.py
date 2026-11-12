import struct

from antios.accelerator import AcceleratorRouter, BackendProfile, Workload, cpu_profile
from antios.analysis_pipeline import (
    AdaptiveAnalysisPipeline, AnalysisContext, StageDisposition, StageResult,
)
from antios.behavior import ProcessEvent
from antios.engine import AntiOSEngine
from antios.evidence import Evidence, EvidenceBus, summarize_evidence
from antios.incident import IncidentGraph
from antios.process_identity import ProcessIdentity
from antios.risk import evaluate_risk


def _scan():
    return {
        "verdict": "no-threats-found",
        "coverage": "antios-local-inspection",
        "findings": [],
        "engine": {"available": True, "database_freshness": "local"},
    }


def test_evidence_bus_is_bounded_and_subscriber_failure_isolated():
    now = [10.0]
    bus = EvidenceBus(max_events=16, clock=lambda: now[0])
    received = []
    bus.subscribe(received.append)

    def broken(_item):
        raise RuntimeError("fixture")

    bus.subscribe(broken)
    for index in range(20):
        bus.publish(Evidence(source="fixture", kind="file", subject=str(index)))

    assert len(bus.recent()) == 16
    assert len(received) == 20
    assert bus.status()["delivery_failures"] == 20


def test_correlated_evidence_is_not_additively_counted():
    values = [
        Evidence(source="pe", kind="file", subject="x", maliciousness=.9,
                 confidence=.8, severity=80, correlation_group="packer"),
        Evidence(source="entropy", kind="file", subject="x", maliciousness=.95,
                 confidence=.9, severity=70, correlation_group="packer"),
        Evidence(source="memory", kind="memory", subject="x", maliciousness=.8,
                 confidence=.9, severity=90, correlation_group="memory"),
    ]
    score, sources = summarize_evidence(values)
    assert score == max(item.risk_score for item in values)
    assert set(sources) == {"pe", "entropy", "memory"}


def test_accelerator_router_requires_comparable_measurements():
    router = AcceleratorRouter(minimum_accelerator_bytes=1024)
    router.register(cpu_profile())
    router.register(BackendProfile(
        name="gpu", device="gpu", workloads=frozenset({"pattern-scan"}),
        compute_bytes_per_second=10_000_000_000,
        transfer_bytes_per_second=10_000_000_000,
        benchmarked=True,
    ))
    assert router.choose(Workload("pattern-scan", 10_000_000)).name == "cpu"

    router.register(cpu_profile(
        compute_bytes_per_second=100_000_000, benchmarked=True,
    ))
    assert router.choose(Workload("pattern-scan", 100_000_000)).name == "gpu"
    assert router.choose(
        Workload("pattern-scan", 100, latency_sensitive=True)
    ).name == "cpu"


def test_adaptive_pipeline_preserves_escalation_and_evidence():
    class Cheap:
        name = "cheap"

        def analyze(self, context):
            return StageResult(
                StageDisposition.ESCALATE,
                (Evidence(source="cheap", kind="file", subject=context.subject,
                          maliciousness=.5, confidence=.8, severity=50),),
            )

    class Deep:
        name = "deep"

        def analyze(self, context):
            return StageResult(
                StageDisposition.STOP,
                (Evidence(source="deep", kind="model", subject=context.subject),),
            )

    bus = EvidenceBus(max_events=16)
    result = AdaptiveAnalysisPipeline(
        [Cheap(), Deep()], evidence_bus=bus,
    ).run(AnalysisContext("fixture"))

    assert result.stages_run == ("cheap", "deep")
    assert result.escalated is True
    assert result.stopped_by == "deep"
    assert len(result.evidence) == len(bus.recent()) == 2


def test_process_identity_distinguishes_pid_reuse():
    assert ProcessIdentity(55, 100).node_id == "process:55:100"
    assert ProcessIdentity(55, 100).node_id != ProcessIdentity(55, 200).node_id
    assert ProcessIdentity(55).stable is False


def test_incident_graph_does_not_join_reused_stable_pid():
    incidents = IncidentGraph()
    old_path = r"C:\Data\old.exe"
    incidents.observe_file_change(old_path)
    first = incidents.observe_process(ProcessEvent(
        pid=55, ppid=10, image="old.exe", path=old_path,
        parent_image="explorer.exe", creation_time=100,
    ))[0]

    second = incidents.observe_process(
        ProcessEvent(
            pid=55, ppid=11, image="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_image="WINWORD.EXE", creation_time=200,
        ),
        behavior_findings=[{
            "rule": "document-spawns-interpreter",
            "score": 85,
            "severity": "high",
            "summary": "fixture",
        }],
    )[0]

    assert second["id"] != first["id"]
    assert any(node["id"] == "process:55:200" for node in second["nodes"])


def test_generic_evidence_can_raise_risk_but_never_auto_enforces():
    evidence = Evidence(
        source="memory", kind="memory", subject="pid:55",
        maliciousness=.9, confidence=.9, severity=85,
        correlation_group="private-executable-memory",
    )
    context = evaluate_risk(r"C:\Data\unknown.exe", _scan(), evidence=[evidence], now=1)
    assert context.evidence_score == evidence.risk_score
    assert context.classification == "high"
    assert context.automatic_enforcement_eligible is False
    assert context.evidence_sources == ("memory",)


def test_generic_process_evidence_attaches_to_existing_incident():
    incidents = IncidentGraph()
    first = incidents.observe_process(
        ProcessEvent(
            pid=70, ppid=10, image="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_image="WINWORD.EXE", creation_time=1234,
        ),
        behavior_findings=[{
            "rule": "document-spawns-interpreter",
            "score": 85,
            "severity": "high",
            "summary": "fixture",
        }],
    )[0]
    updates = incidents.observe_evidence([Evidence(
        source="memory", kind="memory", subject="powershell.exe",
        maliciousness=.8, confidence=.9, severity=80,
        attributes={"pid": 70, "creation_time": 1234},
    )])
    assert updates[0]["id"] == first["id"]
    assert any(edge["relation"] == "supports-risk" for edge in updates[0]["edges"])


def test_out_of_bounds_pe_section_is_incomplete_not_silently_clean():
    content = bytearray(512)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", content, 0x80 + 6, 1)
    struct.pack_into("<H", content, 0x80 + 20, 0xE0)
    table = 0x80 + 24 + 0xE0
    struct.pack_into("<II12xI", content, table + 16, 4096, 0x1000, 0x60000020)

    result = AntiOSEngine().scan(bytes(content), "fixture.exe")
    assert result.kind == "review"
    assert result.complete is False
    assert "invalid-pe-section-bounds" in result.coverage_gaps
