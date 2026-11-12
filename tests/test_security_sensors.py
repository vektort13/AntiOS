"""Safety and integration tests for the AntiOS deep-security sensor layer."""
import pytest

from antios.evidence import Evidence, EvidenceBus
from antios.security_sensors import (
    Acquisition,
    BudgetGuard,
    CapabilityState,
    Coverage,
    CoverageSummary,
    PlaceholderSensor,
    Privilege,
    ScanBudget,
    ScanContext,
    SensorDescriptor,
    SensorRegistry,
    SensorReport,
    Surface,
    default_descriptors,
    default_registry,
    sensor_evidence,
)


def _descriptor(
    name: str = "x",
    surface: Surface = Surface.PROCESS,
    privilege: Privilege = Privilege.USER,
) -> SensorDescriptor:
    return SensorDescriptor(
        name=name,
        surface=surface,
        acquisition=Acquisition.SNAPSHOT,
        minimum_privilege=privilege,
        capability=CapabilityState.AVAILABLE,
        experimental=False,
    )


def test_every_planned_surface_has_a_descriptor():
    assert {d.surface for d in default_descriptors()} == set(Surface)


def test_default_registry_never_claims_a_clean_scan():
    reports = default_registry().collect_all(
        ScanContext(budget=ScanBudget(allow_privileged=True))
    )
    assert {r.descriptor.surface for r in reports} == set(Surface)
    assert all(r.coverage is Coverage.NOT_IMPLEMENTED for r in reports)
    assert all(r.reason and not r.evidence for r in reports)


def test_privileged_sensors_are_denied_before_collection_by_default():
    class MustNotRun:
        descriptor = _descriptor("admin", Surface.RAM, Privilege.ADMIN)

        def collect(self, context):
            raise AssertionError("must not execute")

    registry = SensorRegistry()
    registry.register(MustNotRun())
    report, = registry.collect_all()
    assert report.coverage is Coverage.PERMISSION_DENIED


def test_requested_surface_filtering():
    reports = default_registry().collect_all(
        ScanContext(
            requested_surfaces=frozenset({Surface.PROCESS, Surface.BROWSER})
        )
    )
    assert {r.descriptor.surface for r in reports} == {
        Surface.PROCESS,
        Surface.BROWSER,
    }


def test_sensor_evidence_records_shared_provenance():
    descriptor = _descriptor("sensor.process", Surface.PROCESS)
    context = ScanContext(run_id="run-1")
    item = sensor_evidence(
        descriptor,
        context,
        subject="pid:42",
        kind="process",
        rule_id="process.test",
        detail="test observation",
        maliciousness=.5,
        confidence=.8,
        severity=50,
    )
    assert item.source == descriptor.name
    assert item.attributes["surface"] == "process"
    assert item.attributes["rule_id"] == "process.test"
    assert item.attributes["scan_run_id"] == "run-1"


def test_sensor_report_rejects_cross_sensor_evidence():
    descriptor = _descriptor("sensor.process")
    item = Evidence(
        source="different",
        kind="process",
        subject="pid:1",
        attributes={"surface": "process"},
    )
    with pytest.raises(ValueError):
        SensorReport(descriptor, Coverage.COMPLETE, (item,))


def test_sensor_report_rejects_cross_surface_evidence():
    descriptor = _descriptor("sensor.process", Surface.PROCESS)
    item = Evidence(
        source="sensor.process",
        kind="process",
        subject="pid:1",
        attributes={"surface": "gpu"},
    )
    with pytest.raises(ValueError):
        SensorReport(descriptor, Coverage.COMPLETE, (item,))


def test_incomplete_coverage_requires_reason():
    with pytest.raises(ValueError):
        SensorReport(_descriptor(), Coverage.PARTIAL)


def test_registry_publishes_sensor_evidence_to_shared_bus():
    descriptor = _descriptor("sensor.process", Surface.PROCESS)
    bus = EvidenceBus(max_events=16)

    class Working:
        def __init__(self, descriptor):
            self.descriptor = descriptor

        def collect(self, context):
            item = sensor_evidence(
                self.descriptor,
                context,
                subject="pid:7",
                kind="process",
                rule_id="process.example",
                detail="example",
            )
            return SensorReport(
                self.descriptor,
                Coverage.COMPLETE,
                (item,),
                inspected_items=1,
            )

    registry = SensorRegistry(evidence_bus=bus)
    registry.register(Working(descriptor))
    report, = registry.collect_all()
    assert report.coverage is Coverage.COMPLETE
    assert len(bus.recent(subject="pid:7")) == 1


def test_collector_failures_are_isolated_and_details_not_leaked():
    class Broken:
        descriptor = _descriptor("broken", Surface.GPU)

        def collect(self, context):
            raise RuntimeError("secret implementation detail")

    registry = SensorRegistry()
    registry.register(Broken())
    report, = registry.collect_all()
    assert report.coverage is Coverage.ERROR
    assert "secret implementation detail" not in report.reason


def test_duplicate_registration_rejected():
    registry = SensorRegistry()
    descriptor = _descriptor("a")
    registry.register(PlaceholderSensor(descriptor))
    with pytest.raises(ValueError):
        registry.register(PlaceholderSensor(descriptor))


def test_budget_guard_stops_at_hard_limits():
    guard = BudgetGuard(
        ScanBudget(max_items=2, max_bytes=10, max_seconds=60)
    )
    assert guard.take(items=1, byte_count=4)
    assert guard.take(items=1, byte_count=6)
    assert not guard.take(items=1)
    assert not guard.take(items=0, byte_count=1)
    assert guard.items == 2
    assert guard.bytes == 10


def test_coverage_summary_never_calls_missing_surfaces_fully_covered():
    complete = SensorReport(_descriptor("a"), Coverage.COMPLETE)
    missing = SensorReport(
        _descriptor("b", Surface.BROWSER),
        Coverage.NOT_IMPLEMENTED,
        reason="not connected",
    )
    summary = CoverageSummary.from_reports((complete, missing))
    assert summary.complete == 1
    assert summary.not_implemented == 1
    assert not summary.fully_covered
