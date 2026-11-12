"""Capability-first contracts for optional AntiOS deep-security sensors.

Collectors report both capability and actual coverage, then emit the shared
:mod:`antios.evidence` model used by the detection, risk and incident layers.
This module deliberately contains no OS-specific RAM, kernel, VRAM or firmware
reader.

Invariant: unsupported, unavailable, permission-limited and unimplemented
surfaces must never be represented as a clean scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import os
from threading import RLock
from time import monotonic, time
from typing import Mapping, Protocol
from uuid import uuid4

from .evidence import Evidence, EvidenceBus


class Surface(str, Enum):
    PROCESS = "process"
    RAM = "ram"
    PERSISTENCE = "persistence"
    DRIVER = "driver"
    KERNEL = "kernel"
    BOOT = "boot"
    UEFI = "uefi"
    PLATFORM_FIRMWARE = "platform_firmware"
    DEVICE_FIRMWARE = "device_firmware"
    GPU = "gpu"
    NETWORK = "network"
    BROWSER = "browser"
    DMA = "dma"
    VIRTUALIZATION = "virtualization"
    ATTESTATION = "attestation"


class Coverage(str, Enum):
    NOT_IMPLEMENTED = "not_implemented"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission_denied"
    ERROR = "error"
    PARTIAL = "partial"
    COMPLETE = "complete"


class CapabilityState(str, Enum):
    NOT_IMPLEMENTED = "not_implemented"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    PERMISSION_REQUIRED = "permission_required"
    EXPERIMENTAL = "experimental"
    AVAILABLE = "available"


class Privilege(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"
    KERNEL = "kernel"
    FIRMWARE = "firmware"


class Acquisition(str, Enum):
    SNAPSHOT = "snapshot"
    EVENT_STREAM = "event_stream"
    QUERY = "query"
    ATTESTATION = "attestation"


@dataclass(frozen=True)
class SensorDescriptor:
    name: str
    surface: Surface
    acquisition: Acquisition
    minimum_privilege: Privilege = Privilege.USER
    capability: CapabilityState = CapabilityState.NOT_IMPLEMENTED
    version: int = 1
    experimental: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("sensor name must be non-empty")
        if self.version < 1:
            raise ValueError("sensor version must be positive")


@dataclass(frozen=True)
class ScanBudget:
    """Hard upper bounds shared by collectors."""

    max_items: int = 10_000
    max_bytes: int = 256 * 1024 * 1024
    max_seconds: float = 30.0
    max_depth: int = 4
    allow_privileged: bool = False

    def __post_init__(self) -> None:
        if type(self.max_items) is not int or self.max_items < 1:
            raise ValueError("max_items must be a positive integer")
        if type(self.max_bytes) is not int or self.max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        if (
            not isinstance(self.max_seconds, (int, float))
            or isinstance(self.max_seconds, bool)
            or self.max_seconds <= 0
        ):
            raise ValueError("max_seconds must be positive")
        if type(self.max_depth) is not int or self.max_depth < 0:
            raise ValueError("max_depth must be a non-negative integer")
        if not isinstance(self.allow_privileged, bool):
            raise ValueError("allow_privileged must be boolean")


@dataclass(frozen=True)
class ScanContext:
    run_id: str = field(default_factory=lambda: uuid4().hex)
    budget: ScanBudget = field(default_factory=ScanBudget)
    requested_surfaces: frozenset[Surface] = field(
        default_factory=lambda: frozenset(Surface)
    )

    def __post_init__(self) -> None:
        if not self.run_id.strip():
            raise ValueError("run_id must be non-empty")
        if not isinstance(self.requested_surfaces, frozenset):
            raise ValueError("requested_surfaces must be a frozenset")
        if not all(isinstance(item, Surface) for item in self.requested_surfaces):
            raise ValueError("requested_surfaces contains an invalid surface")


class BudgetGuard:
    """Small helper collectors can use to enforce a ScanBudget."""

    def __init__(self, budget: ScanBudget) -> None:
        self._budget = budget
        self._started = monotonic()
        self._items = 0
        self._bytes = 0

    @property
    def items(self) -> int:
        return self._items

    @property
    def bytes(self) -> int:
        return self._bytes

    def expired(self) -> bool:
        return monotonic() - self._started >= self._budget.max_seconds

    def can_take(self, *, items: int = 1, byte_count: int = 0) -> bool:
        if type(items) is not int or type(byte_count) is not int:
            raise ValueError("budget claims must be integers")
        if items < 0 or byte_count < 0:
            raise ValueError("budget claims must be non-negative")
        return (
            not self.expired()
            and self._items + items <= self._budget.max_items
            and self._bytes + byte_count <= self._budget.max_bytes
        )

    def take(self, *, items: int = 1, byte_count: int = 0) -> bool:
        if not self.can_take(items=items, byte_count=byte_count):
            return False
        self._items += items
        self._bytes += byte_count
        return True


def sensor_evidence(
    descriptor: SensorDescriptor,
    context: ScanContext,
    *,
    subject: str,
    kind: str,
    rule_id: str,
    detail: str,
    maliciousness: float = 0.0,
    confidence: float = 1.0,
    severity: int = 0,
    complete: bool = True,
    correlation_group: str = "",
    at: float = 0.0,
    attributes: Mapping[str, object] | None = None,
) -> Evidence:
    """Create shared Evidence with mandatory sensor provenance.

    Generic sensor evidence is context only. Current AntiOS enforcement policy
    remains in the risk/scanner layers and does not grant automatic remediation
    authority to this helper.
    """

    if not rule_id.strip():
        raise ValueError("rule_id must be non-empty")
    payload = dict(attributes or {})
    payload.update(
        surface=descriptor.surface.value,
        sensor_version=descriptor.version,
        rule_id=rule_id,
        scan_run_id=context.run_id,
    )
    return Evidence(
        source=descriptor.name,
        kind=kind,
        subject=subject,
        maliciousness=maliciousness,
        confidence=confidence,
        severity=severity,
        complete=complete,
        correlation_group=correlation_group,
        detail=detail,
        at=at,
        attributes=payload,
    )


@dataclass(frozen=True)
class SensorReport:
    descriptor: SensorDescriptor
    coverage: Coverage
    evidence: tuple[Evidence, ...] = ()
    reason: str = ""
    inspected_items: int = 0
    inspected_bytes: int = 0
    skipped_items: int = 0
    error_items: int = 0
    collected_at: float = field(default_factory=time)

    def __post_init__(self) -> None:
        if self.coverage != Coverage.COMPLETE and not self.reason.strip():
            raise ValueError("incomplete coverage requires a reason")
        counts = (
            self.inspected_items,
            self.inspected_bytes,
            self.skipped_items,
            self.error_items,
        )
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("coverage counters must be non-negative integers")
        for item in self.evidence:
            if not isinstance(item, Evidence):
                raise ValueError("sensor evidence must use antios.evidence.Evidence")
            if item.source != self.descriptor.name:
                raise ValueError("evidence source does not match reporting sensor")
            if item.attributes.get("surface") != self.descriptor.surface.value:
                raise ValueError("evidence surface does not match reporting sensor")


@dataclass(frozen=True)
class CoverageSummary:
    complete: int
    partial: int
    unavailable: int
    not_implemented: int
    errors: int

    @classmethod
    def from_reports(cls, reports: tuple[SensorReport, ...]) -> "CoverageSummary":
        return cls(
            complete=sum(r.coverage is Coverage.COMPLETE for r in reports),
            partial=sum(r.coverage is Coverage.PARTIAL for r in reports),
            unavailable=sum(
                r.coverage in {
                    Coverage.UNSUPPORTED,
                    Coverage.UNAVAILABLE,
                    Coverage.PERMISSION_DENIED,
                }
                for r in reports
            ),
            not_implemented=sum(
                r.coverage is Coverage.NOT_IMPLEMENTED for r in reports
            ),
            errors=sum(r.coverage is Coverage.ERROR for r in reports),
        )

    @property
    def fully_covered(self) -> bool:
        return (
            self.partial == 0
            and self.unavailable == 0
            and self.not_implemented == 0
            and self.errors == 0
        )


class Sensor(Protocol):
    descriptor: SensorDescriptor

    def collect(self, context: ScanContext) -> SensorReport: ...


class PlaceholderSensor:
    """Honest capability placeholder; never claims to inspect a surface."""

    def __init__(self, descriptor: SensorDescriptor) -> None:
        self.descriptor = descriptor

    def collect(self, context: ScanContext) -> SensorReport:
        state = self.descriptor.capability
        mapping = {
            CapabilityState.NOT_IMPLEMENTED: Coverage.NOT_IMPLEMENTED,
            CapabilityState.UNSUPPORTED: Coverage.UNSUPPORTED,
            CapabilityState.UNAVAILABLE: Coverage.UNAVAILABLE,
            CapabilityState.PERMISSION_REQUIRED: Coverage.PERMISSION_DENIED,
            CapabilityState.EXPERIMENTAL: Coverage.NOT_IMPLEMENTED,
            CapabilityState.AVAILABLE: Coverage.NOT_IMPLEMENTED,
        }
        return SensorReport(
            descriptor=self.descriptor,
            coverage=mapping[state],
            reason="Collector not connected; no inspection performed",
        )


class SensorRegistry:
    """Bounded, exception-isolated registry publishing into one EvidenceBus."""

    def __init__(
        self,
        max_sensors: int = 64,
        *,
        evidence_bus: EvidenceBus | None = None,
    ) -> None:
        if type(max_sensors) is not int or max_sensors < 1:
            raise ValueError("max_sensors must be a positive integer")
        self._lock = RLock()
        self._sensors: dict[str, Sensor] = {}
        self._max_sensors = max_sensors
        self._evidence_bus = evidence_bus

    def register(self, sensor: Sensor) -> None:
        descriptor = sensor.descriptor
        with self._lock:
            if descriptor.name in self._sensors:
                raise ValueError("duplicate sensor name")
            if len(self._sensors) >= self._max_sensors:
                raise ValueError("sensor capacity reached")
            self._sensors[descriptor.name] = sensor

    def descriptors(self) -> tuple[SensorDescriptor, ...]:
        with self._lock:
            return tuple(sensor.descriptor for sensor in self._sensors.values())

    def collect_all(
        self, context: ScanContext | None = None
    ) -> tuple[SensorReport, ...]:
        context = context or ScanContext()
        with self._lock:
            sensors = tuple(self._sensors.values())

        reports: list[SensorReport] = []
        for sensor in sensors:
            descriptor = sensor.descriptor
            if descriptor.surface not in context.requested_surfaces:
                continue
            if (
                descriptor.minimum_privilege is not Privilege.USER
                and not context.budget.allow_privileged
            ):
                reports.append(
                    SensorReport(
                        descriptor=descriptor,
                        coverage=Coverage.PERMISSION_DENIED,
                        reason="Privileged collection disabled by scan budget",
                    )
                )
                continue
            try:
                report = sensor.collect(context)
                if report.descriptor != descriptor:
                    raise ValueError("collector returned mismatched descriptor")
                reports.append(report)
                if self._evidence_bus is not None:
                    for item in report.evidence:
                        self._evidence_bus.publish(item)
            except Exception as exc:
                reports.append(
                    SensorReport(
                        descriptor=descriptor,
                        coverage=Coverage.ERROR,
                        reason=f"Collector failure: {type(exc).__name__}",
                    )
                )
        return tuple(reports)


_SURFACE_DEFAULTS: tuple[tuple[Surface, Acquisition, Privilege], ...] = (
    (Surface.PROCESS, Acquisition.SNAPSHOT, Privilege.USER),
    (Surface.RAM, Acquisition.SNAPSHOT, Privilege.ADMIN),
    (Surface.PERSISTENCE, Acquisition.QUERY, Privilege.USER),
    (Surface.DRIVER, Acquisition.QUERY, Privilege.ADMIN),
    (Surface.KERNEL, Acquisition.SNAPSHOT, Privilege.SYSTEM),
    (Surface.BOOT, Acquisition.ATTESTATION, Privilege.ADMIN),
    (Surface.UEFI, Acquisition.ATTESTATION, Privilege.ADMIN),
    (Surface.PLATFORM_FIRMWARE, Acquisition.ATTESTATION, Privilege.ADMIN),
    (Surface.DEVICE_FIRMWARE, Acquisition.QUERY, Privilege.ADMIN),
    (Surface.GPU, Acquisition.QUERY, Privilege.USER),
    (Surface.NETWORK, Acquisition.EVENT_STREAM, Privilege.USER),
    (Surface.BROWSER, Acquisition.QUERY, Privilege.USER),
    (Surface.DMA, Acquisition.ATTESTATION, Privilege.ADMIN),
    (Surface.VIRTUALIZATION, Acquisition.QUERY, Privilege.ADMIN),
    (Surface.ATTESTATION, Acquisition.ATTESTATION, Privilege.ADMIN),
)


def default_descriptors() -> tuple[SensorDescriptor, ...]:
    """Machine-readable inventory of planned deep-security surfaces."""
    return tuple(
        SensorDescriptor(
            name=f"antios.{surface.value}",
            surface=surface,
            acquisition=acquisition,
            minimum_privilege=privilege,
        )
        for surface, acquisition, privilege in _SURFACE_DEFAULTS
    )


def default_registry(*, evidence_bus: EvidenceBus | None = None) -> SensorRegistry:
    registry = SensorRegistry(evidence_bus=evidence_bus)
    for descriptor in default_descriptors():
        registry.register(PlaceholderSensor(descriptor))
    return registry


def runtime_registry(*, evidence_bus: EvidenceBus | None = None) -> SensorRegistry:
    """Return real platform collectors where implemented, placeholders elsewhere."""
    if os.name == "nt":
        from .windows_security_sensors import build_windows_registry
        return build_windows_registry(evidence_bus=evidence_bus)
    return default_registry(evidence_bus=evidence_bus)
