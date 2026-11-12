"""Adaptive accelerator routing primitives for AntiOS analysis stages.

The core does not pretend that a GPU/NPU backend exists. Optional backends
register measured profiles; until then work remains on CPU. This keeps device
selection separate from detection policy and makes later CUDA/Windows ML/NPU
implementations replaceable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import math
from threading import RLock
from typing import Iterable


class DeviceKind(StrEnum):
    CPU = "cpu"
    GPU = "gpu"
    NPU = "npu"


class WorkloadKind(StrEnum):
    PATTERN_SCAN = "pattern-scan"
    FEATURE_EXTRACTION = "feature-extraction"
    MODEL_INFERENCE = "model-inference"
    SIMILARITY = "similarity"
    ENTROPY_MAP = "entropy-map"


@dataclass(frozen=True)
class Workload:
    kind: str
    bytes_total: int
    items: int = 1
    latency_sensitive: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise ValueError("Workload kind must be non-empty")
        if type(self.bytes_total) is not int or self.bytes_total < 0:
            raise ValueError("Workload bytes_total must be a non-negative integer")
        if type(self.items) is not int or self.items <= 0:
            raise ValueError("Workload items must be a positive integer")
        if not isinstance(self.latency_sensitive, bool):
            raise ValueError("Workload latency_sensitive must be boolean")


@dataclass(frozen=True)
class BackendProfile:
    """Measured routing profile for one accelerator backend."""

    name: str
    device: str
    workloads: frozenset[str]
    fixed_overhead_us: float = 0.0
    compute_bytes_per_second: float = 0.0
    transfer_bytes_per_second: float = 0.0
    max_batch_bytes: int = 0
    benchmarked: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 128:
            raise ValueError("Backend name must be non-empty and <= 128 characters")
        if self.device not in {item.value for item in DeviceKind}:
            raise ValueError("Unsupported backend device kind")
        if not isinstance(self.workloads, frozenset) or not self.workloads:
            raise ValueError("Backend workloads must be a non-empty frozenset")
        for name, value in (
            ("fixed_overhead_us", self.fixed_overhead_us),
            ("compute_bytes_per_second", self.compute_bytes_per_second),
            ("transfer_bytes_per_second", self.transfer_bytes_per_second),
        ):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if type(self.max_batch_bytes) is not int or self.max_batch_bytes < 0:
            raise ValueError("max_batch_bytes must be a non-negative integer")
        if not isinstance(self.benchmarked, bool):
            raise ValueError("benchmarked must be boolean")

    def supports(self, workload: Workload) -> bool:
        return (
            workload.kind in self.workloads
            and (not self.max_batch_bytes or workload.bytes_total <= self.max_batch_bytes)
        )

    def estimate_seconds(self, workload: Workload) -> float:
        if not self.supports(workload):
            return math.inf
        if self.device != DeviceKind.CPU and not self.benchmarked:
            return math.inf
        if self.compute_bytes_per_second <= 0:
            return math.inf
        seconds = float(self.fixed_overhead_us) / 1_000_000.0
        seconds += workload.bytes_total / float(self.compute_bytes_per_second)
        if self.device != DeviceKind.CPU:
            if self.transfer_bytes_per_second <= 0:
                return math.inf
            seconds += workload.bytes_total / float(self.transfer_bytes_per_second)
        return seconds


class AcceleratorRouter:
    """Choose a measured backend without embedding detection logic."""

    def __init__(self, *, minimum_accelerator_bytes: int = 4 * 1024 * 1024):
        if type(minimum_accelerator_bytes) is not int or minimum_accelerator_bytes < 0:
            raise ValueError("minimum_accelerator_bytes must be a non-negative integer")
        self.minimum_accelerator_bytes = minimum_accelerator_bytes
        self._profiles: dict[str, BackendProfile] = {}
        self._lock = RLock()

    def register(self, profile: BackendProfile) -> None:
        with self._lock:
            self._profiles[profile.name] = profile

    def unregister(self, name: str) -> None:
        with self._lock:
            self._profiles.pop(name, None)

    def profiles(self) -> tuple[BackendProfile, ...]:
        with self._lock:
            return tuple(self._profiles.values())

    def choose(self, workload: Workload, *, preferred_device: str | None = None) -> BackendProfile | None:
        profiles = self.profiles()
        candidates = [item for item in profiles if item.supports(workload)]
        if preferred_device is not None:
            if preferred_device not in {item.value for item in DeviceKind}:
                raise ValueError("Unsupported preferred device kind")
            preferred = [item for item in candidates if item.device == preferred_device]
            if preferred:
                candidates = preferred

        cpu = [item for item in candidates if item.device == DeviceKind.CPU]
        if cpu and preferred_device is None and not any(item.benchmarked for item in cpu):
            return min(cpu, key=lambda item: item.name)
        if cpu and (workload.latency_sensitive or workload.bytes_total < self.minimum_accelerator_bytes):
            return min(cpu, key=lambda item: item.estimate_seconds(workload))

        ranked = [
            (item.estimate_seconds(workload), item)
            for item in candidates
            if math.isfinite(item.estimate_seconds(workload))
        ]
        if ranked:
            return min(ranked, key=lambda pair: pair[0])[1]
        return min(cpu, key=lambda item: item.name) if cpu else None

    def status(self) -> dict:
        profiles = self.profiles()
        return {
            "mode": "adaptive-measured-routing",
            "minimum_accelerator_bytes": self.minimum_accelerator_bytes,
            "backends": [asdict(item) | {"workloads": sorted(item.workloads)} for item in profiles],
            "devices": sorted({item.device for item in profiles}),
            "benchmarked_accelerators": sum(
                item.device != DeviceKind.CPU and item.benchmarked for item in profiles
            ),
        }


def cpu_profile(*, name: str = "cpu", workloads: Iterable[str] = tuple(item.value for item in WorkloadKind),
                compute_bytes_per_second: float = 0.0, benchmarked: bool = False) -> BackendProfile:
    """Create a CPU profile; callers should replace throughput with benchmark data."""
    return BackendProfile(
        name=name,
        device=DeviceKind.CPU,
        workloads=frozenset(workloads),
        compute_bytes_per_second=compute_bytes_per_second,
        benchmarked=benchmarked,
    )
