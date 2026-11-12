"""Optional CUDA hashing for bounded groups of already-verified file bytes."""
from __future__ import annotations

import hashlib
import re
from time import perf_counter

from .accelerator import AcceleratorRouter, BackendProfile, DeviceKind, Workload, WorkloadKind, cpu_profile


GPU_MODES = ("cpu", "auto", "eco", "accelerated")
DEFAULT_GPU_MODE = "cpu"
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _open_cuda():
    from .cuda_sha256 import CudaSHA256
    return CudaSHA256()


class ScanAcceleration:
    """A scan owns at most one CUDA backend and falls back on the same snapshots."""

    def __init__(self, mode: str, *, backend_factory=None):
        if mode not in GPU_MODES:
            raise ValueError("Unsupported GPU scan mode")
        self.mode = mode
        self.batch_items = 256 if mode == "eco" else 1024
        self.batch_bytes = (4 if mode == "eco" else 16) * 1024 * 1024
        self.max_item_bytes = 64 * 1024
        self.minimum_items = 32 if mode == "accelerated" else 128
        self._factory = backend_factory or _open_cuda
        self._backend = None
        self._gpu_faster = None
        self._last_use = float("-inf")
        self._failure = ""
        self._timing = None
        self._gpu_batches = self._gpu_files = 0

    @property
    def enabled(self) -> bool:
        return self.mode != "cpu" and not self._failure and self._gpu_faster is not False

    def _calibrate(self, contents, workload, dispatch):
        started = perf_counter()
        expected = tuple(map(sha256, contents))
        cpu_seconds = max(perf_counter() - started, 1e-9)
        # The first dispatch checks the backend and warms the driver/kernel.
        if tuple(self._backend.digest_many(contents)) != expected:
            raise ValueError("CUDA hash verification failed")
        started = perf_counter()
        actual = tuple(self._backend.digest_many(contents))
        gpu_seconds = max(perf_counter() - started, 1e-9)
        if actual != expected:
            raise ValueError("CUDA hash verification failed")
        # CPU-only scan tasks hash and inspect in one worker call. CUDA
        # staging adds a second pool dispatch even when hashing is faster.
        started = perf_counter()
        dispatch(contents)
        dispatch_seconds = perf_counter() - started
        pipeline_seconds = gpu_seconds + dispatch_seconds
        self._timing = {
            "files": workload.items, "bytes": workload.bytes_total,
            "cpu_seconds": round(cpu_seconds, 6), "gpu_seconds": round(gpu_seconds, 6),
            "dispatch_seconds": round(dispatch_seconds, 6),
        }
        # The GPU measurement includes the host/device transfer. Split it
        # evenly between compute and transfer in the router's additive model.
        router = AcceleratorRouter(minimum_accelerator_bytes=0)
        router.register(cpu_profile(compute_bytes_per_second=workload.bytes_total / cpu_seconds, benchmarked=True))
        throughput = 2 * workload.bytes_total / gpu_seconds
        router.register(BackendProfile(
            self._backend.name, DeviceKind.GPU, frozenset({WorkloadKind.PATTERN_SCAN}),
            fixed_overhead_us=dispatch_seconds * 1_000_000,
            compute_bytes_per_second=throughput, transfer_bytes_per_second=throughput,
            max_batch_bytes=self.batch_bytes, benchmarked=True,
        ))
        chosen = router.choose(workload)
        self._gpu_faster = self.mode == "accelerated" or (
            chosen is not None and chosen.device == DeviceKind.GPU and pipeline_seconds < cpu_seconds * .9
        )
        return actual, expected

    def digests(self, contents: tuple[bytes, ...], signatures, cpu_hashes, dispatch) -> tuple[str, ...]:
        if not self.enabled or len(contents) < self.minimum_items:
            return cpu_hashes(contents)
        if self.mode == "eco" and perf_counter() - self._last_use < .25:
            return cpu_hashes(contents)
        total = sum(map(len, contents))
        if total == 0:
            return cpu_hashes(contents)
        try:
            if self._backend is None:
                self._backend = self._factory()
            if self._gpu_faster is None:
                workload = Workload(WorkloadKind.PATTERN_SCAN, total, len(contents))
                actual, expected = self._calibrate(contents, workload, dispatch)
                if not self._gpu_faster:
                    return expected
            else:
                actual = tuple(self._backend.digest_many(contents))
                if len(actual) != len(contents) or not all(_DIGEST.fullmatch(value) for value in actual):
                    raise ValueError("Malformed CUDA digest batch")
                # Confirm catalog hits and sample clean results independently.
                verify = {0, len(actual) // 2, len(actual) - 1}
                verify.update(index for index, value in enumerate(actual) if value in signatures)
                if any(sha256(contents[index]) != actual[index] for index in verify):
                    raise ValueError("CUDA hash verification failed")
            self._last_use = perf_counter()
            self._gpu_batches += 1
            self._gpu_files += len(contents)
            return actual
        except (OSError, RuntimeError, ValueError, ImportError, TypeError) as exc:
            self._failure = type(exc).__name__
            return cpu_hashes(contents)

    def status(self) -> dict:
        return {
            "mode": self.mode,
            "device": "gpu" if self._gpu_batches else "cpu",
            "backend": self._backend.name if self._backend is not None else "",
            "device_name": getattr(self._backend, "device_name", ""),
            "gpu_batches": self._gpu_batches, "gpu_files": self._gpu_files,
            "fallback": self._failure,
            "calibration": self._timing,
        }

    def close(self) -> None:
        if self._backend is not None:
            try:
                self._backend.close()
            except (OSError, RuntimeError):
                pass
