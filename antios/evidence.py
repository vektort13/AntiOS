"""Shared, bounded evidence primitives for AntiOS detection layers.

Sensors describe observations; policy decides what they mean. This module is
intentionally side-effect free apart from an in-memory bounded event bus. It
is suitable for file, process, memory, network, model and accelerator sensors.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
import math
from threading import RLock
import time
from typing import Callable, Iterable, Mapping


class EvidenceKind(StrEnum):
    FILE = "file"
    PROCESS = "process"
    MEMORY = "memory"
    PERSISTENCE = "persistence"
    DRIVER = "driver"
    BOOT = "boot"
    ATTESTATION = "attestation"
    BEHAVIOR = "behavior"
    NETWORK = "network"
    BROWSER = "browser"
    GPU = "gpu"
    DEVICE_FIRMWARE = "device_firmware"
    MODEL = "model"
    SIGNATURE = "signature"
    COVERAGE = "coverage"
    OTHER = "other"


@dataclass(frozen=True)
class Evidence:
    """One explainable observation produced by a sensor or analysis stage.

    maliciousness and confidence are deliberately separate. A strong
    observation can still be ambiguous, and a highly reliable observation can
    still be benign context. correlation_group lets later fusion avoid
    counting multiple symptoms of the same underlying fact as independent
    proof.
    """

    source: str
    kind: str
    subject: str
    maliciousness: float = 0.0
    confidence: float = 1.0
    severity: int = 0
    complete: bool = True
    correlation_group: str = ""
    detail: str = ""
    at: float = 0.0
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip() or len(self.source) > 128:
            raise ValueError("Evidence source must be a non-empty string up to 128 characters")
        if not isinstance(self.kind, str) or not self.kind.strip() or len(self.kind) > 64:
            raise ValueError("Evidence kind must be a non-empty string up to 64 characters")
        if not isinstance(self.subject, str) or len(self.subject) > 32768:
            raise ValueError("Evidence subject must be a string up to 32768 characters")
        for name, value in (("maliciousness", self.maliciousness), ("confidence", self.confidence)):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                raise ValueError(f"Evidence {name} must be finite")
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"Evidence {name} must be between 0 and 1")
        if type(self.severity) is not int or not 0 <= self.severity <= 100:
            raise ValueError("Evidence severity must be between 0 and 100")
        if not isinstance(self.complete, bool):
            raise ValueError("Evidence complete must be boolean")
        if not isinstance(self.correlation_group, str) or len(self.correlation_group) > 128:
            raise ValueError("Evidence correlation_group must be a string up to 128 characters")
        if not isinstance(self.detail, str) or len(self.detail) > 1000:
            raise ValueError("Evidence detail must be a string up to 1000 characters")
        if not isinstance(self.at, (int, float)) or isinstance(self.at, bool) or not math.isfinite(self.at):
            raise ValueError("Evidence timestamp must be finite")
        if not isinstance(self.attributes, Mapping):
            raise ValueError("Evidence attributes must be a mapping")

    @property
    def risk_score(self) -> int:
        """Return a conservative single-signal score used only as fusion input."""
        weighted = round(100.0 * float(self.maliciousness) * float(self.confidence))
        if self.severity:
            weighted = min(weighted, self.severity)
        return min(95, max(0, int(weighted)))

    def stamped(self, at: float) -> "Evidence":
        return self if self.at else replace(self, at=float(at))

    def to_dict(self) -> dict:
        value = asdict(self)
        value["attributes"] = dict(self.attributes)
        value["risk_score"] = self.risk_score
        return value


def coerce_evidence(value: Evidence | Mapping[str, object]) -> Evidence:
    if isinstance(value, Evidence):
        return value
    if not isinstance(value, Mapping):
        raise TypeError("Evidence must be Evidence or a mapping")
    allowed = {
        "source", "kind", "subject", "maliciousness", "confidence", "severity",
        "complete", "correlation_group", "detail", "at", "attributes",
    }
    return Evidence(**{key: item for key, item in value.items() if key in allowed})


def summarize_evidence(values: Iterable[Evidence | Mapping[str, object]]) -> tuple[int, tuple[str, ...]]:
    """Return a conservative score and unique sources for generic evidence."""
    groups: dict[str, int] = {}
    sources: list[str] = []
    for raw in values:
        item = coerce_evidence(raw)
        group = item.correlation_group or item.source
        groups[group] = max(groups.get(group, 0), item.risk_score)
        if item.source not in sources:
            sources.append(item.source)
    return max(groups.values(), default=0), tuple(sources[:32])


Subscriber = Callable[[Evidence], None]


class EvidenceBus:
    """Thread-safe bounded in-memory fan-out for sensor observations."""

    def __init__(self, *, max_events: int = 4096, clock=time.time):
        if type(max_events) is not int or not 16 <= max_events <= 100_000:
            raise ValueError("max_events must be between 16 and 100000")
        self.max_events = max_events
        self.clock = clock
        self._events: deque[Evidence] = deque(maxlen=max_events)
        self._subscribers: list[Subscriber] = []
        self._lock = RLock()
        self.published = 0
        self.delivery_failures = 0
        self.last_delivery_error = ""

    def subscribe(self, callback: Subscriber) -> Callable[[], None]:
        if not callable(callback):
            raise TypeError("Evidence subscriber must be callable")
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def publish(self, value: Evidence | Mapping[str, object]) -> Evidence:
        item = coerce_evidence(value).stamped(float(self.clock()))
        with self._lock:
            self._events.append(item)
            self.published += 1
            subscribers = tuple(self._subscribers)
        for callback in subscribers:
            try:
                callback(item)
            except Exception as exc:
                with self._lock:
                    self.delivery_failures += 1
                    self.last_delivery_error = f"{type(exc).__name__}: {exc}"[:500]
        return item

    def recent(self, *, subject: str | None = None, kinds: Iterable[str] | None = None,
               max_age: float | None = None) -> list[Evidence]:
        if max_age is not None and (
            not isinstance(max_age, (int, float)) or isinstance(max_age, bool)
            or not math.isfinite(max_age) or max_age < 0
        ):
            raise ValueError("max_age must be finite and non-negative")
        allowed = set(kinds) if kinds is not None else None
        now = float(self.clock())
        with self._lock:
            values = list(self._events)
        return [
            item for item in values
            if (subject is None or item.subject == subject)
            and (allowed is None or item.kind in allowed)
            and (max_age is None or now - item.at <= max_age)
        ]

    def status(self) -> dict:
        with self._lock:
            return {
                "mode": "bounded-local-evidence-bus",
                "published": self.published,
                "buffered": len(self._events),
                "capacity": self.max_events,
                "subscribers": len(self._subscribers),
                "delivery_failures": self.delivery_failures,
                "last_delivery_error": self.last_delivery_error,
            }
