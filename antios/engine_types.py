"""Shared detection result contract. No external antivirus runtime dependencies."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanOutcome:
    kind: str | None = None
    name: str = ""
    engine: str = "AntiOS Engine"
    complete: bool = True
    detail: str = ""
    rule_id: str = ""
    coverage_gaps: frozenset[str] = frozenset()
