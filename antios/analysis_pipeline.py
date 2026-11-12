"""Adaptive staged-analysis coordinator for future AntiOS detectors.

The pipeline provides control flow only. Stages decide what evidence they can
produce; enforcement remains outside this module. Cheap stages may stop a
clean analysis, while ambiguous results can explicitly request deeper stages.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, Sequence

from .evidence import Evidence, EvidenceBus


class StageDisposition(StrEnum):
    CONTINUE = "continue"
    STOP = "stop"
    ESCALATE = "escalate"


@dataclass
class AnalysisContext:
    subject: str
    bytes_total: int = 0
    metadata: dict[str, object] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject:
            raise ValueError("Analysis subject must be non-empty")
        if type(self.bytes_total) is not int or self.bytes_total < 0:
            raise ValueError("Analysis bytes_total must be a non-negative integer")
        if not isinstance(self.metadata, dict):
            raise ValueError("Analysis metadata must be a dict")


@dataclass(frozen=True)
class StageResult:
    disposition: str = StageDisposition.CONTINUE
    evidence: tuple[Evidence, ...] = ()
    complete: bool = True
    reason: str = ""

    def __post_init__(self) -> None:
        if self.disposition not in {item.value for item in StageDisposition}:
            raise ValueError("Unsupported stage disposition")
        if not isinstance(self.evidence, tuple) or not all(isinstance(item, Evidence) for item in self.evidence):
            raise ValueError("Stage evidence must be a tuple of Evidence")
        if not isinstance(self.complete, bool):
            raise ValueError("Stage complete must be boolean")
        if not isinstance(self.reason, str) or len(self.reason) > 500:
            raise ValueError("Stage reason must be a string up to 500 characters")


class AnalysisStage(Protocol):
    name: str

    def analyze(self, context: AnalysisContext) -> StageResult:
        ...


@dataclass(frozen=True)
class PipelineResult:
    subject: str
    stages_run: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    complete: bool
    stopped_by: str = ""
    escalated: bool = False

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "stages_run": list(self.stages_run),
            "evidence": [item.to_dict() for item in self.evidence],
            "complete": self.complete,
            "stopped_by": self.stopped_by,
            "escalated": self.escalated,
        }


class AdaptiveAnalysisPipeline:
    """Run ordered stages and preserve explainable escalation decisions."""

    def __init__(self, stages: Sequence[AnalysisStage] = (), *, evidence_bus: EvidenceBus | None = None,
                 max_stages: int = 32):
        if type(max_stages) is not int or not 1 <= max_stages <= 128:
            raise ValueError("max_stages must be between 1 and 128")
        if len(stages) > max_stages:
            raise ValueError("Too many analysis stages")
        names = [str(stage.name) for stage in stages]
        if any(not name for name in names) or len(names) != len(set(names)):
            raise ValueError("Analysis stage names must be unique and non-empty")
        self.stages = tuple(stages)
        self.evidence_bus = evidence_bus
        self.max_stages = max_stages

    def run(self, context: AnalysisContext) -> PipelineResult:
        stages_run: list[str] = []
        complete = True
        escalated = False
        stopped_by = ""
        for stage in self.stages[:self.max_stages]:
            result = stage.analyze(context)
            if not isinstance(result, StageResult):
                raise TypeError(f"Analysis stage {stage.name} returned an invalid result")
            stages_run.append(str(stage.name))
            complete = complete and result.complete
            for item in result.evidence:
                context.evidence.append(item)
                if self.evidence_bus is not None:
                    self.evidence_bus.publish(item)
            if result.disposition == StageDisposition.ESCALATE:
                escalated = True
                continue
            if result.disposition == StageDisposition.STOP:
                stopped_by = str(stage.name)
                break
        return PipelineResult(
            subject=context.subject,
            stages_run=tuple(stages_run),
            evidence=tuple(context.evidence),
            complete=complete,
            stopped_by=stopped_by,
            escalated=escalated,
        )
