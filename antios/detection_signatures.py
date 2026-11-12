"""Explainable evidence signatures for AntiOS detection fusion.

These signatures combine observations from independent sensors. They are
review-only evidence: a match can raise risk and enrich an incident, but never
authorizes automatic quarantine. Exact authenticated malware hashes remain the
only confirmed-threat path in the current engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .evidence import Evidence, coerce_evidence


_SUPPORTED_OPERATORS = frozenset({"eq", "gte", "lte", "truthy", "contains"})


@dataclass(frozen=True)
class AttributeConstraint:
    key: str
    operator: str
    value: object = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key or len(self.key) > 128:
            raise ValueError("Constraint key must be non-empty and <= 128 characters")
        if self.operator not in _SUPPORTED_OPERATORS:
            raise ValueError("Unsupported evidence constraint operator")

    def matches(self, attributes: Mapping[str, object]) -> bool:
        if self.key not in attributes:
            return False
        actual = attributes[self.key]
        if self.operator == "eq":
            return actual == self.value
        if self.operator == "truthy":
            return bool(actual)
        if self.operator in {"gte", "lte"}:
            if (not isinstance(actual, (int, float)) or isinstance(actual, bool)
                    or not isinstance(self.value, (int, float)) or isinstance(self.value, bool)):
                return False
            return actual >= self.value if self.operator == "gte" else actual <= self.value
        if self.operator == "contains":
            if isinstance(actual, str) and isinstance(self.value, str):
                return self.value.lower() in actual.lower()
            if isinstance(actual, (list, tuple, set, frozenset)):
                return self.value in actual
            return False
        return False


@dataclass(frozen=True)
class SignalPattern:
    kinds: frozenset[str] = frozenset()
    sources: frozenset[str] = frozenset()
    constraints: tuple[AttributeConstraint, ...] = ()
    min_risk_score: int = 0

    def __post_init__(self) -> None:
        if type(self.min_risk_score) is not int or not 0 <= self.min_risk_score <= 95:
            raise ValueError("Pattern min_risk_score must be between 0 and 95")
        if not self.kinds and not self.sources and not self.constraints and not self.min_risk_score:
            raise ValueError("Evidence pattern cannot be empty")

    def matches(self, item: Evidence) -> bool:
        return (
            (not self.kinds or item.kind in self.kinds)
            and (not self.sources or item.source in self.sources)
            and item.risk_score >= self.min_risk_score
            and all(constraint.matches(item.attributes) for constraint in self.constraints)
        )


@dataclass(frozen=True)
class DetectionSignature:
    rule_id: str
    label: str
    family: str
    patterns: tuple[SignalPattern, ...]
    severity: int
    maliciousness: float
    confidence: float
    same_subject: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id or len(self.rule_id) > 128:
            raise ValueError("Detection signature rule_id must be non-empty and <= 128 characters")
        if not isinstance(self.label, str) or not self.label or len(self.label) > 200:
            raise ValueError("Detection signature label must be non-empty and <= 200 characters")
        if not isinstance(self.family, str) or not self.family or len(self.family) > 128:
            raise ValueError("Detection signature family must be non-empty and <= 128 characters")
        if not self.patterns:
            raise ValueError("Detection signature needs at least one pattern")
        if type(self.severity) is not int or not 1 <= self.severity <= 95:
            raise ValueError("Detection signature severity must be between 1 and 95")
        for name, value in (("maliciousness", self.maliciousness), ("confidence", self.confidence)):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
                raise ValueError(f"Detection signature {name} must be between 0 and 1")
        if not isinstance(self.same_subject, bool):
            raise ValueError("Detection signature same_subject must be boolean")

    def match(self, evidence: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
        matched: list[Evidence] = []
        subject: str | None = None
        for pattern in self.patterns:
            candidate = next((
                item for item in evidence
                if pattern.matches(item)
                and (not self.same_subject or subject is None or item.subject == subject)
            ), None)
            if candidate is None:
                return ()
            if self.same_subject and subject is None:
                subject = candidate.subject
            matched.append(candidate)
        return tuple(matched)


class DetectionSignatureEngine:
    """Evaluate bounded explainable rules over already-collected evidence."""

    def __init__(self, signatures: Iterable[DetectionSignature]):
        rules = tuple(signatures)
        if len(rules) > 1024:
            raise ValueError("Too many detection signatures")
        ids = [rule.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate detection signature id")
        self.signatures = rules

    def evaluate(self, values: Iterable[Evidence | Mapping[str, object]]) -> tuple[Evidence, ...]:
        evidence = tuple(coerce_evidence(item) for item in values)
        findings: list[Evidence] = []
        for rule in self.signatures:
            matched = rule.match(evidence)
            if not matched:
                continue
            subjects = [item.subject for item in matched if item.subject]
            subject = subjects[0] if subjects else rule.family
            attributes = {
                "rule_id": rule.rule_id,
                "family": rule.family,
                "label": rule.label,
                "matched_sources": [item.source for item in matched],
                "matched_kinds": [item.kind for item in matched],
            }
            # Preserve stable process/file anchors when every contributing
            # signal agrees. This lets IncidentGraph attach a fused signature
            # to the same subject instead of creating a detached incident.
            for key in ("pid", "creation_time", "path"):
                values = [
                    item.attributes.get(key)
                    for item in matched
                    if key in item.attributes
                ]
                if len(values) == len(matched) and values and all(
                    value == values[0] for value in values
                ):
                    attributes[key] = values[0]
            findings.append(Evidence(
                source=f"signature:{rule.rule_id}",
                kind="behavior",
                subject=subject,
                maliciousness=rule.maliciousness,
                confidence=rule.confidence,
                severity=rule.severity,
                complete=all(item.complete for item in matched),
                correlation_group=f"signature-family:{rule.family}",
                detail=rule.label,
                at=max((item.at for item in matched), default=0.0),
                attributes=attributes,
            ))
        return tuple(findings)


def _eq(key: str, value: object) -> AttributeConstraint:
    return AttributeConstraint(key, "eq", value)


def _gte(key: str, value: float) -> AttributeConstraint:
    return AttributeConstraint(key, "gte", value)


def _truthy(key: str) -> AttributeConstraint:
    return AttributeConstraint(key, "truthy")


def behavior_findings_to_evidence(findings: Iterable[Mapping[str, object]]) -> tuple[Evidence, ...]:
    """Translate existing BehaviorEngine findings into rule-engine inputs.

    This adapter does not add new maliciousness to risk by itself. Risk fusion
    uses it only as context for multi-sensor signatures, while the original
    behavior score remains authoritative for behavior-only decisions.
    """
    translated: list[Evidence] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        rule = finding.get("rule")
        score = finding.get("score", 0)
        if not isinstance(rule, str) or not rule or type(score) is not int:
            continue
        score = min(95, max(0, score))
        attributes: dict[str, object] = {}
        if rule == "document-spawns-interpreter":
            attributes.update(document_spawns_interpreter=True, interpreter_execution=True)
        elif rule == "browser-spawns-interpreter":
            attributes.update(browser_spawns_interpreter=True, interpreter_execution=True)
        elif rule == "user-writable-execution":
            attributes["user_writable_execution"] = True
        elif rule == "changed-then-executed":
            attributes["changed_then_executed"] = True
        elif rule == "mass-file-changes":
            attributes["mass_file_changes"] = True
        elif rule == "interpreter-with-mass-file-changes":
            attributes.update(mass_file_changes=True, interpreter_execution=True)
        else:
            continue
        translated.append(Evidence(
            source=f"behavior:{rule}",
            kind="behavior",
            subject=str(finding.get("subject") or ""),
            maliciousness=min(.95, score / 100.0),
            confidence=.90,
            severity=score,
            correlation_group=f"behavior-rule:{rule}",
            detail=str(finding.get("summary") or "")[:1000],
            at=float(finding.get("at") or 0.0),
            attributes=attributes,
        ))
    return tuple(translated)


DEFAULT_DETECTION_SIGNATURES = DetectionSignatureEngine((
    DetectionSignature(
        "file.packed-rwx-high-entropy",
        "Writable executable region with high-entropy executable content",
        "packed-executable",
        (
            SignalPattern(kinds=frozenset({"file"}), constraints=(
                _eq("writable_executable", True),
            )),
            SignalPattern(kinds=frozenset({"file"}), constraints=(
                _eq("high_entropy_executable", True),
            )),
        ),
        severity=70, maliciousness=.80, confidence=.80,
    ),
    DetectionSignature(
        "memory.private-executable-pe",
        "PE image observed in private executable memory",
        "in-memory-execution",
        (
            SignalPattern(kinds=frozenset({"memory"}), constraints=(
                _eq("private_executable", True),
                _eq("embedded_pe", True),
            )),
        ),
        severity=90, maliciousness=.95, confidence=.90,
    ),
    DetectionSignature(
        "memory.remote-write-thread",
        "Remote process write correlated with remote thread execution",
        "process-injection",
        (
            SignalPattern(kinds=frozenset({"memory"}), constraints=(
                _eq("remote_write", True),
            )),
            SignalPattern(kinds=frozenset({"memory", "process"}), constraints=(
                _eq("remote_thread", True),
            )),
        ),
        severity=95, maliciousness=.98, confidence=.92,
    ),
    DetectionSignature(
        "memory.private-thread-start",
        "Thread start address points into private executable memory",
        "in-memory-execution",
        (
            SignalPattern(kinds=frozenset({"memory", "process"}), constraints=(
                _eq("thread_start_private_exec", True),
            )),
        ),
        severity=90, maliciousness=.93, confidence=.90,
    ),
    DetectionSignature(
        "process.document-interpreter-network",
        "Document-launched interpreter established an outbound connection",
        "document-execution-chain",
        (
            SignalPattern(kinds=frozenset({"behavior", "process"}), constraints=(
                _eq("document_spawns_interpreter", True),
            )),
            SignalPattern(kinds=frozenset({"network"}), constraints=(
                _eq("outbound_connection", True),
            )),
        ),
        severity=85, maliciousness=.88, confidence=.84,
    ),
    DetectionSignature(
        "process.browser-interpreter-persistence",
        "Browser-launched interpreter correlated with persistence creation",
        "browser-execution-chain",
        (
            SignalPattern(kinds=frozenset({"behavior", "process"}), constraints=(
                _eq("browser_spawns_interpreter", True),
            )),
            SignalPattern(kinds=frozenset({"behavior", "process"}), constraints=(
                _eq("persistence_created", True),
            )),
        ),
        severity=85, maliciousness=.88, confidence=.84,
    ),
    DetectionSignature(
        "ransomware.mass-change-execution",
        "Mass file modification correlated with script or interpreter execution",
        "ransomware-like-behavior",
        (
            SignalPattern(kinds=frozenset({"behavior"}), constraints=(
                _eq("mass_file_changes", True),
            )),
            SignalPattern(kinds=frozenset({"process", "behavior"}), constraints=(
                _eq("interpreter_execution", True),
            )),
        ),
        severity=95, maliciousness=.95, confidence=.90,
    ),
    DetectionSignature(
        "gpu.hidden-compute-abuse",
        "Unsigned hidden process sustained unusually high GPU compute load",
        "compute-abuse",
        (
            SignalPattern(kinds=frozenset({"gpu"}), constraints=(
                _gte("compute_percent", 90),
                _eq("visible_window", False),
                _eq("signed", False),
            )),
        ),
        severity=70, maliciousness=.72, confidence=.78,
    ),
    DetectionSignature(
        "gpu.hidden-compute-network",
        "Hidden high-compute process also established outbound network activity",
        "compute-abuse",
        (
            SignalPattern(kinds=frozenset({"gpu"}), constraints=(
                _gte("compute_percent", 90),
                _eq("visible_window", False),
            )),
            SignalPattern(kinds=frozenset({"network"}), constraints=(
                _eq("outbound_connection", True),
            )),
        ),
        severity=80, maliciousness=.82, confidence=.82,
    ),
    DetectionSignature(
        "similarity.malicious-family-near-match",
        "Unknown file is a strong structural near-match to a known malicious family",
        "malware-similarity",
        (
            SignalPattern(kinds=frozenset({"model", "file"}), constraints=(
                _gte("malicious_similarity", .95),
                _truthy("reference_family"),
            )),
        ),
        severity=80, maliciousness=.86, confidence=.82,
    ),
    DetectionSignature(
        "model.high-confidence-static-with-structure",
        "High-confidence static model score agrees with an independent structural anomaly",
        "static-ml",
        (
            SignalPattern(kinds=frozenset({"model"}), constraints=(
                _gte("malware_probability", .98),
            )),
            SignalPattern(kinds=frozenset({"file"}), constraints=(
                _eq("structural_anomaly", True),
            )),
        ),
        severity=88, maliciousness=.92, confidence=.86,
    ),
    DetectionSignature(
        "temp-execution-private-memory",
        "User-writable execution correlated with private executable memory",
        "dropper-loader-chain",
        (
            SignalPattern(kinds=frozenset({"process", "behavior"}), constraints=(
                _eq("user_writable_execution", True),
            )),
            SignalPattern(kinds=frozenset({"memory"}), constraints=(
                _eq("private_executable", True),
            )),
        ),
        severity=90, maliciousness=.94, confidence=.88,
    ),
    DetectionSignature(
        "driver.microsoft-blocklist-loaded",
        "Loaded kernel driver matches a Microsoft recommended deny hash",
        "byovd",
        (
            SignalPattern(kinds=frozenset({"driver"}), constraints=(
                _eq("microsoft_blocked_hash", True),
            )),
        ),
        severity=95, maliciousness=.99, confidence=.98,
    ),
    DetectionSignature(
        "driver.untrusted-user-writable",
        "Untrusted loaded kernel driver originates from a user-writable path",
        "kernel-driver-abuse",
        (
            SignalPattern(kinds=frozenset({"driver"}), constraints=(
                _eq("user_writable_path", True),
                _eq("signature_valid", False),
            )),
        ),
        severity=92, maliciousness=.96, confidence=.90,
    ),
))
