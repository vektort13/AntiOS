"""Explainable per-file risk fusion for AntiOS.

RiskContext combines scanner evidence, recent behavior correlation and file
origin. Native pre-execution state is represented as protection context, not as
a maliciousness signal. Only a confirmed scanner threat is eligible for
automatic enforcement; heuristics remain review-only.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ntpath
import time
from typing import Iterable

from .detection_signatures import DEFAULT_DETECTION_SIGNATURES, behavior_findings_to_evidence
from .evidence import Evidence, summarize_evidence


@dataclass(frozen=True)
class RiskContext:
    path: str
    score: int
    classification: str
    recommended_action: str
    automatic_enforcement_eligible: bool
    scanner_verdict: str
    scanner_complete: bool
    confirmed_threat: bool
    review_signal: bool
    behavior_score: int
    behavior_rules: tuple[str, ...]
    evidence_score: int
    evidence_sources: tuple[str, ...]
    evidence_rules: tuple[str, ...]
    origin: str
    origin_score: int
    native_pre_execution: str
    native_execution_boundary_protected: bool | None
    evaluated_at: float

    def to_dict(self) -> dict:
        value = asdict(self)
        value["behavior_rules"] = list(self.behavior_rules)
        return value


def classify_origin(path: str) -> tuple[str, int]:
    normalized = ntpath.normcase(ntpath.normpath(path or ""))
    parts = tuple(part.lower() for part in normalized.replace("/", "\\").split("\\") if part)
    if not normalized:
        return "unknown", 0
    if "startup" in parts or (
        "start menu" in parts and "programs" in parts and parts[-1] == "startup"
    ):
        return "startup", 15
    if "appdata" in parts and "local" in parts and "temp" in parts:
        return "user-temp", 10
    if "downloads" in parts:
        return "downloads", 5
    if "\\windows\\" in normalized or normalized.startswith("c:\\windows\\"):
        return "windows", 0
    if "\\program files\\" in normalized or "\\program files (x86)\\" in normalized:
        return "program-files", 0
    return "other", 0


def _behavior_summary(findings: Iterable[dict]) -> tuple[int, tuple[str, ...]]:
    highest = 0
    rules: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        score = finding.get("score", 0)
        if isinstance(score, int):
            highest = max(highest, min(100, max(0, score)))
        rule = finding.get("rule")
        if isinstance(rule, str) and rule and rule not in rules:
            rules.append(rule)
    return highest, tuple(rules[:16])


def _scanner_summary(result: dict) -> tuple[str, bool, bool, bool]:
    verdict = str(result.get("verdict") or "unknown")
    coverage = str(result.get("coverage") or "limited")
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    confirmed = any(
        isinstance(item, dict) and item.get("kind") == "threat"
        for item in findings
    )
    review = (
        verdict == "review" or
        any(isinstance(item, dict) and item.get("kind") == "review" for item in findings)
    )
    engine = result.get("engine") if isinstance(result.get("engine"), dict) else {}
    # A retired ClamAV/AMSI coverage string must never be promoted to a
    # complete result by the native risk classifier.
    engine_ready = bool(
        engine.get("available") is True and
        engine.get("failed_during_scan") is not True and
        engine.get("database_freshness") == "local"
    )
    complete = coverage == "antios-local-inspection" and engine_ready
    return verdict, complete, confirmed, review


def evaluate_risk(path: str, scan_result: dict, *, behavior_findings: Iterable[dict] = (),
                  evidence: Iterable[Evidence | dict] = (),
                  native_pre_execution: bool | None = None,
                  now: float | None = None) -> RiskContext:
    verdict, complete, confirmed, review = _scanner_summary(scan_result)
    behavior_items = tuple(behavior_findings)
    behavior_score, behavior_rules = _behavior_summary(behavior_items)
    raw_evidence = tuple(evidence)
    behavior_evidence = behavior_findings_to_evidence(behavior_items)
    signature_evidence = DEFAULT_DETECTION_SIGNATURES.evaluate(
        (*raw_evidence, *behavior_evidence)
    )
    evidence_score, evidence_sources = summarize_evidence((*raw_evidence, *signature_evidence))
    evidence_rules = tuple(
        str(item.attributes.get("rule_id"))
        for item in signature_evidence
        if item.attributes.get("rule_id")
    )
    origin, origin_score = classify_origin(path)

    if confirmed:
        score = 100
    else:
        base = 0
        if review:
            base = 65
        elif not complete:
            base = 50

        if behavior_score >= 90:
            base = max(base, 90)
        elif behavior_score >= 75:
            base = max(base, 80)
        elif behavior_score >= 60:
            base = max(base, 70)
        elif behavior_score > 0:
            base = max(base, min(45, behavior_score))

        # Generic evidence is already confidence/severity bounded. Keep the
        # strongest independent signal rather than adding uncalibrated points.
        base = max(base, evidence_score)

        # Origin is context, never sufficient to produce a high-risk decision.
        if base > 0:
            score = min(95, base + origin_score)
        else:
            score = min(25, origin_score)

    if confirmed:
        classification = "confirmed-threat"
        action = "quarantine-or-native-block"
        automatic = True
    elif score >= 90:
        classification = "critical-behavior"
        action = "review-immediately"
        automatic = False
    elif score >= 75:
        classification = "high"
        action = "review-and-rescan"
        automatic = False
    elif score >= 60:
        classification = "elevated"
        action = "review"
        automatic = False
    elif score >= 40:
        classification = "observe"
        action = "observe"
        automatic = False
    else:
        classification = "low"
        action = "none"
        automatic = False

    if native_pre_execution is True:
        native_state = "active"
        protected = True
    elif native_pre_execution is False:
        native_state = "inactive"
        protected = False
    else:
        native_state = "unknown"
        protected = None

    return RiskContext(
        path=str(path),
        score=score,
        classification=classification,
        recommended_action=action,
        automatic_enforcement_eligible=automatic,
        scanner_verdict=verdict,
        scanner_complete=complete,
        confirmed_threat=confirmed,
        review_signal=review,
        behavior_score=behavior_score,
        behavior_rules=behavior_rules,
        evidence_score=evidence_score,
        evidence_sources=evidence_sources,
        evidence_rules=evidence_rules,
        origin=origin,
        origin_score=origin_score,
        native_pre_execution=native_state,
        native_execution_boundary_protected=protected,
        evaluated_at=float(now if now is not None else time.time()),
    )
