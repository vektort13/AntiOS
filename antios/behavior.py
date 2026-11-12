"""Bounded behavioral correlation for AntiOS Guard.

This module is detection-only. It never terminates processes, changes Defender,
or claims pre-execution enforcement. Inputs are deliberately simple so Windows
collectors, Guard file notifications and tests can feed the same rule engine.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
import ntpath
from pathlib import PureWindowsPath
import time
from typing import Iterable


_INTERPRETERS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
})
_DOCUMENT_PARENTS = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "acrord32.exe", "acrobat.exe",
})
_BROWSER_PARENTS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
})
_EXECUTABLE_SUFFIXES = frozenset({
    ".exe", ".com", ".scr", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar",
})


@dataclass(frozen=True)
class ProcessEvent:
    pid: int
    ppid: int
    image: str
    path: str = ""
    parent_image: str = ""
    parent_path: str = ""
    at: float = 0.0
    creation_time: int = 0
    parent_creation_time: int = 0
    command_line: str = ""
    signer: str = ""
    integrity_level: str = ""


@dataclass(frozen=True)
class BehaviorFinding:
    rule: str
    severity: str
    score: int
    summary: str
    subject: str
    at: float

    def to_dict(self) -> dict:
        return asdict(self)


def _basename(value: str) -> str:
    return ntpath.basename(value or "").lower()


def _normalized_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value or ""))


def _execution_boundary(path: str) -> bool:
    return ntpath.splitext(path)[1].lower() in _EXECUTABLE_SUFFIXES


def _user_writable_execution_path(path: str) -> bool:
    if not path or not _execution_boundary(path):
        return False
    lowered = _normalized_path(path)
    pieces = [piece.lower() for piece in PureWindowsPath(path).parts]
    if "downloads" in pieces:
        return True
    return "\\appdata\\local\\temp\\" in lowered or lowered.endswith("\\appdata\\local\\temp")


class BehaviorEngine:
    """Small bounded correlator with conservative, explainable rules."""

    def __init__(self, *, clock=time.monotonic, event_window=30.0,
                 mass_window=10.0, mass_threshold=40, dedupe_seconds=60.0):
        if not 5 <= event_window <= 300:
            raise ValueError("event_window must be between 5 and 300 seconds")
        if not 2 <= mass_window <= 60:
            raise ValueError("mass_window must be between 2 and 60 seconds")
        if not 10 <= mass_threshold <= 1000:
            raise ValueError("mass_threshold must be between 10 and 1000")
        self.clock = clock
        self.event_window = float(event_window)
        self.mass_window = float(mass_window)
        self.mass_threshold = int(mass_threshold)
        self.dedupe_seconds = float(dedupe_seconds)
        self.processes = deque(maxlen=512)
        self.files = deque(maxlen=4096)
        self.findings = deque(maxlen=100)
        self._dedupe: dict[tuple[str, str], float] = {}
        self.process_events = 0
        self.file_events = 0

    def _now(self, supplied: float) -> float:
        return float(supplied or self.clock())

    def _prune(self, now: float) -> None:
        while self.processes and now - self.processes[0].at > self.event_window:
            self.processes.popleft()
        while self.files and now - self.files[0][0] > max(self.event_window, self.mass_window):
            self.files.popleft()
        for key, at in list(self._dedupe.items()):
            if now - at > self.dedupe_seconds:
                del self._dedupe[key]

    def _finding(self, rule: str, severity: str, score: int,
                 summary: str, subject: str, now: float) -> list[BehaviorFinding]:
        key = (rule, subject.lower())
        previous = self._dedupe.get(key)
        if previous is not None and now - previous <= self.dedupe_seconds:
            return []
        finding = BehaviorFinding(rule, severity, score, summary, subject, now)
        self._dedupe[key] = now
        self.findings.append(finding)
        return [finding]

    def observe_process(self, event: ProcessEvent) -> list[BehaviorFinding]:
        now = self._now(event.at)
        event = ProcessEvent(
            int(event.pid), int(event.ppid), event.image or "", event.path or "",
            event.parent_image or "", event.parent_path or "", now,
            int(event.creation_time or 0), int(event.parent_creation_time or 0),
            event.command_line or "", event.signer or "", event.integrity_level or "",
        )
        self._prune(now)
        self.processes.append(event)
        self.process_events += 1
        findings: list[BehaviorFinding] = []

        child = _basename(event.image or event.path)
        parent = _basename(event.parent_image or event.parent_path)
        subject = event.path or event.image or f"pid:{event.pid}"

        if child in _INTERPRETERS and parent in _DOCUMENT_PARENTS:
            findings += self._finding(
                "document-spawns-interpreter", "high", 85,
                f"{parent} started {child}", subject, now,
            )
        elif child in _INTERPRETERS and parent in _BROWSER_PARENTS:
            findings += self._finding(
                "browser-spawns-interpreter", "high", 80,
                f"{parent} started {child}", subject, now,
            )

        if _user_writable_execution_path(event.path):
            findings += self._finding(
                "user-writable-execution", "low", 45,
                "Executable or script started from Downloads/Temp", subject, now,
            )

        normalized = _normalized_path(event.path)
        if normalized and any(
            normalized == path and now - changed <= self.event_window
            for changed, path in self.files
        ):
            findings += self._finding(
                "changed-then-executed", "high", 75,
                "Recently changed file was executed", subject, now,
            )

        recent_unique = {path for changed, path in self.files if now - changed <= self.mass_window}
        if child in _INTERPRETERS and len(recent_unique) >= self.mass_threshold:
            findings += self._finding(
                "interpreter-with-mass-file-changes", "critical", 95,
                f"{child} observed during mass file changes", subject, now,
            )
        return findings

    def observe_file_change(self, path: str, *, at: float = 0.0) -> list[BehaviorFinding]:
        now = self._now(at)
        normalized = _normalized_path(path)
        if not normalized:
            return []
        self._prune(now)
        self.files.append((now, normalized))
        self.file_events += 1

        recent_unique = {item for changed, item in self.files if now - changed <= self.mass_window}
        if len(recent_unique) < self.mass_threshold:
            return []

        active_interpreter = next((
            process for process in reversed(self.processes)
            if now - process.at <= self.mass_window and
            _basename(process.image or process.path) in _INTERPRETERS
        ), None)
        if active_interpreter is not None:
            subject = active_interpreter.path or active_interpreter.image or f"pid:{active_interpreter.pid}"
            return self._finding(
                "interpreter-with-mass-file-changes", "critical", 95,
                f"Mass file changes correlated with {_basename(active_interpreter.image or active_interpreter.path)}",
                subject, now,
            )

        return self._finding(
            "mass-file-changes", "medium", 65,
            f"{len(recent_unique)} distinct paths changed within {self.mass_window:g}s",
            "filesystem", now,
        )

    def observe_many_file_changes(self, paths: Iterable[str], *, at: float = 0.0) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        for path in dict.fromkeys(str(path) for path in paths):
            findings.extend(self.observe_file_change(path, at=at))
        return findings

    def findings_for_subject(self, subject: str, *, max_age: float | None = None) -> list[dict]:
        """Return recent findings that refer to one exact path/process subject."""
        now = self.clock()
        self._prune(now)
        wanted = _normalized_path(subject)
        if not wanted:
            return []
        age = self.event_window if max_age is None else float(max_age)
        if not 0 <= age <= 300:
            raise ValueError("max_age must be between 0 and 300 seconds")
        return [
            finding.to_dict()
            for finding in self.findings
            if now - finding.at <= age and _normalized_path(finding.subject) == wanted
        ]

    def status(self) -> dict:
        now = self.clock()
        self._prune(now)
        recent = [finding for finding in self.findings if now - finding.at <= 300]
        highest = max((finding.score for finding in recent), default=0)
        if highest >= 90:
            state = "alert"
        elif highest >= 60:
            state = "attention"
        else:
            state = "normal"
        return {
            "state": state,
            "mode": "detect-only",
            "process_events": self.process_events,
            "file_events": self.file_events,
            "recent_findings": len(recent),
            "highest_score": highest,
            "findings": [finding.to_dict() for finding in recent[-10:]],
        }
