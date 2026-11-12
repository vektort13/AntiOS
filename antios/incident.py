"""Bounded local incident graph for AntiOS Resident Guard.

The graph correlates already-observed evidence. It does not collect additional
sensitive data, terminate processes or make automatic enforcement decisions.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
import ntpath
import time
from typing import Iterable

from .behavior import ProcessEvent
from .evidence import Evidence, coerce_evidence
from .process_identity import process_identity


def _path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value or ""))


def _name(value: str) -> str:
    return ntpath.basename(value or "").lower()


def _classification_for_score(score: int, *, confirmed: bool = False) -> str:
    if confirmed:
        return "confirmed-threat"
    if score >= 90:
        return "critical-behavior"
    if score >= 75:
        return "high"
    if score >= 60:
        return "elevated"
    if score >= 40:
        return "observe"
    return "low"


@dataclass(frozen=True)
class IncidentNode:
    id: str
    kind: str
    label: str
    at: float
    data: dict

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class IncidentEdge:
    source: str
    target: str
    relation: str
    at: float

    def to_dict(self) -> dict:
        return asdict(self)


class _Incident:
    def __init__(self, incident_id: str, at: float):
        self.id = incident_id
        self.started_at = at
        self.updated_at = at
        self.score = 0
        self.classification = "observe"
        self.confirmed_threat = False
        self.automatic_enforcement_eligible = False
        self.nodes: dict[str, IncidentNode] = {}
        self.edges: list[IncidentEdge] = []
        self.edge_keys: set[tuple[str, str, str]] = set()

    def touch(self, at: float) -> None:
        self.updated_at = max(self.updated_at, at)


class IncidentGraph:
    """Explainable, bounded correlation graph over Guard evidence."""

    def __init__(self, *, clock=time.monotonic, ttl=120.0, max_incidents=32,
                 max_nodes=64, max_edges=128):
        if not 30 <= ttl <= 900:
            raise ValueError("incident ttl must be between 30 and 900 seconds")
        if not 4 <= max_incidents <= 128:
            raise ValueError("max_incidents must be between 4 and 128")
        if not 16 <= max_nodes <= 256:
            raise ValueError("max_nodes must be between 16 and 256")
        if not 32 <= max_edges <= 512:
            raise ValueError("max_edges must be between 32 and 512")
        self.clock = clock
        self.ttl = float(ttl)
        self.max_incidents = int(max_incidents)
        self.max_nodes = int(max_nodes)
        self.max_edges = int(max_edges)
        self.recent_files = deque(maxlen=4096)
        self.recent_processes = deque(maxlen=512)
        self.incidents: dict[str, _Incident] = {}
        self.path_index: dict[str, str] = {}
        # PID-only index is retained for collectors that cannot observe a
        # creation stamp. Stable collectors use process_index and never fall
        # back to a recycled PID.
        self.pid_index: dict[int, str] = {}
        self.process_index: dict[tuple[int, int], str] = {}
        self.pending_updates = deque(maxlen=100)
        self._pending_incidents: set[str] = set()
        self.total_created = 0
        self._counter = 0
        self.latest_id: str | None = None

    def _now(self, supplied: float = 0.0) -> float:
        return float(supplied or self.clock())

    def _expire(self, now: float) -> None:
        expired = [
            incident_id for incident_id, incident in self.incidents.items()
            if now - incident.updated_at > self.ttl
        ]
        for incident_id in expired:
            del self.incidents[incident_id]
        if expired:
            dead = set(expired)
            self.path_index = {
                key: value for key, value in self.path_index.items()
                if value not in dead
            }
            self.pid_index = {
                key: value for key, value in self.pid_index.items()
                if value not in dead
            }
            self.process_index = {
                key: value for key, value in self.process_index.items()
                if value not in dead
            }
            if self.latest_id in dead:
                self.latest_id = max(
                    self.incidents,
                    key=lambda key: self.incidents[key].updated_at,
                    default=None,
                )
        while self.recent_files and now - self.recent_files[0][0] > self.ttl:
            self.recent_files.popleft()
        while self.recent_processes and now - self.recent_processes[0][0] > self.ttl:
            self.recent_processes.popleft()

    def _new(self, now: float) -> _Incident:
        self._expire(now)
        if len(self.incidents) >= self.max_incidents:
            oldest = min(self.incidents.values(), key=lambda item: item.updated_at)
            old_id = oldest.id
            del self.incidents[old_id]
            self.path_index = {
                key: value for key, value in self.path_index.items()
                if value != old_id
            }
            self.pid_index = {
                key: value for key, value in self.pid_index.items()
                if value != old_id
            }
            self.process_index = {
                key: value for key, value in self.process_index.items()
                if value != old_id
            }
        self._counter += 1
        incident_id = f"INC-{self._counter:06d}"
        incident = _Incident(incident_id, now)
        self.incidents[incident_id] = incident
        self.total_created += 1
        self.latest_id = incident_id
        return incident

    def _process_incident(self, pid: int, creation_time: int = 0) -> _Incident | None:
        if not pid:
            return None
        identity = process_identity(pid, creation_time)
        if identity.stable:
            incident_id = self.process_index.get(identity.lookup_key)
        else:
            incident_id = self.pid_index.get(identity.pid)
        return self.incidents.get(incident_id or "")

    def _index_process(self, pid: int, creation_time: int, incident_id: str) -> None:
        if not pid:
            return
        identity = process_identity(pid, creation_time)
        self.pid_index[identity.pid] = incident_id
        if identity.stable:
            self.process_index[identity.lookup_key] = incident_id

    def _node(self, incident: _Incident, node: IncidentNode) -> bool:
        if node.id in incident.nodes:
            incident.touch(node.at)
            return False
        if len(incident.nodes) >= self.max_nodes:
            return False
        incident.nodes[node.id] = node
        incident.touch(node.at)
        return True

    def _edge(self, incident: _Incident, source: str, target: str,
              relation: str, at: float) -> bool:
        key = (source, target, relation)
        if key in incident.edge_keys or len(incident.edges) >= self.max_edges:
            return False
        incident.edge_keys.add(key)
        incident.edges.append(IncidentEdge(source, target, relation, at))
        incident.touch(at)
        return True

    def _queue_update(self, incident: _Incident, reason: str) -> None:
        self.latest_id = incident.id
        if incident.id in self._pending_incidents:
            # Keep one journal candidate per incident between Guard heartbeats.
            # The snapshot itself is rebuilt on drain, so it still contains the
            # newest nodes/edges and highest severity.
            for item in reversed(self.pending_updates):
                if item["incident_id"] == incident.id:
                    item["reason"] = reason
                    break
            return
        self._pending_incidents.add(incident.id)
        self.pending_updates.append({
            "reason": reason,
            "incident_id": incident.id,
        })

    def _recent_change(self, normalized: str, now: float) -> float | None:
        for changed_at, path in reversed(self.recent_files):
            if path == normalized and now - changed_at <= self.ttl:
                return changed_at
        return None

    def observe_file_change(self, path: str, *, at: float = 0.0) -> list[dict]:
        now = self._now(at)
        self._expire(now)
        normalized = _path(path)
        if not normalized:
            return []
        self.recent_files.append((now, normalized))
        incident_id = self.path_index.get(normalized)
        if not incident_id or incident_id not in self.incidents:
            return []
        incident = self.incidents[incident_id]
        file_id = f"file:{normalized}"
        changed_id = f"change:{normalized}:{int(now * 1000)}"
        self._node(incident, IncidentNode(
            file_id, "file", path, now, {"path": path},
        ))
        self._node(incident, IncidentNode(
            changed_id, "file-change", "file changed", now, {"path": path},
        ))
        self._edge(incident, file_id, changed_id, "modified", now)
        self._queue_update(incident, "file-change")
        return [self.snapshot(incident.id)]

    def observe_process(self, event: ProcessEvent, *,
                        behavior_findings: Iterable[dict] = ()) -> list[dict]:
        now = self._now(event.at)
        self._expire(now)
        child_path = _path(event.path)
        parent_path = _path(event.parent_path)
        findings = [item for item in behavior_findings if isinstance(item, dict)]
        behavior_score = max(
            (int(item.get("score", 0)) for item in findings
             if isinstance(item.get("score", 0), int)),
            default=0,
        )

        incident = None
        changed_at = self._recent_change(child_path, now) if child_path else None
        parent_incident = self._process_incident(event.ppid, event.parent_creation_time)
        if parent_incident is not None:
            incident = parent_incident
        if incident is None and child_path in self.path_index:
            incident = self.incidents.get(self.path_index[child_path])
        if incident is None and changed_at is not None:
            incident = self._new(now)
        if incident is None and behavior_score >= 60:
            incident = self._new(now)
        if incident is None:
            self.recent_processes.append((now, event))
            return []

        child_identity = process_identity(event.pid, event.creation_time)
        child_id = child_identity.node_id
        child_label = event.path or event.image or f"pid:{event.pid}"
        self._node(incident, IncidentNode(
            child_id, "process", child_label, now,
            {"pid": event.pid, "ppid": event.ppid, "image": event.image,
             "path": event.path, "creation_time": event.creation_time,
             "command_line": event.command_line, "signer": event.signer,
             "integrity_level": event.integrity_level},
        ))
        self._index_process(event.pid, event.creation_time, incident.id)
        if child_path:
            self.path_index[child_path] = incident.id

        if event.ppid:
            parent_identity = process_identity(event.ppid, event.parent_creation_time)
            parent_id = parent_identity.node_id
            parent_label = event.parent_path or event.parent_image or f"pid:{event.ppid}"
            self._node(incident, IncidentNode(
                parent_id, "process", parent_label, now,
                {"pid": event.ppid, "image": event.parent_image,
                 "path": event.parent_path,
                 "creation_time": event.parent_creation_time},
            ))
            self._index_process(event.ppid, event.parent_creation_time, incident.id)
            if parent_path:
                self.path_index[parent_path] = incident.id
            self._edge(incident, parent_id, child_id, "spawned", now)

        if changed_at is not None and child_path:
            file_id = f"file:{child_path}"
            self._node(incident, IncidentNode(
                file_id, "file", event.path or event.image, changed_at,
                {"path": event.path, "changed_at": changed_at},
            ))
            self.path_index[child_path] = incident.id
            self._edge(incident, file_id, child_id, "executed-as", now)

        for index, finding in enumerate(findings[:16]):
            rule = str(finding.get("rule") or "behavior")
            score = int(finding.get("score", 0)) if isinstance(finding.get("score", 0), int) else 0
            signal_id = f"behavior:{incident.id}:{rule}:{index}:{int(now * 1000)}"
            self._node(incident, IncidentNode(
                signal_id, "behavior", rule, now,
                {"rule": rule, "score": score,
                 "severity": finding.get("severity"),
                 "summary": finding.get("summary")},
            ))
            self._edge(incident, child_id, signal_id, "raised-signal", now)
            incident.score = max(incident.score, min(95, max(0, score)))
            incident.classification = _classification_for_score(
                incident.score, confirmed=incident.confirmed_threat
            )

        self.recent_processes.append((now, event))
        self._queue_update(incident, "process-correlation")
        return [self.snapshot(incident.id)]

    def observe_behavior_findings(self, findings: Iterable[dict], *, at: float = 0.0) -> list[dict]:
        now = self._now(at)
        self._expire(now)
        updates: list[dict] = []
        for finding in [item for item in findings if isinstance(item, dict)][:16]:
            score = finding.get("score", 0)
            score = int(score) if isinstance(score, int) else 0
            if score < 60:
                continue
            rule = str(finding.get("rule") or "behavior")
            subject = str(finding.get("subject") or "")
            normalized = _path(subject) if subject and subject != "filesystem" else ""
            incident = self.incidents.get(self.path_index.get(normalized, "")) if normalized else None

            process = next((
                event for seen_at, event in reversed(self.recent_processes)
                if now - seen_at <= self.ttl and normalized and
                _path(event.path) == normalized
            ), None)
            if incident is None and process is not None:
                incident = self._process_incident(process.pid, process.creation_time)
            if incident is None:
                incident = self._new(now)

            anchor_id = None
            if process is not None:
                anchor_id = process_identity(process.pid, process.creation_time).node_id
                self._node(incident, IncidentNode(
                    anchor_id, "process", process.path or process.image, now,
                    {"pid": process.pid, "ppid": process.ppid,
                     "image": process.image, "path": process.path,
                     "creation_time": process.creation_time},
                ))
                self._index_process(process.pid, process.creation_time, incident.id)
                if normalized:
                    self.path_index[normalized] = incident.id

            signal_id = f"behavior:{incident.id}:{rule}:{int(now * 1000)}"
            self._node(incident, IncidentNode(
                signal_id, "behavior", rule, now,
                {"rule": rule, "score": score,
                 "severity": finding.get("severity"),
                 "summary": finding.get("summary"),
                 "subject": subject},
            ))
            if anchor_id:
                self._edge(incident, anchor_id, signal_id, "raised-signal", now)

            if rule in {"mass-file-changes", "interpreter-with-mass-file-changes"}:
                recent = [
                    (changed_at, path) for changed_at, path in self.recent_files
                    if now - changed_at <= 10.0
                ][-32:]
                for changed_at, changed_path in recent:
                    file_id = f"file:{changed_path}"
                    self._node(incident, IncidentNode(
                        file_id, "file", changed_path, changed_at,
                        {"path": changed_path, "changed_at": changed_at},
                    ))
                    self.path_index[changed_path] = incident.id
                    self._edge(
                        incident, anchor_id or signal_id, file_id,
                        "correlated-write", now
                    )

            incident.score = max(incident.score, min(95, max(0, score)))
            incident.classification = _classification_for_score(
                incident.score, confirmed=incident.confirmed_threat
            )
            self._queue_update(incident, "behavior-correlation")
            updates.append(self.snapshot(incident.id))
        return updates

    def observe_evidence(self, values: Iterable[Evidence | dict], *, at: float = 0.0) -> list[dict]:
        """Attach generic sensor/model evidence without granting enforcement."""
        now = self._now(at)
        self._expire(now)
        updates: list[dict] = []
        for raw in list(values)[:32]:
            item = coerce_evidence(raw)
            observed_at = float(item.at or now)
            attrs = dict(item.attributes)
            path_value = attrs.get("path")
            if not isinstance(path_value, str):
                path_value = item.subject if item.kind == "file" else ""
            normalized = _path(path_value)

            pid_value = attrs.get("pid", 0)
            pid = pid_value if type(pid_value) is int and pid_value > 0 else 0
            creation_value = attrs.get("creation_time", 0)
            creation_time = (
                creation_value if type(creation_value) is int and creation_value > 0 else 0
            )

            incident = self.incidents.get(self.path_index.get(normalized, "")) if normalized else None
            if incident is None and pid:
                incident = self._process_incident(pid, creation_time)
            score = item.risk_score
            if incident is None and score >= 40:
                incident = self._new(observed_at)
            if incident is None:
                continue

            anchor_id = ""
            if pid:
                identity = process_identity(pid, creation_time)
                anchor_id = identity.node_id
                self._node(incident, IncidentNode(
                    anchor_id, "process", item.subject or f"pid:{pid}", observed_at,
                    {"pid": pid, "creation_time": creation_time},
                ))
                self._index_process(pid, creation_time, incident.id)
            elif normalized:
                anchor_id = f"file:{normalized}"
                self._node(incident, IncidentNode(
                    anchor_id, "file", path_value, observed_at, {"path": path_value},
                ))
                self.path_index[normalized] = incident.id

            evidence_id = (
                f"evidence:{incident.id}:{len(incident.nodes)}:"
                f"{int(observed_at * 1000000)}"
            )
            self._node(incident, IncidentNode(
                evidence_id, "evidence", item.source, observed_at, item.to_dict(),
            ))
            if anchor_id:
                self._edge(incident, anchor_id, evidence_id, "supports-risk", observed_at)

            incident.score = max(incident.score, score)
            incident.classification = _classification_for_score(
                incident.score, confirmed=incident.confirmed_threat
            )
            self._queue_update(incident, "generic-evidence")
            updates.append(self.snapshot(incident.id))
        return updates

    def observe_risk(self, context: dict, *, at: float = 0.0) -> list[dict]:
        now = self._now(at)
        self._expire(now)
        path = str(context.get("path") or "")
        normalized = _path(path)
        score = context.get("score", 0)
        score = int(score) if isinstance(score, int) else 0
        confirmed = context.get("confirmed_threat") is True

        incident = self.incidents.get(self.path_index.get(normalized, "")) if normalized else None
        if incident is None and (score >= 40 or confirmed):
            incident = self._new(now)
        if incident is None:
            return []

        file_id = f"file:{normalized}" if normalized else f"file:unknown:{incident.id}"
        self._node(incident, IncidentNode(
            file_id, "file", path or "unknown file", now, {"path": path},
        ))
        if normalized:
            self.path_index[normalized] = incident.id

        verdict_id = f"risk:{incident.id}:{int(now * 1000)}"
        self._node(incident, IncidentNode(
            verdict_id, "risk", str(context.get("classification") or "unknown"),
            now,
            {
                "score": score,
                "classification": context.get("classification"),
                "scanner_verdict": context.get("scanner_verdict"),
                "scanner_complete": context.get("scanner_complete"),
                "confirmed_threat": confirmed,
                "behavior_score": context.get("behavior_score"),
                "behavior_rules": context.get("behavior_rules", []),
                "evidence_score": context.get("evidence_score", 0),
                "evidence_sources": context.get("evidence_sources", []),
                "evidence_rules": context.get("evidence_rules", []),
                "origin": context.get("origin"),
                "native_pre_execution": context.get("native_pre_execution"),
                "automatic_enforcement_eligible":
                    context.get("automatic_enforcement_eligible") is True,
            },
        ))
        self._edge(incident, file_id, verdict_id, "evaluated-as", now)
        incident.score = max(incident.score, min(100, max(0, score)))
        incident.confirmed_threat = incident.confirmed_threat or confirmed
        incident.classification = _classification_for_score(
            incident.score, confirmed=incident.confirmed_threat
        )
        incident.automatic_enforcement_eligible = (
            incident.automatic_enforcement_eligible or
            context.get("automatic_enforcement_eligible") is True
        )
        self._queue_update(incident, "risk-evaluation")
        return [self.snapshot(incident.id)]

    def snapshot(self, incident_id: str) -> dict:
        incident = self.incidents[incident_id]
        return {
            "id": incident.id,
            "started_at": incident.started_at,
            "updated_at": incident.updated_at,
            "score": incident.score,
            "classification": incident.classification,
            "confirmed_threat": incident.confirmed_threat,
            "automatic_enforcement_eligible":
                incident.automatic_enforcement_eligible,
            "node_count": len(incident.nodes),
            "edge_count": len(incident.edges),
            "nodes": [node.to_dict() for node in incident.nodes.values()],
            "edges": [edge.to_dict() for edge in incident.edges],
        }

    def drain_updates(self) -> list[dict]:
        updates = []
        for item in self.pending_updates:
            incident_id = item["incident_id"]
            if incident_id in self.incidents:
                updates.append({
                    "reason": item["reason"],
                    "incident": self.snapshot(incident_id),
                })
        self.pending_updates.clear()
        self._pending_incidents.clear()
        return updates

    def status(self) -> dict:
        now = self.clock()
        self._expire(now)
        latest = self.snapshot(self.latest_id) if self.latest_id in self.incidents else None
        highest = max((item.score for item in self.incidents.values()), default=0)
        if highest >= 90:
            state = "alert"
        elif highest >= 60:
            state = "attention"
        else:
            state = "normal"
        return {
            "state": state,
            "mode": "correlation-graph",
            "active_incidents": len(self.incidents),
            "total_created": self.total_created,
            "highest_score": highest,
            "latest": latest,
            "limits": {
                "ttl_seconds": self.ttl,
                "max_incidents": self.max_incidents,
                "max_nodes_per_incident": self.max_nodes,
                "max_edges_per_incident": self.max_edges,
            },
        }
