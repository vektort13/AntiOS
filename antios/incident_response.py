"""Safe response helpers for Incident Viewer.

Response actions operate only on evidence already present in an incident.
Destructive isolation is possible only from a fresh confirmed scanner finding;
behavior/risk scores alone are never sufficient.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ntpath
from pathlib import Path
import re
from typing import Callable, Iterable

from .quarantine import Quarantine
from .scan_process import run_scan_process


MAX_RESPONSE_PATHS = 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def incident_file_paths(incident: dict, *, limit: int = MAX_RESPONSE_PATHS) -> list[str]:
    """Return unique absolute Windows file paths represented by graph nodes."""
    if not isinstance(limit, int) or not 1 <= limit <= MAX_RESPONSE_PATHS:
        raise ValueError(f"incident response path limit must be between 1 and {MAX_RESPONSE_PATHS}")
    if not isinstance(incident, dict):
        return []
    nodes = incident.get("nodes")
    if not isinstance(nodes, list):
        return []

    result: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("kind") not in {"file", "file-change", "process"}:
            continue
        data = node.get("data") if isinstance(node.get("data"), dict) else {}
        value = data.get("path")
        if not isinstance(value, str) or not value.strip() or len(value) > 32767:
            continue
        value = value.strip()
        # Product response targets are Windows paths. Avoid interpreting labels,
        # command lines or relative strings as files.
        if not ntpath.isabs(value):
            continue
        normalized = ntpath.normcase(ntpath.normpath(value))
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(value)
        if len(result) >= limit:
            break
    return result


def scan_incident_files(
    incident: dict,
    *,
    scanner=run_scan_process,
    signature_path: Path | None = None,
    require_verified_peer: bool = False,
    cancelled: Callable[[], bool] = lambda: False,
    progress: Callable[[int, int, str], None] | None = None,
) -> dict:
    """Freshly scan incident-linked paths without changing files."""
    paths = incident_file_paths(incident)
    started_at = utc_now()
    results: list[dict] = []
    errors: list[dict] = []
    total = len(paths)

    for index, value in enumerate(paths, start=1):
        if cancelled():
            return {
                "schema": 1,
                "kind": "incident-response-scan",
                "incident_id": incident.get("id"),
                "started_at": started_at,
                "finished_at": utc_now(),
                "cancelled": True,
                "paths": paths,
                "results": results,
                "errors": errors,
            }
        if progress:
            progress(index, total, value)
        try:
            result = scanner(
                Path(value),
                signature_path=signature_path,
                engine="antios",
                require_verified_peer=require_verified_peer,
                cancelled=cancelled,
            )
            results.append({"path": value, "result": result})
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append({"path": value, "error": str(exc)[:1000]})

    return {
        "schema": 1,
        "kind": "incident-response-scan",
        "incident_id": incident.get("id"),
        "started_at": started_at,
        "finished_at": utc_now(),
        "cancelled": False,
        "paths": paths,
        "results": results,
        "errors": errors,
    }


def confirmed_findings(response_scan: dict | None) -> list[dict]:
    """Extract unique fresh confirmed scanner findings from a response scan."""
    if not isinstance(response_scan, dict):
        return []
    output: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for entry in response_scan.get("results", []):
        if not isinstance(entry, dict):
            continue
        result = entry.get("result")
        if not isinstance(result, dict):
            continue
        for finding in result.get("findings", []):
            if not isinstance(finding, dict) or finding.get("kind") != "threat":
                continue
            path = finding.get("path")
            digest = finding.get("sha256")
            fingerprint = finding.get("fingerprint")
            if (
                not isinstance(path, str)
                or not isinstance(digest, str)
                or re.fullmatch(r"[a-fA-F0-9]{64}", digest) is None
                or not isinstance(fingerprint, (list, tuple))
                or len(fingerprint) != 4
                or not all(isinstance(value, int) for value in fingerprint)
            ):
                continue
            key = (ntpath.normcase(ntpath.normpath(path)), digest.lower())
            if key in seen:
                continue
            seen.add(key)
            output.append(finding)
    return output


def isolate_confirmed_findings(
    response_scan: dict,
    *,
    quarantine_factory=Quarantine,
) -> dict:
    """Isolate only fresh confirmed findings.

    Caller is responsible for obtaining explicit user confirmation immediately
    before invoking this function.
    """
    findings = confirmed_findings(response_scan)
    isolated: list[dict] = []
    errors: list[dict] = []
    if not findings:
        return {
            "schema": 1,
            "kind": "incident-response-isolation",
            "incident_id": response_scan.get("incident_id"),
            "finished_at": utc_now(),
            "attempted": 0,
            "isolated": [],
            "errors": [],
        }
    vault = quarantine_factory()
    for finding in findings:
        try:
            isolated.append(vault.add(finding, dry_run=False))
        except (OSError, ValueError) as exc:
            errors.append({
                "path": finding.get("path"),
                "name": finding.get("name"),
                "error": str(exc)[:1000],
            })
    return {
        "schema": 1,
        "kind": "incident-response-isolation",
        "incident_id": response_scan.get("incident_id"),
        "finished_at": utc_now(),
        "attempted": len(findings),
        "isolated": isolated,
        "errors": errors,
    }


def build_incident_report(
    incident: dict,
    *,
    response_scan: dict | None = None,
    isolation: dict | None = None,
) -> dict:
    """Build a portable local JSON incident report."""
    return {
        "schema": 1,
        "kind": "antios-incident-report",
        "exported_at": utc_now(),
        "incident": incident,
        "response": {
            "scan": response_scan,
            "isolation": isolation,
        },
        "safety": {
            "behavior_only_auto_enforcement": False,
            "isolation_requires_fresh_confirmed_scan_finding": True,
        },
    }
