"""Versioned scan decisions and replay over recorded evidence."""
from __future__ import annotations

from collections.abc import Iterable
import hashlib
import json


_POLICY = "antios-scan-verdict-v1"
MAX_REPLAY_BYTES = 64 * 1024 * 1024


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _ledger_digest(rows: Iterable[dict]) -> str:
    return _digest(sorted(_digest(row) for row in rows))


def _coverage_v1(summary: dict, engine: dict, file_gaps: dict) -> dict:
    without_engine = summary["files_scanned"] - summary.get("provider_scanned", 0)
    partial = engine.get("limited_results", 0)
    conditions = (
        (not engine.get("available"), "engine-unavailable"),
        (engine.get("available") and engine.get("database_freshness") != "local", "local-coverage-unverified"),
        (not summary["files_scanned"], "no-files-scanned"),
        (without_engine, "missing-engine-results"),
        (partial, "partial-file-inspection"),
        (summary.get("skipped"), "entries-skipped"),
        (summary.get("errors"), "scan-errors"),
        (summary.get("limit_reached"), "scan-scope-limit"),
        (summary.get("cancelled"), "scan-cancelled"),
        (summary.get("timed_out"), "scan-timed-out"),
    )
    reasons = [reason for condition, reason in conditions if condition]
    return {"status": "limited" if reasons else "complete", "reasons": reasons,
            "file_gaps": dict(file_gaps), "files_with_partial_inspection": partial,
            "files_without_engine_result": without_engine}


def _evidence_v1(report: dict) -> dict:
    summary = report["summary"]
    engine = report.get("engine", {})
    findings = report["findings"]
    issues = report["issues"]
    if not isinstance(findings, list) or not isinstance(issues, list):
        raise ValueError("Invalid scan evidence ledgers")
    threats = sum(item["kind"] == "threat" for item in findings)
    reviews = [item for item in findings if item["kind"] == "review"]
    if (type(summary["threats"]) is not int or type(summary["reviews"]) is not int
            or threats != summary["threats"] or len(reviews) != summary["reviews"]
            or threats + len(reviews) != len(findings)):
        raise ValueError("Scan findings disagree with recorded counts")
    advisories = sum(bool(item.get("rule_id") or not item.get("coverage_gaps")) for item in reviews)
    return {
        "scope": {"path": report.get("path"), "limits": report.get("limits", {})},
        "engine": {key: engine[key] for key in (
            "provider", "version", "signature_source", "signature_catalog_version", "signatures_sha256",
        ) if key in engine},
        "counts": {key: summary.get(key, 0) for key in (
            "files_scanned", "provider_scanned", "threats", "reviews", "skipped", "errors",
        )},
        "advisory_findings": advisories,
        "coverage": _coverage_v1(summary, engine, report.get("coverage_contract", {}).get("file_gaps", {})),
        # The dashboard adds this annotation only after a separate user action.
        "findings_sha256": _ledger_digest({k: v for k, v in item.items() if k != "quarantined"} for item in findings),
        "issues_sha256": _ledger_digest(issues),
    }


def _decision_v1(evidence: dict) -> dict:
    coverage = evidence["coverage"]["status"]
    if evidence["counts"]["threats"]:
        verdict = "threats-found"
        maliciousness, certainty, severity = "confirmed-signature", "confirmed-detection", "high-priority"
        remediation = "requires-file-revalidation"
    elif evidence["advisory_findings"]:
        verdict = "review"
        maliciousness, certainty, severity = "suspicious", "advisory", "review-priority"
        remediation = "insufficient-evidence"
    elif coverage == "limited":
        verdict = "review" if evidence["counts"]["reviews"] else "incomplete"
        maliciousness, certainty, severity = "undetermined", "limited", "unrated"
        remediation = "insufficient-evidence"
    else:
        verdict = "no-threats-found"
        maliciousness, certainty, severity = "no-indicators", "within-inspection-scope", "none-observed"
        remediation = "not-applicable"
    return {"verdict": verdict, "dimensions": {
        "maliciousness": maliciousness, "certainty": certainty, "coverage": coverage,
        "severity": severity, "remediation_confidence": remediation,
    }}


def _derive_v1(report: dict) -> tuple[dict, dict]:
    evidence = _evidence_v1(report)
    decision = _decision_v1(evidence)
    receipt = {"schema": 1, "policy": _POLICY, "evidence": evidence}
    return decision, dict(receipt, sha256=_digest({**receipt, "decision": decision}))


def apply_scan_verdict(report: dict) -> None:
    decision, receipt = _derive_v1(report)
    contract = receipt["evidence"]["coverage"]
    report.update(verdict=decision["verdict"], decision=decision, proof_receipt=receipt,
                  coverage_contract=contract,
                  coverage="limited" if contract["status"] == "limited" else "antios-local-inspection")


def replay_scan_report(report: dict) -> dict:
    """Recompute the decision without reading any file named in the report."""
    if (not isinstance(report, dict) or type(report.get("schema")) is not int
            or report["schema"] != 1 or report.get("kind") != "antivirus-scan"):
        raise ValueError("Expected an AntiOS antivirus scan report")
    receipt = report.get("proof_receipt")
    if not isinstance(receipt, dict) or receipt.get("policy") != _POLICY:
        raise ValueError("The scan report has no supported proof receipt")
    try:
        decision, expected = _derive_v1(report)
        contract = expected["evidence"]["coverage"]
        legacy_coverage = "limited" if contract["status"] == "limited" else "antios-local-inspection"
        comparisons = (
            (receipt, expected), (report.get("decision"), decision),
            (report.get("coverage_contract"), contract), (report.get("coverage"), legacy_coverage),
            (report.get("verdict"), decision["verdict"]),
        )
        matches = all(_canonical(saved) == _canonical(recomputed) for saved, recomputed in comparisons)
    except (KeyError, AttributeError, TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Invalid scan report evidence") from exc
    if not matches:
        raise ValueError("Scan report does not match its proof receipt")
    return {"kind": "antivirus-scan-replay", "verified": True, "policy": _POLICY,
            "receipt_sha256": expected["sha256"], **decision}


def replay_scan_json(data: bytes) -> dict:
    def unique_fields(pairs):
        fields = {}
        for key, value in pairs:
            if key in fields:
                raise ValueError("Duplicate scan report field")
            fields[key] = value
        return fields

    try:
        report = json.loads(data, object_pairs_hook=unique_fields)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid scan report JSON") from exc
    return replay_scan_report(report)
