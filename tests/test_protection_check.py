import json
import sqlite3

import pytest

from antios import protection_check as checks
from antios.engine_types import ScanOutcome


class Engine:
    metadata = {"database_freshness": "local"}
    closed = False
    def scan(self, content, name):
        return ScanOutcome("threat", "Win.Test.EICAR") if b"EICAR" in content else ScanOutcome()
    def close(self):
        self.closed = True


def guard():
    return {"running": True, "state": "monitoring"}


def test_functional_controls_and_real_backup_roundtrip_leave_no_sample_files(tmp_path, monkeypatch):
    monkeypatch.setattr(checks.tempfile, "tempdir", str(tmp_path))
    engine = Engine()
    result = checks.run_checks(scanner_factory=lambda: engine, guard_reader=guard)
    assert result["status"] == "passed"
    assert len(result["checks"]) == 6
    assert engine.closed
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("outcome", [ScanOutcome(), ScanOutcome("threat", "Everything")])
def test_engine_that_always_allows_or_always_flags_fails(outcome):
    class Broken(Engine):
        def scan(self, content, name):
            return outcome
    result = checks.run_checks(scanner_factory=Broken, guard_reader=guard)
    assert result["status"] == "failed"
    assert any(row["state"] == "failed" for row in result["checks"])


def test_unavailable_engine_does_not_prevent_recovery_check():
    def unavailable():
        raise OSError("unavailable")
    result = checks.run_checks(scanner_factory=unavailable, guard_reader=guard)
    states = {row["id"]: row["state"] for row in result["checks"]}
    assert states["engine"] == "failed"
    assert states["test-detection"] == "skipped"
    assert states["recovery"] == "passed"
    assert result["status"] == "failed"


def test_stale_signatures_and_unreadable_guard_are_visible():
    class Stale(Engine):
        metadata = {"database_freshness": "stale"}
    def denied():
        raise sqlite3.DatabaseError("damaged")
    result = checks.run_checks(scanner_factory=Stale, guard_reader=denied)
    assert result["status"] == "failed"
    assert {row["id"] for row in result["checks"] if row["state"] == "warning"} == {"database", "guard-status"}
    assert next(row for row in result["checks"] if row["id"] == "engine")["state"] == "failed"


def test_cancellation_closes_engine_without_running_later_steps():
    engine = Engine()
    progress = []
    result = checks.run_checks(scanner_factory=lambda: engine, guard_reader=lambda: pytest.fail("guard was read"),
                              cancelled=lambda: len(progress) >= 2, progress=progress.append)
    assert result["status"] == "cancelled"
    assert len(result["checks"]) == 2
    assert engine.closed


def test_recovery_failure_is_not_reported_as_ready(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(checks.recovery, "create", broken)
    result = checks.run_checks(scanner_factory=Engine, guard_reader=guard)
    assert result["status"] == "failed"
    assert result["checks"][-1]["id"] == "recovery"
    assert result["checks"][-1]["state"] == "failed"


def test_cli_returns_structured_result_without_requiring_user_configuration(monkeypatch, capsys):
    from antios import cli
    report = {"kind": "antios-self-check", "status": "attention", "checks": []}
    monkeypatch.setattr(checks, "run_checks", lambda: report)
    monkeypatch.setattr(cli, "load_config", lambda *a: pytest.fail("configuration was read"))
    assert cli.main(["self-check", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == report
