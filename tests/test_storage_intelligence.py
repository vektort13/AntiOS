import os
import time
from pathlib import Path

import pytest

from antios.storage_intelligence import (
    StorageJournal, background_permission, candidate_categories, copy_evidence,
    estimate_trend, insights_for_scan, survival_report,
)
from antios.storage_cleanup import scan_storage


def _scan(tmp_path):
    (tmp_path / "a.zip").write_bytes(b"x" * 3000)
    (tmp_path / "b.zip").write_bytes(b"x" * 3000)
    (tmp_path / "alone.iso").write_bytes(b"y" * 4000)
    return scan_storage(tmp_path, duplicate_min_bytes=1, large_bytes=999999)


def test_lastcopy_differentiates_verified_match_and_unknown(tmp_path):
    scan = _scan(tmp_path)
    evidence = copy_evidence(scan)
    assert evidence[str(tmp_path / "a.zip")]["status"] == "verified-other-file-in-scan"
    assert evidence[str(tmp_path / "alone.iso")]["status"] == "no-independent-copy-verified"
    assert survival_report(scan)["needs_verified_external_backup"]


def test_lastcopy_hardlinks_not_independent(tmp_path):
    first = tmp_path / "a.zip"
    first.write_bytes(b"x" * 1024)
    second = tmp_path / "b.zip"
    try:
        os.link(first, second)
    except OSError:
        pytest.skip("Hard links not supported")
    scan = scan_storage(tmp_path, duplicate_min_bytes=1, large_bytes=999999)
    evidence = copy_evidence(scan)
    assert evidence[str(first)]["status"] == "no-independent-copy-verified"


def test_history_uses_one_sample_per_day_and_forecast_needs_data(tmp_path):
    db = tmp_path / "history.db"
    root = tmp_path / "root"
    with StorageJournal(db) as journal:
        for day in range(10):
            journal.capture(root, 1000 + day * 100, 3, now=(20000 + day) * 86400)
        assert len(journal.timeline(root)) == 10
        data = estimate_trend(journal.timeline(root))
        assert data["bytes_per_day"] == 100
        assert data["predicted_bytes_30_days"] == 1000 + 9 * 100 + 30 * 100
        journal.capture(root, 2222, 3, now=(20009) * 86400)
        assert len(journal.timeline(root)) == 10


def test_cleanup_dna_never_infers_dislikes_from_no_action(tmp_path):
    with StorageJournal(tmp_path / "db.sqlite") as journal:
        journal.set_preference("archive", "hide")
        journal.confirmed_cleanup(["duplicate", "duplicate"])
        assert journal.preferences()["archive"]["choice"] == "hide"
        assert journal.preferences()["duplicate"]["confirmed_deletions"] == 2
        assert journal.preferences()["old"]["choice"] == "normal"
        with pytest.raises(ValueError):
            journal.set_preference("unknown", "prefer")


def test_insights_integrate_without_deleting_anything(tmp_path):
    root = tmp_path / "scan"
    root.mkdir()
    scan = _scan(root)
    result = insights_for_scan(scan, journal_path=tmp_path / "journal.db")
    assert result["history"]["forecast"] == "insufficient-history"
    assert result["recommendations"]
    assert (root / "a.zip").exists()
    assert (root / "alone.iso").exists()
    assert candidate_categories(scan)[str(root / "a.zip")]


def test_smartsleep_does_not_claim_idle_on_unsupported_os():
    if os.name != "nt":
        assert not background_permission()["allowed"]


def test_incomplete_scan_does_not_pollute_memorymap(tmp_path):
    scan = _scan(tmp_path)
    scan["limit_reached"] = True
    db = tmp_path / "history.db"
    insight = insights_for_scan(scan, journal_path=db)
    assert insight["history"]["forecast"] == "unavailable"
    assert not db.exists()


def test_history_can_be_disabled_and_cleared_by_owner(tmp_path):
    db = tmp_path / "history.db"
    with StorageJournal(db) as journal:
        assert journal.history_enabled()
        journal.capture(tmp_path, 100, 2, now=20000 * 86400)
        journal.set_history_enabled(False)
        assert not journal.history_enabled()
        journal.clear_history()
        assert not journal.timeline(tmp_path)
        journal.set_history_enabled(True)
        assert journal.history_enabled()


def test_repeated_confirmed_deletions_raise_recommendation_without_auto_delete(tmp_path):
    root = tmp_path / "folder"
    root.mkdir()
    scanned = _scan(root)
    db = tmp_path / "history.sqlite3"
    with StorageJournal(db) as journal:
        journal.confirmed_cleanup(["archive", "archive", "archive"])
    recommendations = insights_for_scan(scanned, journal_path=db)["recommendations"]
    archive = next(row for row in recommendations if row["path"] == str(root / "alone.iso"))
    assert archive["priority"] == "preferred"
    assert archive["priority_reason"] == "repeated-confirmed-cleanups"
    assert (root / "alone.iso").exists()
