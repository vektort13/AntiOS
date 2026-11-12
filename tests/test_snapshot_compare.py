import zipfile

import pytest

from antios import recovery


def test_compare_snapshots_tracks_new_removed_changed_and_recoverable_bytes(tmp_path):
    folder = tmp_path / "documents"
    folder.mkdir()
    for name in ("stable", "changed", "removed"):
        (folder / name).write_bytes(b"original")
    before, after = tmp_path / "before.zip", tmp_path / "after.zip"
    recovery.create([folder], before)
    (folder / "changed").write_bytes(b"new")
    (folder / "removed").unlink()
    (folder / "added").write_bytes(b"added")
    recovery.create([folder], after)
    result = recovery.compare(before, after)
    assert result["counts"] == {"added": 1, "removed": 1, "changed": 1, "unchanged": 1}
    selected = [item["index"] for item in result["files"] if item["state"] in {"changed", "removed"}]
    exported = tmp_path / "restored"
    recovery.export(before, exported, indices=selected, expected_id=result["archive_id"], named=True)
    copies = [path for path in exported.glob("*/*") if path.is_file()]
    assert {path.name for path in copies} == {"changed", "removed"}
    assert all(path.read_bytes() == b"original" for path in copies)
    assert (folder / "changed").read_bytes() == b"new"


def test_compare_never_reads_original_paths(tmp_path, monkeypatch):
    source = tmp_path / "file"
    source.write_bytes(b"content")
    before = tmp_path / "before.zip"
    recovery.create([source], before)
    source.unlink()
    monkeypatch.setattr(recovery, "read_regular", lambda *a, **kw: pytest.fail("Original path read"))
    assert recovery.compare(before, before)["counts"]["unchanged"] == 1


def test_compare_rejects_corrupt_saved_content(tmp_path):
    source = tmp_path / "file"
    source.write_bytes(b"saved")
    good, broken = tmp_path / "good.zip", tmp_path / "broken.zip"
    recovery.create([source], good)
    with zipfile.ZipFile(good) as old, zipfile.ZipFile(broken, "w") as new:
        for entry in old.namelist():
            new.writestr(entry, b"wrong" if entry == "files/0.bin" else old.read(entry))
    with pytest.raises(ValueError, match="integrity"):
        recovery.compare(good, broken)


def test_compare_honors_cancellation(tmp_path):
    with pytest.raises(recovery.RecoveryCancelled):
        # A real valid archive is required before inventory can checkpoint.
        source = tmp_path / "file"
        source.write_bytes(b"saved")
        archive = tmp_path / "backup.zip"
        recovery.create([source], archive)
        recovery.compare(archive, archive, cancelled=lambda: True)
