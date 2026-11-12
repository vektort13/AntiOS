import json
import zipfile
import struct

import pytest

from antios import recovery
from antios.cli import main


def test_changes_missing_and_restore_never_overwrites_original(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    one, two = root / "one.txt", root / "two.txt"
    one.write_bytes(b"first")
    two.write_bytes(b"second")
    archive = tmp_path / "backup.zip"
    assert recovery.create([root], archive)["files"] == 2
    assert all(x["state"] == "unchanged" for x in recovery.check(archive)["files"])
    one.write_bytes(b"changed")
    two.unlink()
    assert {x["state"] for x in recovery.check(archive)["files"]} == {"changed", "missing"}
    destination = tmp_path / "recovered"
    recovery.export(archive, destination)
    assert {p.read_bytes() for p in destination.glob("*.bin")} == {b"first", b"second"}
    assert one.read_bytes() == b"changed"
    assert not two.exists()
    with pytest.raises(FileExistsError):
        recovery.export(archive, destination)


def test_extension_preserves_old_baseline_and_adds_new_paths(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    one.write_bytes(b"old")
    two.write_bytes(b"new")
    old, new = tmp_path / "old.zip", tmp_path / "new.zip"
    recovery.create([one], old)
    one.write_bytes(b"modified")
    recovery.create([one, two], new, previous=old)
    assert [x["state"] for x in recovery.check(new)["files"]] == ["changed", "unchanged"]
    recovery.export(new, tmp_path / "export")
    assert (tmp_path / "export/0.bin").read_bytes() == b"old"


def test_exclusive_archive_and_missing_source(tmp_path):
    archive = tmp_path / "backup.zip"
    result = recovery.create([tmp_path / "missing"], archive)
    assert result["coverage"] == "partial"
    before = archive.read_bytes()
    with pytest.raises(FileExistsError):
        recovery.create([], archive)
    assert archive.read_bytes() == before


def test_budget_aborts_nested_traversal_and_removes_incomplete_archive(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    (root / "one").write_bytes(b"12345")
    monkeypatch.setattr(recovery, "MAX_TOTAL", 4)
    archive = tmp_path / "backup.zip"
    with pytest.raises(recovery.RecoveryLimitError):
        recovery.create([root], archive)
    assert not archive.exists()


def test_size_limit_is_reported_as_incomplete(tmp_path, monkeypatch):
    source = tmp_path / "large"
    source.write_bytes(b"12345")
    monkeypatch.setattr(recovery, "MAX_FILE", 4)
    assert recovery.create([source], tmp_path / "backup.zip")["errors"]


def test_corrupted_blob_fails_before_export_directory_creation(tmp_path):
    source = tmp_path / "one"
    source.write_bytes(b"good")
    original, damaged = tmp_path / "old.zip", tmp_path / "bad.zip"
    recovery.create([source], original)
    with zipfile.ZipFile(original) as archive:
        manifest = archive.read("manifest.json")
    with zipfile.ZipFile(damaged, "w") as archive:
        archive.writestr("manifest.json", manifest)
        archive.writestr("files/0.bin", b"evil")
    with pytest.raises(ValueError, match="integrity"):
        recovery.export(damaged, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_manifest_paths_never_control_export_paths(tmp_path):
    source = tmp_path / "one"
    source.write_bytes(b"data")
    archive = tmp_path / "original.zip"
    recovery.create([source], archive)
    with zipfile.ZipFile(archive) as original:
        manifest = json.loads(original.read("manifest.json"))
    manifest["entries"][0]["path"] = "../../escape.exe"
    malicious = tmp_path / "malicious.zip"
    with zipfile.ZipFile(malicious, "w") as output:
        output.writestr("manifest.json", json.dumps(manifest))
        output.writestr("files/0.bin", b"data")
    recovery.export(malicious, tmp_path / "export")
    assert (tmp_path / "export/0.bin").read_bytes() == b"data"
    assert not (tmp_path / "escape.exe").exists()


def test_cli_lifecycle(tmp_path, capsys):
    source, archive = tmp_path / "source", tmp_path / "backup.zip"
    source.write_bytes(b"ok")
    assert main(["recovery", "create", str(archive), str(source)]) == 0
    assert main(["recovery", "check", str(archive)]) == 0
    source.unlink()
    assert main(["recovery", "check", str(archive)]) == 2
    assert main(["recovery", "export", str(archive), str(tmp_path / "export")]) == 0


def test_reparse_source_rejected(tmp_path):
    source = tmp_path / "one"
    source.write_bytes(b"data")
    link = tmp_path / "link"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    result = recovery.create([link], tmp_path / "backup.zip")
    assert result["files"] == 0
    assert result["errors"]


@pytest.mark.parametrize("field,value", [("size", -1), ("size", True), ("sha256", "invalid"), ("path", None)])
def test_invalid_manifest_fields_rejected(tmp_path, field, value):
    source = tmp_path / "source"
    source.write_bytes(b"data")
    original = tmp_path / "original.zip"
    recovery.create([source], original)
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    manifest["entries"][0][field] = value
    damaged = tmp_path / "damaged.zip"
    with zipfile.ZipFile(damaged, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("files/0.bin", b"data")
    with pytest.raises(ValueError):
        recovery.export(damaged, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_extension_retains_incomplete_coverage(tmp_path):
    old = tmp_path / "old.zip"
    recovery.create([tmp_path / "missing"], old)
    source = tmp_path / "source"
    source.write_bytes(b"data")
    result = recovery.create([source], tmp_path / "new.zip", previous=old)
    assert result["coverage"] == "partial"


def test_nested_output_failure_invalidates_whole_archive(tmp_path, monkeypatch):
    root = tmp_path / "folder"
    root.mkdir()
    (root / "one").write_bytes(b"one")
    archive = tmp_path / "backup.zip"
    def fail(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(zipfile.ZipFile, "writestr", fail)
    with pytest.raises(OSError, match="disk full"):
        recovery.create([root], archive)
    assert not archive.exists()


def test_cancel_capture_cleans_up_and_preserves_source(tmp_path):
    source = tmp_path / "one"
    source.write_bytes(b"original")
    state = {"cancel": False}
    def progress(value):
        if value["files"]:
            state["cancel"] = True
    archive = tmp_path / "backup.zip"
    with pytest.raises(recovery.RecoveryCancelled):
        recovery.create([source], archive, cancelled=lambda: state["cancel"], progress=progress)
    assert not archive.exists()
    assert source.read_bytes() == b"original"


def test_cancel_export_cleans_up_only_its_new_directory(tmp_path):
    source = tmp_path / "one"
    source.write_bytes(b"original")
    archive = tmp_path / "backup.zip"
    recovery.create([source], archive)
    checks = []
    def cancelled():
        checks.append(1)
        return len(checks) == 5  # two checks at each checkpoint; cancel before manifest
    destination = tmp_path / "export"
    with pytest.raises(recovery.RecoveryCancelled):
        recovery.export(archive, destination, cancelled=cancelled)
    assert not destination.exists()
    assert archive.exists()
    assert source.read_bytes() == b"original"


def test_overlapping_folders_do_not_duplicate_entries(tmp_path):
    root = tmp_path / "folder"
    root.mkdir()
    source = root / "one"
    source.write_bytes(b"original")
    archive = tmp_path / "backup.zip"
    assert recovery.create([root, root, source], archive)["files"] == 1


def test_bad_zip_returns_cli_error(tmp_path, capsys):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"not a zip")
    assert main(["recovery", "check", str(archive)]) == 1
    assert "error" in json.loads(capsys.readouterr().out)


def test_oversized_central_directory_rejected_before_zip_parser(tmp_path, monkeypatch):
    archive = tmp_path / "oversized.zip"
    archive.write_bytes(struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0,
                                    recovery.MAX_ZIP_DIRECTORY + 1, 0, 0))
    def unexpected(*args, **kwargs):
        raise AssertionError("ZIP parser must not run before metadata limits")
    monkeypatch.setattr(zipfile, "ZipFile", unexpected)
    with pytest.raises(ValueError, match="oversized"):
        recovery.check(archive)


def test_inventory_verifies_saved_content_without_reading_originals(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"original")
    archive = tmp_path / "backup.zip"
    recovery.create([source], archive)
    source.unlink()
    def unexpected(*args, **kwargs):
        raise AssertionError("Inventory must not read original paths")
    monkeypatch.setattr(recovery, "read_regular", unexpected)
    result = recovery.inventory(archive)
    assert result["files"][0]["state"] == "saved"
    assert result["files"][0]["index"] == 0
    assert result["bytes"] == 8
    assert len(result["archive_id"]) == 64


def test_selected_named_recovery_preserves_duplicates_and_keeps_unselected_private(tmp_path):
    paths = []
    for index in range(3):
        folder = tmp_path / str(index)
        folder.mkdir()
        path = folder / "документ.txt"
        path.write_bytes(str(index).encode())
        paths.append(path)
    archive = tmp_path / "backup.zip"
    recovery.create(paths, archive)
    listed = recovery.inventory(archive)
    destination = tmp_path / "export"
    result = recovery.export(archive, destination, named=True, indices=[2, 0], expected_id=listed["archive_id"])
    assert result["files"] == 2
    assert (destination / "00000/документ.txt").read_bytes() == b"0"
    assert (destination / "00002/документ.txt").read_bytes() == b"2"
    assert not (destination / "00001").exists()
    assert not (destination / "manifest.json").exists()
    report = json.loads((destination / "recovery-report.json").read_text(encoding="utf-8"))
    assert [entry["index"] for entry in report["files"]] == [0, 2]
    assert str(paths[1]) not in {entry["original_path"] for entry in report["files"]}
    assert [path.read_bytes() for path in paths] == [b"0", b"1", b"2"]


@pytest.mark.parametrize("indices", [[], [-1], [1], [0, 0], [True], ["0"]])
def test_invalid_selection_never_creates_destination(tmp_path, indices):
    source = tmp_path / "source"
    source.write_bytes(b"data")
    archive = tmp_path / "backup.zip"
    recovery.create([source], archive)
    destination = tmp_path / "export"
    with pytest.raises(ValueError, match="indices"):
        recovery.export(archive, destination, indices=indices)
    assert not destination.exists()


def test_changed_archive_rejected_before_any_destination_write(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"original")
    old, new = tmp_path / "old.zip", tmp_path / "new.zip"
    recovery.create([source], old)
    identity = recovery.inventory(old)["archive_id"]
    source.write_bytes(b"replacement")
    recovery.create([source], new)
    with pytest.raises(ValueError, match="changed"):
        recovery.export(new, tmp_path / "export", indices=[0], expected_id=identity)
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("name,expected", [
    (r"C:\folder\CON.txt", "recovered.bin"),
    (r"C:\folder\CON .txt", "recovered.bin"),
    (r"C:\folder\LPT¹.txt", "recovered.bin"),
    ("../../escape.txt", "escape.txt"),
    (r"C:\folder\a.txt:payload", "a.txt_payload"),
    ("safe\u202etxt.exe", "safetxt.exe"),
    ("..", "recovered.bin"),
    ("a" * 181, "recovered.bin"),
])
def test_named_export_sanitizes_untrusted_basename(tmp_path, name, expected):
    source = tmp_path / "source"
    source.write_bytes(b"data")
    original = tmp_path / "original.zip"
    recovery.create([source], original)
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    manifest["entries"][0]["path"] = name
    archive = tmp_path / "untrusted.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("manifest.json", json.dumps(manifest))
        output.writestr("files/0.bin", b"data")
    recovery.export(archive, tmp_path / "export", named=True)
    assert (tmp_path / "export/00000" / expected).read_bytes() == b"data"
    assert not (tmp_path / "escape.txt").exists()


def test_cancel_named_export_removes_created_subdirectories(tmp_path):
    source = tmp_path / "source.txt"
    source.write_bytes(b"original")
    archive = tmp_path / "backup.zip"
    recovery.create([source], archive)
    checks = []
    def cancelled():
        checks.append(1)
        return len(checks) == 5
    with pytest.raises(recovery.RecoveryCancelled):
        recovery.export(archive, tmp_path / "export", named=True, cancelled=cancelled)
    assert not (tmp_path / "export").exists()
    assert source.read_bytes() == b"original"


def test_cli_lists_and_recovers_selected_named_entry(tmp_path, capsys):
    source = tmp_path / "source.txt"
    source.write_bytes(b"data")
    archive = tmp_path / "backup.zip"
    recovery.create([source], archive)
    assert main(["recovery", "list", str(archive)]) == 0
    assert json.loads(capsys.readouterr().out)["files"][0]["index"] == 0
    destination = tmp_path / "export"
    assert main(["recovery", "export", str(archive), str(destination), "--entry", "0", "--named"]) == 0
    assert (destination / "00000/source.txt").read_bytes() == b"data"


def test_zip64_locator_rejected_before_parser(tmp_path, monkeypatch):
    archive = tmp_path / "zip64.zip"
    archive.write_bytes(b"PK\x06\x07" + bytes(16) +
                       struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, 0, 0, 0))
    def unexpected(*args, **kwargs):
        raise AssertionError("ZIP64 should be refused before parsing")
    monkeypatch.setattr(zipfile, "ZipFile", unexpected)
    with pytest.raises(ValueError, match="Unsupported"):
        recovery.inventory(archive)


def test_named_export_write_failure_cleans_files_and_directories(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    source.write_bytes(b"original")
    archive = tmp_path / "backup.zip"
    recovery.create([source], archive)
    def fail(*args):
        raise OSError("disk full")
    monkeypatch.setattr(recovery.os, "fsync", fail)
    with pytest.raises(OSError, match="disk full"):
        recovery.export(archive, tmp_path / "export", named=True)
    assert not (tmp_path / "export").exists()
    assert source.read_bytes() == b"original"
