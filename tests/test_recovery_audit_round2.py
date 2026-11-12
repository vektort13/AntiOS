import hashlib
import json
import zipfile

import pytest

from antios import recovery


def _write_archive(path, entries, payloads):
    manifest = {
        "schema": 1,
        "coverage": "selected-files",
        "entries": [
            {
                "path": original,
                "size": len(payload),
                "sha256": hashlib.sha256(expected).hexdigest(),
            }
            for original, payload, expected in entries
        ],
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for index, payload in enumerate(payloads):
            archive.writestr(f"files/{index}.bin", payload)
    return manifest


@pytest.mark.parametrize("original", [
    r"\\server\share\document.txt",
    r"\\.\PIPE\antios-audit",
    "relative/document.txt",
])
def test_check_rejects_nonlocal_manifest_paths_before_file_access(tmp_path, monkeypatch, original):
    payload = b"saved"
    archive = tmp_path / "untrusted.zip"
    _write_archive(archive, [(original, payload, payload)], [payload])
    touched = []
    monkeypatch.setattr(recovery, "read_regular", lambda *a, **k: touched.append(a) or (b"", None))
    with pytest.raises(ValueError, match="local"):
        recovery.check(archive)
    assert touched == []


def test_check_verifies_all_saved_blobs_before_reading_any_original(tmp_path, monkeypatch):
    one = tmp_path / "one.txt"
    two = tmp_path / "two.txt"
    good = b"good"
    expected_second = b"expected"
    damaged_second = b"damaged!"
    archive = tmp_path / "damaged.zip"
    _write_archive(
        archive,
        [(str(one), good, good), (str(two), damaged_second, expected_second)],
        [good, damaged_second],
    )
    touched = []
    monkeypatch.setattr(recovery, "read_regular", lambda *a, **k: touched.append(a) or (b"", None))
    with pytest.raises(ValueError, match="integrity"):
        recovery.check(archive)
    assert touched == []


def test_extend_rejects_previous_archive_replaced_after_listing(tmp_path):
    original_file = tmp_path / "original.txt"
    replacement_file = tmp_path / "replacement.txt"
    added = tmp_path / "added.txt"
    original_file.write_bytes(b"original")
    replacement_file.write_bytes(b"replacement")
    added.write_bytes(b"added")

    previous = tmp_path / "baseline.zip"
    replacement = tmp_path / "replacement.zip"
    destination = tmp_path / "extended.zip"
    recovery.create([original_file], previous)
    expected_id = recovery.inventory(previous)["archive_id"]
    recovery.create([replacement_file], replacement)
    replacement.replace(previous)

    with pytest.raises(ValueError, match="changed since"):
        recovery.create(
            [added], destination, previous=previous, expected_previous_id=expected_id
        )
    assert not destination.exists()


def test_extend_accepts_matching_previous_archive_id(tmp_path):
    original_file = tmp_path / "original.txt"
    added = tmp_path / "added.txt"
    original_file.write_bytes(b"original")
    added.write_bytes(b"added")
    previous = tmp_path / "baseline.zip"
    destination = tmp_path / "extended.zip"
    recovery.create([original_file], previous)
    expected_id = recovery.inventory(previous)["archive_id"]
    result = recovery.create(
        [added], destination, previous=previous, expected_previous_id=expected_id
    )
    assert result["files"] == 2
    assert recovery.inventory(destination)["files"][0]["path"] == str(original_file)
