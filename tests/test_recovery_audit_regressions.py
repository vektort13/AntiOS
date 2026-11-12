import hashlib
import json
import struct
import zipfile

from antios import recovery


def _archive_with_payload(path, *, compression=zipfile.ZIP_STORED):
    content = b"benign audit fixture"
    manifest = {
        "schema": 1,
        "coverage": "selected-files",
        "entries": [{
            "path": str(path.parent / "original.txt"),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }],
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("files/0.bin", content, compress_type=compression)
    return manifest


def test_cli_corrupt_deflate_is_structured_error_not_traceback(tmp_path, capsys):
    path = tmp_path / "damaged.zip"
    _archive_with_payload(path, compression=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(path) as archive:
        offset = archive.getinfo("files/0.bin").header_offset
    raw = bytearray(path.read_bytes())
    name_length, extra_length = struct.unpack_from("<HH", raw, offset + 26)
    raw[offset + 30 + name_length + extra_length] = 7
    path.write_bytes(raw)

    assert recovery.main(["list", str(path)]) == 1
    assert "error" in json.loads(capsys.readouterr().out)


def test_cli_invalid_utf8_path_is_structured_error_not_traceback(tmp_path, capsys):
    path = tmp_path / "surrogate.zip"
    manifest = _archive_with_payload(path)
    manifest["entries"][0]["path"] = "C:/bad/\ud800.txt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("files/0.bin", b"benign audit fixture")

    assert recovery.main(["list", str(path)]) == 1
    assert "error" in json.loads(capsys.readouterr().out)
