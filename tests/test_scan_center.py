import hashlib
import json
import os

import pytest

from antios import antivirus, elevation
from antios.engine_types import ScanOutcome
from test_elevation import shell_mock


class StreamEngine:
    metadata = {"database_freshness": "local"}

    def scan_stream(self, chunks):
        for chunk in chunks:
            assert 0 < len(chunk) <= 65536
        return ScanOutcome()

    def scan(self, data, name):
        return ScanOutcome()

    def close(self):
        pass


def full_scan(path, provider=StreamEngine, **options):
    return antivirus.scan_files(path, max_bytes=None, max_files=None, engine="antios",
                                provider_factory=provider, **options)


def test_gui_profile_scans_above_previous_size_limit_and_keeps_hash(tmp_path):
    path = tmp_path / "large.bin"
    with path.open("wb") as stream:
        stream.truncate(antivirus.DEFAULT_MAX_BYTES + 1)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    signatures = tmp_path / "fixture.json"
    signatures.write_text(json.dumps({"schema": 1, "sha256": {digest: "Inert large fixture"}}))
    result = full_scan(path, signature_path=signatures)
    assert result["summary"]["provider_scanned"] == 1
    assert result["findings"][0]["sha256"] == digest
    assert result["limits"]["max_file_bytes"] is None and result["limits"]["max_files"] is None
    assert result["summary"]["bytes_scanned"] == path.stat().st_size


def test_stream_error_is_local_and_retains_hash_detection(tmp_path, monkeypatch):
    monkeypatch.setattr(antivirus, "DEFAULT_MAX_BYTES", 100)
    class Limited(StreamEngine):
        def scan_stream(self, chunks):
            next(chunks)
            raise OSError("stream limit")
    path = tmp_path / "large"
    data = b"inert" * 30000
    path.write_bytes(data)
    (tmp_path / "small").write_bytes(b"ok")
    result = full_scan(tmp_path, Limited, workers=1)
    assert result["summary"]["files_scanned"] == 2
    assert result["summary"]["provider_scanned"] == 1
    assert result["summary"]["errors"] == 1
    assert result["verdict"] == "incomplete"
    sigs = tmp_path / "sigs.json"
    sigs.write_text(json.dumps({"schema": 1, "sha256": {hashlib.sha256(data).hexdigest(): "test"}}))
    assert full_scan(path, Limited, signature_path=sigs)["verdict"] == "threats-found"


def test_modified_stream_cannot_be_reported_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(antivirus, "DEFAULT_MAX_BYTES", 1)
    path = tmp_path / "moving"
    path.write_bytes(b"initial")
    class Modified(StreamEngine):
        def scan_stream(self, chunks):
            for _ in chunks:
                pass
            with path.open("ab") as stream:
                stream.write(b"changed")
            return ScanOutcome()
    result = full_scan(path, Modified)
    assert result["summary"]["errors"] == 1
    assert result["summary"]["files_scanned"] == 0
    assert result["verdict"] == "incomplete"


def test_stream_cancel_stops_reading(tmp_path, monkeypatch):
    monkeypatch.setattr(antivirus, "DEFAULT_MAX_BYTES", 1)
    path = tmp_path / "cancel"
    path.write_bytes(b"x" * 150000)
    stopped = []
    class Cancel(StreamEngine):
        def scan_stream(self, chunks):
            next(chunks)
            stopped.append(True)
            for _ in chunks:
                pytest.fail("cancelled reader yielded additional data")
    result = full_scan(path, Cancel, cancelled=lambda: bool(stopped))
    assert result["summary"]["cancelled"]
    assert result["coverage"] == "limited"


def test_explicit_uac_uses_only_the_verified_gui_and_fixed_arguments(monkeypatch, tmp_path):
    shell = shell_mock(monkeypatch)
    exe = tmp_path / "AntiOS-GUI.exe"
    names = []
    monkeypatch.setattr(elevation, "_managed_executable", lambda name: names.append(name) or exe)
    elevation.open_admin_scan_center("ru")
    assert names == ["AntiOS-GUI.exe"]
    assert shell.ShellExecuteW.calls == [(None, "runas", str(exe), "--scan-center --lang ru",
                                         str(exe.parent), 1)]
    with pytest.raises(ValueError):
        elevation.open_admin_scan_center("ru --background")
    shell.ShellExecuteW.result = 5
    with pytest.raises(PermissionError):
        elevation.open_admin_scan_center("ru")


@pytest.mark.skipif(os.name != "nt", reason="requires a Windows system image")
def test_windows_allows_trusted_readonly_install_permissions(monkeypatch, tmp_path):
    from pathlib import Path
    from antios.windows_acl import assert_protected_install
    monkeypatch.setenv("PSModulePath", str(tmp_path / "unrelated-host-modules"))
    root = Path(os.environ["SystemRoot"]) / "System32"
    assert_protected_install(root / "whoami.exe", root)
