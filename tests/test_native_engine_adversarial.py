"""Adversarial fixtures for the independent, read-only AntiOS Engine.

All payloads are inert test bytes; no malware or external services required.
"""
import bz2
import gzip
import hashlib
import io
import lzma
import struct
import tarfile
import zipfile

import pytest

from antios import engine
from antios.engine import AntiOSEngine
from antios.engine_types import ScanOutcome


def zipped(entries, *, compression=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, mode="w", compression=compression) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return out.getvalue()


def test_signature_is_confirmed_even_when_wrapped_in_archive():
    payload = b"inert nested signature fixture"
    signature = hashlib.sha256(payload).hexdigest()
    scanner = AntiOSEngine(signatures={signature: "Inert test rule"})
    result = scanner.scan(zipped({"folder/inner.bin": payload}), "outer.zip")
    assert result.kind == "threat"
    assert result.name == "Inert test rule"
    assert result.engine == scanner.name


def test_bad_zip_returns_review_and_incomplete():
    result = AntiOSEngine().scan(b"PK\x03\x04invalid zip data", "archive.zip")
    assert result.kind == "review"
    assert not result.complete


def test_zip_member_failure_does_not_prevent_scanning_other_members(monkeypatch):
    payload = b"inert known sibling"
    scanner = AntiOSEngine(signatures={hashlib.sha256(payload).hexdigest(): "Inert rule"})
    original_open = zipfile.ZipFile.open

    def open_member(archive, member, *args, **kwargs):
        if isinstance(member, zipfile.ZipInfo) and member.filename == "broken":
            raise zipfile.BadZipFile("Unreadable fixture")
        return original_open(archive, member, *args, **kwargs)

    archive = zipped({"broken": b"inert", "sibling": payload})
    monkeypatch.setattr(zipfile.ZipFile, "open", open_member)
    result = scanner.scan(archive, "test.zip")
    assert result.kind == "threat"
    assert result.name == "Inert rule"
    assert not result.complete


def test_zip_entry_count_budget_precedes_decompression(monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARCHIVE_MEMBERS", 2)
    data = zipped({"a.txt": b"one", "b.txt": b"two", "c.txt": b"three"})
    outcome = AntiOSEngine().scan(data, "three-files.zip")
    assert outcome.kind == "review"
    assert not outcome.complete


def test_zip_and_gzip_share_the_same_budget(monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARCHIVE_MEMBERS", 1)
    archive = zipped({"nested.gz": gzip.compress(b"inert", mtime=0)})
    result = AntiOSEngine().scan(archive, "outer.zip")
    assert result.kind == "review"
    assert not result.complete


def test_gzip_recognized_without_extension_and_hashes_decompressed_content():
    payload = b"inert gzip content"
    scanner = AntiOSEngine(signatures={hashlib.sha256(payload).hexdigest(): "Inert rule"})
    content = gzip.compress(payload, mtime=0)
    assert scanner.scan(content, "download").kind == "threat"
    assert AntiOSEngine().scan(content, "download") == ScanOutcome()


def test_gzip_damaged_or_incompletely_inspected_is_not_clean():
    content = gzip.compress(b"inert gzip content", mtime=0)
    for sample in (content[:-2], content + content, gzip.compress(b"x" * 100_000, mtime=0)):
        result = AntiOSEngine().scan(sample, "test.gz")
        assert result.kind == "review"
        assert not result.complete


def test_tar_and_tar_gzip_find_an_inert_member_without_extracting(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = b"inert tar content"
    scanner = AntiOSEngine(signatures={hashlib.sha256(payload).hexdigest(): "Inert rule"})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        member = tarfile.TarInfo("member.bin")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    content = buffer.getvalue()
    assert scanner.scan(content, "download").kind == "threat"
    assert scanner.scan(gzip.compress(content, mtime=0), "download.tgz").kind == "threat"
    assert AntiOSEngine().scan(content, "download") == ScanOutcome()
    assert not list(tmp_path.iterdir())


def test_empty_tar_gzip_with_standard_padding_is_clean():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w"):
        pass
    content = gzip.compress(buffer.getvalue(), mtime=0)
    assert AntiOSEngine().scan(content, "empty.tar.gz") == ScanOutcome()


def test_tar_requires_a_complete_header_and_payload():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("file.bin")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"test"))
    result = AntiOSEngine().scan(buffer.getvalue()[:514], "test.tar")
    assert result.kind == "review"
    assert not result.complete


def test_unsupported_archive_and_zip_method_are_reported_incomplete():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_LZMA) as archive:
        archive.writestr("benign.txt", b"inert")
    for sample, name in ((b"inert", "example.rar"), (buffer.getvalue(), "example.zip")):
        result = AntiOSEngine().scan(sample, name)
        assert result.kind == "review"
        assert not result.complete


def test_zip_traversal_path_review_never_writes_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    package = zipped({"../../outside.txt": b"inert"})
    result = AntiOSEngine().scan(package, "attempt.zip")
    assert result.kind == "review"
    assert not (tmp_path / "outside.txt").exists()


def test_zip_decompression_ratio_limit_is_incomplete():
    data = zipped({"filler.txt": b"x" * 100_000})
    result = AntiOSEngine().scan(data, "large-ratio.zip")
    assert result.kind == "review"
    assert not result.complete


def test_nested_zip_depth_budget_is_conservative(monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARCHIVE_DEPTH", 2)
    data = zipped({"nested.zip": zipped({"deep.zip": zipped({"x": b"plain"})})})
    result = AntiOSEngine().scan(data, "outer.zip")
    assert result.kind == "review"
    assert not result.complete


def test_nested_zip_uses_expanded_default_budget():
    payload = b"inert nested fixture"
    scanner = AntiOSEngine(signatures={hashlib.sha256(payload).hexdigest(): "Inert rule"})
    data = zipped({"level2.zip": zipped({"level3.zip": zipped({"inner.bin": payload})})})
    assert scanner.scan(data, "test.zip").kind == "threat"


@pytest.mark.parametrize("compress,extension", [(bz2.compress, ".bz2"), (lzma.compress, ".xz")])
def test_standalone_bzip2_and_xz_check_members(compress, extension):
    payload = b"inert compressed fixture"
    scanner = AntiOSEngine(signatures={hashlib.sha256(payload).hexdigest(): "Inert rule"})
    compressed = compress(payload)
    assert scanner.scan(compressed, "test" + extension).kind == "threat"
    assert not scanner.scan(compressed[:-3], "test" + extension).complete


def test_zip_bzip2_inspects_crc_valid_member():
    payload = b"inert bzip2 zip fixture"
    scanner = AntiOSEngine(signatures={hashlib.sha256(payload).hexdigest(): "Inert rule"})
    data = zipped({"inner.bin": payload}, compression=zipfile.ZIP_BZIP2)
    assert scanner.scan(data, "test.zip") == ScanOutcome("threat", "Inert rule")


def test_macro_member_is_advisory():
    data = zipped({"word/vbaProject.bin": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"inert"})
    result = AntiOSEngine().scan(data, "test.docm")
    assert result.kind == "review"
    assert "VBA" in result.name


def test_elf_identification_and_header_size():
    content = bytearray(64)
    content[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", content, 52, len(content))
    assert AntiOSEngine().scan(bytes(content), "inert.elf") == ScanOutcome()
    result = AntiOSEngine().scan(bytes(content[:-1]), "inert.elf")
    assert result.kind == "review" and not result.complete


@pytest.mark.parametrize("sample,filename", [
    (b"invoke-expression downloadstring('inert')", "example.ps1"),
    (b"frombase64string('a')\nset-mppreference -disable", "example.ps1"),
    (b"iex('inert')\ndownloadfile('inert')", "example.ps1"),
])
def test_script_multi_signal_is_advisory_not_threat(sample, filename):
    result = AntiOSEngine().scan(sample, filename)
    assert result.kind == "review"
    assert result.engine == "AntiOS Engine"
    assert result.complete


def test_single_script_signal_is_not_a_confirmed_threat():
    result = AntiOSEngine().scan(b"invoke-expression 'fixture'", "sample.ps1")
    assert result.kind is None


def test_truncated_pe_is_incomplete_review():
    result = AntiOSEngine().scan(b"MZ" + b"\x00" * 20, "sample.exe")
    assert result.kind == "review"
    assert not result.complete


def test_non_archive_without_signature_has_no_detections():
    result = AntiOSEngine().scan(b"benign fixture", "example.txt")
    assert result.kind is None
    assert result.complete


def test_large_stream_is_not_misreported_as_fully_scanned():
    scanner = AntiOSEngine()
    payload = b"a" * (engine.STREAM_PREVIEW_BYTES + 1)
    outcome = scanner.scan_stream_named(iter((payload,)), "sample.bin")
    assert not outcome.complete
    assert outcome.kind is None


def test_stream_matches_full_hash_across_chunks_beyond_preview():
    chunks = (b"x" * engine.STREAM_PREVIEW_BYTES, b"inert tail")
    digest = hashlib.sha256(b"".join(chunks)).hexdigest()
    scanner = AntiOSEngine(signatures={digest: "Inert stream rule"})
    assert scanner.scan_stream(iter(chunks)) == ScanOutcome("threat", "Inert stream rule")


def test_engine_does_not_require_network_or_external_providers(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("network call")))
    assert AntiOSEngine().scan(b"inert content", "fixture").complete
