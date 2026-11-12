import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

import pytest

from antios import antivirus
from antios.engine_types import ScanOutcome


class Provider:
    metadata = {"version": "AntiOS test", "database_freshness": "local"}

    def __init__(self, value=None, failure=False):
        self.value = value or ScanOutcome()
        self.failure, self.closed = failure, False

    def scan(self, content, name):
        if self.failure:
            raise OSError("provider unavailable")
        return self.value

    def close(self):
        self.closed = True


def unavailable():
    raise OSError("native engine unavailable")


def test_native_provider_no_detection_and_scan_is_read_only(tmp_path):
    target = tmp_path / "safe.txt"
    target.write_bytes(b"harmless test content")
    before = target.read_bytes(), target.stat().st_mtime_ns
    provider = Provider()
    result = antivirus.scan_files(target, provider_factory=lambda: provider)
    assert result["verdict"] == "no-threats-found"
    assert result["coverage"] == "antios-local-inspection"
    assert provider.closed
    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


def test_missing_provider_never_claims_a_clean_scan(tmp_path):
    (tmp_path / "a").write_text("ordinary file")
    result = antivirus.scan_files(tmp_path, provider_factory=unavailable)
    assert result["verdict"] == "incomplete"
    assert result["coverage"] == "limited"
    assert result["summary"]["files_scanned"] == 1
    assert result["engine"]["detail"] == "native engine unavailable"


@pytest.mark.parametrize("value,kind,verdict", [
    (ScanOutcome(), None, "no-threats-found"),
    (ScanOutcome("review", "Inert heuristic", "AntiOS Engine"), "review", "review"),
    (ScanOutcome("threat", "Inert signature", "AntiOS Engine"), "threat", "threats-found"),
])
def test_native_detection_results_are_distinct(tmp_path, value, kind, verdict):
    target = tmp_path / "fixture.txt"
    target.write_bytes(b"benign mocked provider fixture")
    result = antivirus.scan_files(target, provider_factory=lambda: Provider(value))
    assert result["verdict"] == verdict
    assert [f["kind"] for f in result["findings"]] == ([] if kind is None else [kind])


def test_family_rule_review_can_have_complete_coverage(tmp_path):
    target = tmp_path / "macro-fixture.docm"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1inert fixture")

    result = antivirus.scan_files(target)

    assert result["verdict"] == "review"
    assert result["coverage"] == "antios-local-inspection"
    assert result["engine"]["limited_results"] == 0
    assert result["coverage_contract"]["status"] == "complete"
    assert result["findings"][0]["rule_id"] == "office.vba-macros"
    assert result["findings"][0]["rule_family"] == "office"


def test_nested_archive_preserves_rule_and_counts_each_gap_once(tmp_path):
    target = tmp_path / "mixed.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("first.7z", b"inert fixture")
        archive.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1inert fixture")
        archive.writestr("second.7z", b"inert fixture")
        archive.writestr("malformed.zip", b"inert fixture")

    result = antivirus.scan_files(target)

    assert result["verdict"] == "review"
    assert result["coverage"] == "limited"
    assert result["findings"][0]["rule_id"] == "office.vba-macros"
    assert result["findings"][0]["coverage_gaps"] == [
        "archive-directory-unavailable", "unsupported-archive-format",
    ]
    assert result["coverage_contract"]["files_with_partial_inspection"] == 1
    assert result["coverage_contract"]["file_gaps"] == {
        "archive-directory-unavailable": 1, "unsupported-archive-format": 1,
    }


def test_stream_preview_is_partial_even_without_a_review(tmp_path, monkeypatch):
    target = tmp_path / "large.txt"
    target.write_bytes(b"harmless test content")
    monkeypatch.setattr(antivirus, "DEFAULT_MAX_BYTES", 8)
    monkeypatch.setattr("antios.engine.STREAM_PREVIEW_BYTES", 8)

    result = antivirus.scan_files(target)

    assert result["verdict"] == "incomplete"
    assert result["coverage_contract"]["file_gaps"] == {"stream-preview-only": 1}
    assert result["issues"][0]["coverage_gaps"] == ["stream-preview-only"]


def test_scan_profiles_can_reach_different_archive_depths(tmp_path):
    payload = b"inert nested signature fixture"
    digest = hashlib.sha256(payload).hexdigest()
    signatures = tmp_path / "signatures.json"
    signatures.write_text(json.dumps({"schema": 1, "sha256": {digest: "Inert test hash"}}))
    for level in range(5):
        container = io.BytesIO()
        with zipfile.ZipFile(container, "w") as archive:
            archive.writestr("inner.zip" if level else "fixture.txt", payload)
        payload = container.getvalue()
    target = tmp_path / "nested.zip"
    target.write_bytes(payload)

    for profile, workers in (("light", 2), ("balanced", 4), ("heavy", 8)):
        result = antivirus.scan_files(target, signature_path=signatures, profile=profile)
        assert result["limits"]["profile"] == profile
        assert result["limits"]["workers"] == workers
        assert result["limits"]["effective_workers"] == 1
        if profile == "heavy":
            assert result["verdict"] == "threats-found"
        else:
            assert result["verdict"] == "review"
            assert result["coverage_contract"]["file_gaps"] == {"archive-depth-limit": 1}


def test_light_scan_checks_whole_file_hash_above_inline_limit(tmp_path):
    target = tmp_path / "large.bin"
    block = bytes(1024 * 1024)
    digest = hashlib.sha256()
    with target.open("wb") as stream:
        for _ in range(16):
            stream.write(block)
            digest.update(block)
        stream.write(b"end of inert fixture")
        digest.update(b"end of inert fixture")
    signatures = tmp_path / "signatures.json"
    signatures.write_text(json.dumps({"schema": 1, "sha256": {digest.hexdigest(): "Inert large file"}}))

    result = antivirus.scan_files(target, signature_path=signatures, profile="light")

    assert result["summary"]["bytes_scanned"] == target.stat().st_size
    assert result["verdict"] == "threats-found"
    assert result["findings"][0]["sha256"] == digest.hexdigest()


def test_scan_workers_can_exceed_eight_and_respect_cpu_count(tmp_path, monkeypatch):
    (tmp_path / "fixture.txt").write_bytes(b"inert fixture")
    monkeypatch.setattr(antivirus.os, "cpu_count", lambda: 12)
    result = antivirus.scan_files(tmp_path, profile="heavy", workers=16)
    assert result["limits"]["workers"] == 16
    assert result["limits"]["effective_workers"] == 12


def test_local_hash_detection_and_finding_digest(tmp_path):
    content = b"benign local signature test"
    target = tmp_path / "sample"
    target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({"schema": 1, "sha256": {digest.upper(): "Test signature"}}))
    result = antivirus.scan_files(target, signature_path=database, provider_factory=unavailable)
    finding = result["findings"][0]
    assert finding["sha256"] == digest
    assert finding["engine"] == "SHA-256"
    assert finding["name"] == "Test signature"
    assert result["verdict"] == "threats-found"


def test_eicar_whitespace_matching_uses_hash_without_writing_eicar(tmp_path, monkeypatch):
    # Use inert bytes: hosted Windows antivirus must never be disabled for tests.
    sample = b"x" * 68
    monkeypatch.setattr(antivirus, "EICAR_SHA256", hashlib.sha256(sample).hexdigest())
    target = tmp_path / "inert-eicar-surrogate"
    target.write_bytes(sample + b"\r\n \t")
    result = antivirus.scan_files(target, provider_factory=unavailable)
    assert result["summary"]["threats"] == 1
    target.write_bytes(sample + b"x")
    assert not antivirus.scan_files(target, provider_factory=unavailable)["findings"]


@pytest.mark.parametrize("data", [[], {"schema": 2}, {"schema": True, "sha256": {}},
    {"schema": 1, "sha256": []},
    {"schema": 1, "sha256": {"not-a-hash": "name"}},
    {"schema": 1, "sha256": {"a" * 64: ""}},
    {"schema": 1, "sha256": {"a" * 64: 123}}, {"schema": 1, "sha256": {"a" * 64: "\ud800"}},
    {"schema": 1, "sha256": {"a" * 64: "First", "A" * 64: "Second"}}])
def test_signature_input_is_validated(tmp_path, data):
    database = tmp_path / "bad.json"
    database.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        antivirus.load_signatures(database)


def test_signature_database_rejects_duplicate_json_keys(tmp_path):
    database = tmp_path / "bad.json"
    database.write_text('{"schema": 1, "schema": 1, "sha256": {}}')
    with pytest.raises(ValueError, match="Duplicate"):
        antivirus.load_signatures(database)


def test_provider_failure_is_reported_and_closed(tmp_path):
    target = tmp_path / "file"
    target.write_bytes(b"fixture")
    provider = Provider(failure=True)
    result = antivirus.scan_files(target, provider_factory=lambda: provider)
    assert result["verdict"] == "incomplete"
    assert result["summary"]["errors"] == 1
    assert result["summary"]["provider_scanned"] == 0
    assert result["issues"][0]["reason"] == "provider unavailable"
    assert provider.closed


def test_size_and_file_count_limits_do_not_hide_incomplete_coverage(tmp_path):
    (tmp_path / "small").write_bytes(b"ok")
    (tmp_path / "large").write_bytes(b"large file")
    result = antivirus.scan_files(tmp_path, max_bytes=2, provider_factory=Provider)
    assert result["summary"]["skipped"] == 1
    assert result["verdict"] == "incomplete"
    result = antivirus.scan_files(tmp_path, max_files=1, provider_factory=Provider)
    assert result["summary"]["limit_reached"]
    assert result["summary"]["files_scanned"] == 1
    assert result["verdict"] == "incomplete"


def test_directory_only_traversal_is_bounded(tmp_path):
    folder = tmp_path
    for _ in range(10):
        folder = folder / "child"
        folder.mkdir()
    result = antivirus.scan_files(tmp_path, max_files=2, provider_factory=Provider)
    assert result["summary"]["entries_seen"] <= 4
    assert result["summary"]["limit_reached"]
    assert result["verdict"] == "incomplete"


def test_sibling_files_each_recheck_their_parent(tmp_path, monkeypatch):
    folder = tmp_path / "siblings"
    folder.mkdir()
    for name in ("first.txt", "second.txt"):
        (folder / name).write_text("inert fixture")

    original_lstat = Path.lstat
    parent_checks = []

    def track_lstat(path):
        if path == folder:
            parent_checks.append(path)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", track_lstat)
    result = antivirus.scan_files(tmp_path, workers=1, use_cache=False)

    assert result["summary"]["files_scanned"] == 2
    assert len(parent_checks) == 3  # Directory enumeration and both file opens.


def test_cancellation_closes_provider_and_does_not_claim_clean(tmp_path):
    provider = Provider()
    result = antivirus.scan_files(tmp_path, provider_factory=lambda: provider, cancelled=lambda: True)
    assert result["summary"]["cancelled"]
    assert result["verdict"] == "incomplete"
    assert provider.closed


def test_quarantine_tree_is_excluded(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "ciphertext.aq").write_bytes(b"opaque")
    (tmp_path / "normal").write_bytes(b"safe")
    result = antivirus.scan_files(tmp_path, provider_factory=Provider, excluded_paths=(vault,))
    assert result["summary"]["files_scanned"] == 1
    assert result["summary"]["skipped"] == 1
    assert result["issues"][0]["reason"] == "quarantine-excluded"


def test_symlink_root_and_child_are_not_followed(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"benign")
    link = tmp_path / "link"
    try:
        link.symlink_to(original)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    result = antivirus.scan_files(tmp_path, provider_factory=Provider)
    assert result["summary"]["skipped"] == 1
    with pytest.raises(ValueError, match="links"):
        antivirus.scan_files(link, provider_factory=Provider)


@pytest.mark.skipif(os.name == "nt", reason="POSIX named pipe")
def test_special_files_do_not_block_scan(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    result = antivirus.scan_files(tmp_path, provider_factory=Provider)
    assert result["summary"]["skipped"] == 1
    assert result["summary"]["files_scanned"] == 0


@pytest.mark.parametrize("kwargs", [{"max_bytes": 0}, {"max_bytes": antivirus.MAX_EXPLICIT_SCAN_BYTES + 1},
                                  {"max_files": 0}, {"max_files": -1}])
def test_invalid_limits_rejected_before_scanning(tmp_path, kwargs):
    with pytest.raises(ValueError):
        antivirus.scan_files(tmp_path, **kwargs)


def test_cli_scan_exit_codes_and_structured_output(tmp_path, monkeypatch, capsys):
    from antios import cli
    target = tmp_path / "safe"
    target.write_text("benign")
    def fake_scan(path, **options):
        return antivirus.scan_files(path, **options, provider_factory=unavailable)
    monkeypatch.setattr(cli, "scan_files", fake_scan)
    assert cli.main(["--config", str(tmp_path / "none.toml"), "virus-scan", str(target), "--json"]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["kind"] == "antivirus-scan"
    monkeypatch.setattr(cli, "scan_files", lambda path, **options:
        antivirus.scan_files(path, **options, provider_factory=lambda: Provider(
            ScanOutcome("threat", "Inert signature", "AntiOS Engine"))))
    assert cli.main(["--config", str(tmp_path / "none.toml"), "virus-scan", str(target)]) == 1
    assert target.exists()


def test_unreadable_directory_entry_does_not_hide_its_siblings(tmp_path, monkeypatch):
    good = tmp_path / 'good'
    good.write_bytes(b'harmless')
    class Entry:
        def __init__(self, path, broken=False):
            self.path, self.broken = str(path), broken
        def stat(self, **kwargs):
            if self.broken:
                raise PermissionError('unreadable entry')
            return Path(self.path).stat()
    class Entries:
        def __enter__(self):
            return iter([Entry(tmp_path / 'bad', True), Entry(good)])
        def __exit__(self, *args):
            pass
    monkeypatch.setattr(antivirus.os, 'scandir', lambda folder: Entries())
    result = antivirus.scan_files(tmp_path, provider_factory=Provider)
    assert result['summary']['errors'] == 1
    assert result['summary']['files_scanned'] == 1
    assert result['verdict'] == 'incomplete'


def test_unknown_engine_is_rejected(tmp_path):
    with pytest.raises(ValueError, match='engine'):
        antivirus.scan_files(tmp_path, engine='unknown')
