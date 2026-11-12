import hashlib
import hmac
import json
import os
import zlib

import pytest

from antios.antivirus import scan_files
from antios.quarantine import DPAPIProtector, Quarantine
from test_antivirus import Provider
from antios.engine_types import ScanOutcome


class AuthenticatedTestProtector:
    """Inert fixture stand-in. Production always uses Windows DPAPI."""
    def protect(self, content):
        payload = zlib.compress(content)
        return hmac.digest(b"test-only", payload, "sha256") + payload

    def unprotect(self, content):
        signature, payload = content[:32], content[32:]
        if not hmac.compare_digest(signature, hmac.digest(b"test-only", payload, "sha256")):
            raise ValueError("tampered test blob")
        return zlib.decompress(payload)


@pytest.fixture
def fixture(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"benign quarantine fixture; never real malware")
    finding = scan_files(source, provider_factory=lambda: Provider(ScanOutcome("threat", "Inert quarantine fixture", "AntiOS Engine")))["findings"][0]
    vault = Quarantine(tmp_path / "vault", protector=AuthenticatedTestProtector())
    return source, finding, vault


def test_default_add_is_a_preview_and_does_not_create_storage(fixture):
    source, finding, vault = fixture
    assert vault.add(finding)["dry_run"]
    assert source.exists()
    assert not vault.root.exists()


def test_quarantine_and_restore_roundtrip_preserves_exact_bytes(fixture):
    source, finding, vault = fixture
    original = source.read_bytes()
    item = vault.add(finding, dry_run=False)
    assert not source.exists()
    assert original not in (vault.root / (item["id"] + ".aq")).read_bytes()
    assert len(vault.list_items()) == 1
    assert vault.list_items()[0]["state"] == "isolated"
    assert vault.restore(item["id"])["dry_run"]
    assert not source.exists()
    vault.restore(item["id"], dry_run=False)
    assert source.read_bytes() == original
    assert not vault.list_items()


def test_modified_file_is_not_quarantined(fixture):
    source, finding, vault = fixture
    source.write_bytes(b"replacement")
    with pytest.raises(ValueError, match="changed"):
        vault.add(finding, dry_run=False)
    assert source.read_bytes() == b"replacement"
    assert not vault.root.exists()


def test_policy_block_is_not_eligible_for_quarantine(fixture):
    source, finding, vault = fixture
    finding["kind"] = "review"
    with pytest.raises(ValueError, match="confirmed"):
        vault.add(finding, dry_run=False)
    assert source.exists()


def test_restore_refuses_overwrite_and_keeps_backup(fixture):
    source, finding, vault = fixture
    item = vault.add(finding, dry_run=False)
    source.write_bytes(b"new valid user file")
    with pytest.raises(FileExistsError):
        vault.restore(item["id"], dry_run=False)
    assert source.read_bytes() == b"new valid user file"
    assert len(vault.list_items()) == 1
    alternate = source.with_name("restored.txt")
    vault.restore(item["id"], destination=alternate, dry_run=False)
    assert hashlib.sha256(alternate.read_bytes()).hexdigest() == finding["sha256"]


def test_failed_status_commit_leaves_recoverable_authenticated_copy(fixture, monkeypatch):
    source, finding, vault = fixture
    save = vault._save_record
    def failing_save(record, *, new):
        if not new:
            raise OSError("status commit failed")
        return save(record, new=new)
    monkeypatch.setattr(vault, "_save_record", failing_save)
    with pytest.raises(OSError, match="recovery copy"):
        vault.add(finding, dry_run=False)
    assert not source.exists()
    items = vault.list_items()
    assert items[0]["state"] == "recovery-copy"
    vault.restore(items[0]["id"], dry_run=False)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == finding["sha256"]


def test_tampered_blob_is_not_restored(fixture):
    source, finding, vault = fixture
    item = vault.add(finding, dry_run=False)
    path = vault.root / (item["id"] + ".aq")
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    with pytest.raises(ValueError):
        vault.restore(item["id"], dry_run=False)
    assert not source.exists()
    assert vault.list_items()[0]["error"]


@pytest.mark.parametrize("item_id", ["../secret", "a" * 31, "A" * 32, "a" * 32 + "/other"])
def test_item_id_cannot_escape_storage(fixture, item_id):
    _source, _finding, vault = fixture
    with pytest.raises(ValueError, match="ID"):
        vault.restore(item_id)


def test_hardlinks_cannot_be_mistaken_for_complete_isolation(fixture):
    source, finding, vault = fixture
    os.link(source, source.with_name("alias.txt"))
    with pytest.raises(ValueError, match="Hard-linked"):
        vault.add(finding, dry_run=False)
    assert source.exists()


def test_encryption_failure_leaves_original_intact(fixture):
    source, finding, vault = fixture
    class BrokenProtector(AuthenticatedTestProtector):
        def protect(self, content):
            raise OSError("encryption failed")
    vault.protector = BrokenProtector()
    with pytest.raises(OSError):
        vault.add(finding, dry_run=False)
    assert source.exists()


def test_undecryptable_backup_never_removes_original(fixture):
    source, finding, vault = fixture
    class BrokenProtector(AuthenticatedTestProtector):
        def unprotect(self, content):
            raise OSError("verification failed")
    vault.protector = BrokenProtector()
    with pytest.raises(OSError):
        vault.add(finding, dry_run=False)
    assert source.exists()


def test_rename_race_keeps_replacement_file_and_verified_backup(fixture, monkeypatch):
    from antios import quarantine
    source, finding, vault = fixture
    move = quarantine._move_without_overwrite
    def raced_move(src, dst):
        if src == source:
            source.write_bytes(b"replacement arriving during isolation")
        move(src, dst)
    monkeypatch.setattr(quarantine, "_move_without_overwrite", raced_move)
    with pytest.raises(ValueError, match="changed"):
        vault.add(finding, dry_run=False)
    assert source.read_bytes() == b"replacement arriving during isolation"
    assert len(vault.list_items()) == 1


def test_restore_rejects_linked_destination_parent(fixture):
    source, finding, vault = fixture
    item = vault.add(finding, dry_run=False)
    link = source.parent / "linked-dir"
    try:
        link.symlink_to(source.parent, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    with pytest.raises(ValueError):
        vault.restore(item["id"], destination=link / "out.txt", dry_run=False)
    assert len(vault.list_items()) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI native integration")
def test_native_dpapi_authenticated_roundtrip_and_tamper_detection():
    protector = DPAPIProtector()
    original = b"ordinary native integration fixture"
    encrypted = protector.protect(original)
    assert encrypted != original
    assert original not in encrypted
    assert protector.unprotect(encrypted) == original
    changed = bytearray(encrypted)
    changed[-1] ^= 1
    with pytest.raises(OSError):
        protector.unprotect(bytes(changed))


def test_verify_all_reports_valid_and_corrupt_items(fixture):
    source, finding, vault = fixture
    item = vault.add(finding, dry_run=False)
    first = vault.verify_all()
    assert first["checked"] == 1
    assert first["valid"] == 1
    assert first["corrupt"] == 0

    path = vault.root / (item["id"] + ".aq")
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)

    second = vault.verify_all()
    assert second["checked"] == 1
    assert second["valid"] == 0
    assert second["corrupt"] == 1
    assert second["issues"][0]["id"] == item["id"]
