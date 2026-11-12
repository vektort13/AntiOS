"""Signed catalog checks use only ephemeral publishers and inert fixture bytes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from antios import antivirus, cli, guard, scan_process, signature_catalog as catalog


@pytest.fixture
def publisher(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    store = tmp_path / "state" / "signatures.sqlite3"

    def package(version, name=None, content=b"inert fixture"):
        label = name or f"Fixture v{version}"
        body = {
            "schema": 1,
            "version": version,
            "published": "2026-11-10",
            "sha256": {hashlib.sha256(content).hexdigest(): {
                "label": label, "source": "https://example.org/report", "source_date": "2026-01-01",
            }},
        }
        data = json.dumps({"catalog": body, "signature": key.sign(catalog.signed_bytes(body)).hex()})
        path = tmp_path / f"catalog-{version}.antisig"
        path.write_text(data, encoding="utf-8")
        return path

    monkeypatch.setattr(catalog, "PUBLIC_KEY", key.public_key().public_bytes_raw())
    monkeypatch.setattr(catalog, "BUNDLED_PACKAGE", package(1).read_bytes())
    monkeypatch.setattr(catalog, "default_catalog_path", lambda: store)
    catalog.bundled_catalog.cache_clear()
    yield package, store
    catalog.bundled_catalog.cache_clear()


def test_bundled_publisher_catalog_has_provenance():
    body = json.loads(catalog.BUNDLED_PACKAGE)["catalog"]
    baseline = catalog.verify_catalog(catalog.BUNDLED_PACKAGE)
    assert baseline.rules
    assert len(baseline.rules) == len(body["sha256"])
    assert all(rule["source"].startswith("https://www.ncsc.gov.uk/") for rule in body["sha256"].values())


def test_application_supplement_is_exact_and_new_signed_catalog_supersedes_it(publisher):
    package, _ = publisher
    supplemental = set(antivirus.AKIRA_SUPPLEMENT)
    cisa_2025 = set(antivirus.CISA_2025_SUPPLEMENT)
    combined = supplemental | cisa_2025
    assert len(supplemental) == 13
    assert len(cisa_2025) == 7
    assert all(len(bytes.fromhex(digest)) == 32 and digest == digest.lower() for digest in combined)

    rules, metadata = antivirus.load_managed_signatures()
    assert combined <= rules.keys()
    assert metadata["signature_bundled_supplement_entries"] == 20
    assert metadata["signature_cisa_2025_entries"] == 7

    catalog.install_catalog(package(4))
    rules, metadata = antivirus.load_managed_signatures()
    assert combined.isdisjoint(rules)
    assert metadata["signature_bundled_supplement_entries"] == 0
    assert metadata["signature_cisa_2025_entries"] == 0


def test_bad_signature_and_downgrade_preserve_active_catalog(publisher):
    package, store = publisher
    newer = package(3)
    catalog.install_catalog(newer)
    assert catalog.install_catalog(newer).version == 3
    before = store.read_bytes()
    with pytest.raises(ValueError, match="newer"):
        catalog.install_catalog(package(2))

    bad = package(4)
    bad.write_text(bad.read_text().replace("Fixture v4", "Untrusted label"))
    with pytest.raises(ValueError, match="authentication failed"):
        catalog.install_catalog(bad)
    assert store.read_bytes() == before
    assert catalog.load_active_catalog().version == 3


def test_bad_update_creates_no_user_store(publisher):
    _, store = publisher
    bad = store.parent.parent / "bad.antisig"
    bad.write_text('{"catalog":{},"catalog":{},"signature":""}')
    with pytest.raises(ValueError):
        catalog.install_catalog(bad)
    assert not store.parent.exists()
    assert catalog.load_active_catalog().version == 1


def test_fallback_to_previous_verified_catalog_and_recovery(publisher):
    package, store = publisher
    catalog.install_catalog(package(2))
    catalog.install_catalog(package(3))
    with closing(sqlite3.connect(store)) as db, db:
        db.execute("UPDATE catalogs SET package=? WHERE version=3", (b"corrupt",))
    fallback = catalog.load_active_catalog()
    assert fallback.version == 2
    assert fallback.metadata()["signature_catalog_status"] == "fallback"
    assert fallback.warning
    assert guard.probe_engine()["signature_catalog_status"] == "fallback"

    catalog.install_catalog(package(4))
    assert catalog.load_active_catalog().version == 4
    assert not catalog.load_active_catalog().warning
    with closing(sqlite3.connect(store)) as db:
        assert db.execute("SELECT version FROM catalogs ORDER BY version").fetchall() == [(2,), (4,)]


def test_unreadable_user_store_falls_back_to_bundled(publisher):
    _, store = publisher
    store.parent.mkdir()
    store.write_bytes(b"not a database")
    result = catalog.load_active_catalog()
    assert result.version == 1
    assert result.metadata()["signature_catalog_status"] == "fallback"


def test_failed_transaction_does_not_publish_candidate(publisher):
    package, store = publisher
    catalog.install_catalog(package(2))
    catalog.install_catalog(package(3))
    with closing(sqlite3.connect(store)) as db, db:
        db.execute("""CREATE TRIGGER block_prune BEFORE DELETE ON catalogs
                      BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END""")
    with pytest.raises(OSError, match="could not be committed"):
        catalog.install_catalog(package(4))
    assert catalog.load_active_catalog().version == 3
    with closing(sqlite3.connect(store)) as db:
        assert db.execute("SELECT version FROM catalogs ORDER BY version").fetchall() == [(2,), (3,)]


def test_concurrent_writers_keep_newest_version(publisher):
    package, _ = publisher
    candidates = (package(2), package(3))

    def install(path):
        try:
            return catalog.install_catalog(path).version
        except ValueError as exc:
            assert "newer" in str(exc)
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        installed = list(executor.map(install, candidates))
    assert 3 in installed
    assert catalog.load_active_catalog().version == 3


def test_cli_guard_and_scan_worker_share_catalog(publisher, tmp_path, capsys):
    package, _ = publisher
    target = tmp_path / "sample"
    target.write_bytes(b"another inert fixture")
    bundle = package(2, "Fixture from installed catalog", target.read_bytes())
    assert cli.main(["--config", str(tmp_path / "none.toml"), "signatures", "install",
                     str(bundle), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["signature_catalog_version"] == guard.probe_engine()["signature_catalog_version"] == 2

    report = antivirus.scan_files(target)
    assert report["engine"]["signature_catalog_version"] == 2
    assert report["findings"][0]["name"] == "Fixture from installed catalog"
    request = tmp_path / "request.json"
    events = tmp_path / "events.jsonl"
    request.write_text(json.dumps({"path": str(target), "use_cache": False}))
    assert scan_process.worker_main(str(request), str(events)) == 0
    reports = [value for kind, value in map(json.loads, events.read_text().splitlines())
               if kind == "checkpoint"]
    assert reports[-1]["engine"]["signature_catalog_version"] == 2
    assert any(finding["name"] == "Fixture from installed catalog"
               for event in reports for finding in event["findings"])
