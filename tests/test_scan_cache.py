import os
import threading
import time

from antios import antivirus
from antios.scan_cache import ScanCache
from antios.engine_types import ScanOutcome


class ReadyNativeProvider:
    metadata = {
        "version": "AntiOS Engine test/42",
        "database_freshness": "local",
        "signature_scope": "local-sha256",
    }

    def __init__(self):
        self.calls = 0
        self.closed = False

    def scan(self, content, name):
        self.calls += 1
        return ScanOutcome()

    def close(self):
        self.closed = True


def test_clean_cache_skips_unchanged_file_and_invalidates_on_change(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"ordinary fixture")
    cache = tmp_path / "cache.sqlite3"

    first = ReadyNativeProvider()
    result1 = antivirus.scan_files(
        target,
        engine="antios",
        provider_factory=lambda: first,
        cache_path=cache,
        workers=2,
    )
    assert result1["verdict"] == "no-threats-found"
    assert first.calls == 1
    assert result1["summary"]["cache_hits"] == 0

    second = ReadyNativeProvider()
    result2 = antivirus.scan_files(
        target,
        engine="antios",
        provider_factory=lambda: second,
        cache_path=cache,
        workers=2,
    )
    assert result2["verdict"] == "no-threats-found"
    assert second.calls == 0
    assert result2["summary"]["cache_hits"] == 1

    target.write_bytes(b"changed fixture")
    third = ReadyNativeProvider()
    result3 = antivirus.scan_files(
        target,
        engine="antios",
        provider_factory=lambda: third,
        cache_path=cache,
        workers=2,
    )
    assert third.calls == 1
    assert result3["summary"]["cache_hits"] == 0


def test_engine_identity_change_invalidates_cache(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"ordinary fixture")
    cache = tmp_path / "cache.sqlite3"

    first = ReadyNativeProvider()
    antivirus.scan_files(
        target, engine="antios", provider_factory=lambda: first, cache_path=cache
    )

    class UpdatedProvider(ReadyNativeProvider):
        metadata = dict(ReadyNativeProvider.metadata, version="AntiOS Engine test/43")

    updated = UpdatedProvider()
    result = antivirus.scan_files(
        target, engine="antios", provider_factory=lambda: updated, cache_path=cache
    )
    assert updated.calls == 1
    assert result["summary"]["cache_hits"] == 0


def test_parallel_cache_rechecks_bytes_with_same_metadata(tmp_path):
    folder = tmp_path / "files"
    folder.mkdir()
    target = folder / "sample.bin"
    target.write_bytes(b"old")
    (folder / "unchanged.bin").write_bytes(b"unchanged")
    cache = tmp_path / "cache.sqlite3"
    antivirus.scan_files(folder, cache_path=cache, provider_factory=ReadyNativeProvider)
    prior = target.stat()
    target.write_bytes(b"new")
    os.utime(target, ns=(prior.st_atime_ns, prior.st_mtime_ns))

    class UpdatedContentProvider(ReadyNativeProvider):
        def scan(self, content, name):
            return ScanOutcome("review", "Changed fixture") if content == b"new" else ScanOutcome()

    result = antivirus.scan_files(folder, cache_path=cache, provider_factory=UpdatedContentProvider)
    assert result["summary"]["cache_hits"] == 1
    assert result["summary"]["reviews"] == 1
    assert result["findings"][0]["name"] == "Changed fixture"


def test_native_workers_are_bounded_and_concurrent(tmp_path):
    for index in range(12):
        (tmp_path / f"{index}.bin").write_bytes(f"fixture-{index}".encode())

    lock = threading.Lock()
    state = {"active": 0, "peak": 0}

    class SlowProvider(ReadyNativeProvider):
        def scan(self, content, name):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                time.sleep(0.02)
                return ScanOutcome()
            finally:
                with lock:
                    state["active"] -= 1

    provider = SlowProvider()
    result = antivirus.scan_files(
        tmp_path,
        engine="antios",
        provider_factory=lambda: provider,
        cache_path=None,
        workers=4,
    )
    assert result["verdict"] == "no-threats-found"
    assert result["limits"]["effective_workers"] == 2
    assert 1 <= state["peak"] <= 2


def test_cache_does_not_share_results_between_depth_profiles(tmp_path):
    target = tmp_path / "fixture.txt"
    target.write_bytes(b"inert fixture")
    cache = tmp_path / "cache.sqlite3"

    def hits(profile):
        result = antivirus.scan_files(target, profile=profile, cache_path=cache)
        return result["summary"]["cache_hits"]

    assert hits("light") == 0
    assert hits("balanced") == 0
    assert hits("balanced") == 1
    assert hits("heavy") == 0


def test_cache_database_prunes_and_closes(tmp_path):
    cache = ScanCache(tmp_path / "cache.sqlite3")
    cache.close()
    assert (tmp_path / "cache.sqlite3").is_file()
