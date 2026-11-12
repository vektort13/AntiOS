import hashlib
import json

from antios import antivirus, scan_acceleration
from antios.scan_verdict import replay_scan_report


class FailingCUDA:
    name = "test-cuda"

    def __init__(self):
        self.calls = 0
        self.closed = False

    def digest_many(self, contents):
        self.calls += 1
        digests = tuple(hashlib.sha256(content).hexdigest() for content in contents)
        if self.calls == 3:
            return ("0" * 64, *digests[1:])
        return digests

    def close(self):
        self.closed = True


def test_gpu_hash_failure_preserves_scan_receipt_and_switches_to_cpu(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    known = b"AntiOS inert GPU regression fixture"
    for index in range(64):
        (corpus / f"item-{index:02}.txt").write_bytes(known if index % 8 == 0 else bytes([index]) * 4096)
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "sha256": {
        hashlib.sha256(known).hexdigest(): "Inert regression signature",
    }}), encoding="utf-8")

    backend = FailingCUDA()
    router = scan_acceleration.ScanAcceleration("accelerated", backend_factory=lambda: backend)
    router.batch_items = 32
    baseline = antivirus.scan_files(corpus, signature_path=catalog, use_cache=False)
    monkeypatch.setattr(antivirus, "ScanAcceleration", lambda _: router)
    accelerated = antivirus.scan_files(corpus, signature_path=catalog, gpu_mode="accelerated", use_cache=False)
    assert accelerated["summary"]["threats"] == 8
    assert replay_scan_report(baseline) == replay_scan_report(accelerated)
    status = accelerated["engine"]["acceleration"]
    assert status["gpu_files"] == 32 and status["fallback"] == "ValueError"
    assert backend.closed


def test_auto_accounts_for_additional_dispatch_time(monkeypatch):
    backend = FailingCUDA()
    router = scan_acceleration.ScanAcceleration("auto", backend_factory=lambda: backend)
    timestamps = iter((0.0, 0.010, 0.010, 0.015, 0.015, 0.025))
    monkeypatch.setattr(scan_acceleration, "perf_counter", lambda: next(timestamps))
    inputs = (b"fixture",) * 128
    expected = tuple(map(scan_acceleration.sha256, inputs))
    assert router.digests(inputs, {}, lambda _: expected, lambda _: None) == expected
    status = router.status()
    assert status["device"] == "cpu" and status["calibration"]["dispatch_seconds"] == .01
    assert not status["fallback"] and not router.enabled
