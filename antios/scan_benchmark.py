"""Deterministic, inert detection controls for the built-in scanner."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from statistics import median
import tempfile
import time
import zipfile

from .antivirus import SCAN_PROFILE_WORKERS, scan_files
from .scan_verdict import replay_scan_report


_CLEAN = ("no-threats-found", "complete", "no-indicators")
_MATCH = ("threats-found", "complete", "confirmed-signature")
_ADVISORY = ("review", "complete", "suspicious")
_LIMITED = ("review", "limited", "undetermined")
_PREVIEW = ("incomplete", "limited", "undetermined")


def _zip_member(name: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(zipfile.ZipInfo(name), content)
    return output.getvalue()


def _write_large(target: Path, trailer: bytes) -> str:
    block = bytes(1024 * 1024)
    digest = hashlib.sha256()
    with target.open("wb") as stream:
        for _ in range(16):
            stream.write(block)
            digest.update(block)
        stream.write(trailer)
    digest.update(trailer)
    return digest.hexdigest()


def _build_corpus(folder: Path) -> tuple[Path, Path, dict]:
    fixtures = folder / "corpus"
    fixtures.mkdir()
    positive = b"AntiOS inert benchmark signature fixture\n"
    nested = _zip_member("fixture.txt", positive)
    for _ in range(4):
        nested = _zip_member("nested.zip", nested)

    inputs = {
        "benign.txt": b"Ordinary benchmark text\n",
        "benign.ps1": b"Write-Output 'ordinary benchmark text'\n",
        "benign.zip": _zip_member("ordinary.txt", b"Ordinary archive content\n"),
        "exact-match.txt": positive,
        "nested-five.zip": nested,
        "office-review.docm": _zip_member("word/vbaProject.bin", bytes.fromhex("d0cf11e0a1b11ae1") + b"inert"),
        "unsupported.7z": b"Inert unsupported format fixture\n",
        "unreadable.zip": b"Inert invalid archive fixture\n",
    }
    for name, content in inputs.items():
        (fixtures / name).write_bytes(content)
    streamed_digest = _write_large(fixtures / "streamed-match.bin", b"signature after the preview")
    _write_large(fixtures / "streamed-benign.bin", b"ordinary trailer")
    signatures = folder / "control-signatures.json"
    signatures.write_text(json.dumps({"schema": 1, "sha256": {
        hashlib.sha256(positive).hexdigest(): "Inert benchmark signature",
        streamed_digest: "Inert streamed benchmark signature",
    }}), encoding="utf-8")

    # Each control has an expected result per depth, independent of the scanner.
    expected = {
        "benign.txt": (_CLEAN, _CLEAN, _CLEAN),
        "benign.ps1": (_CLEAN, _CLEAN, _CLEAN),
        "benign.zip": (_CLEAN, _CLEAN, _CLEAN),
        "exact-match.txt": (_MATCH, _MATCH, _MATCH),
        "nested-five.zip": (_LIMITED, _LIMITED, _MATCH),
        "office-review.docm": (_ADVISORY, _ADVISORY, _ADVISORY),
        "unsupported.7z": (_LIMITED, _LIMITED, _LIMITED),
        "unreadable.zip": (_LIMITED, _LIMITED, _LIMITED),
        "streamed-match.bin": (_MATCH, _MATCH, _MATCH),
        "streamed-benign.bin": (_PREVIEW, _CLEAN, _CLEAN),
    }
    return fixtures, signatures, expected


def _benchmark_profile(fixtures: Path, signatures: Path, expected: dict, profile: str, repeat: int) -> dict:
    index = ("light", "balanced", "heavy").index(profile)
    options = {"signature_path": signatures, "profile": profile, "use_cache": False}
    cases = []
    for name, outcomes in expected.items():
        result = scan_files(fixtures / name, **options)
        replay = replay_scan_report(result)
        dimensions = replay["dimensions"]
        observed = (replay["verdict"], dimensions["coverage"], dimensions["maliciousness"])
        cases.append({"name": name, "expected": list(outcomes[index]), "observed": list(observed),
                      "passed": observed == outcomes[index]})

    # Per-file controls verify answers. Time the folder separately so the
    # selected profile can exercise its real concurrency settings.
    durations, receipts = [], set()
    for _ in range(repeat):
        start = time.perf_counter()
        result = scan_files(fixtures, **options)
        durations.append(time.perf_counter() - start)
        receipts.add(replay_scan_report(result)["receipt_sha256"])
    return {"passed": sum(case["passed"] for case in cases), "total": len(cases),
            "cases": cases, "median_seconds": round(median(durations), 6),
            "effective_workers": result["limits"]["effective_workers"],
            "stable_replay": len(receipts) == 1}


def run_detection_benchmark(*, profile: str | None = None, repeat: int = 3) -> dict:
    if profile is not None and profile not in SCAN_PROFILE_WORKERS:
        raise ValueError("Unsupported scan profile")
    if type(repeat) is not int or not 1 <= repeat <= 5:
        raise ValueError("Benchmark repetitions must be between 1 and 5")
    profiles = (profile,) if profile else tuple(SCAN_PROFILE_WORKERS)
    with tempfile.TemporaryDirectory(prefix="antios-detection-controls-") as folder:
        fixtures, signatures, expected = _build_corpus(Path(folder))
        results = {mode: _benchmark_profile(fixtures, signatures, expected, mode, repeat) for mode in profiles}
    return {"schema": 1, "kind": "antivirus-detection-benchmark", "corpus": "inert-detection-controls-v1",
            "repeat": repeat, "profiles": results,
            "passed": all(item["passed"] == item["total"] and item["stable_replay"] for item in results.values())}
