"""Isolate read-only native AntiOS scans so blocked filesystem calls can be terminated.

The child appends JSON events to a private temporary directory. This works with
windowed frozen executables (which have no stdout), and killing a writer cannot
strand the parent in a partially written pipe message.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from .windows_process import hidden_process_kwargs
import time
from typing import Callable

from .antivirus import DEFAULT_SCAN_PROFILE, checked_path, finalize_scan_result, scan_files, utc_now
from .quarantine import default_quarantine_path
from .scan_cache import default_scan_cache_path
from .scan_acceleration import DEFAULT_GPU_MODE

WORKER_FLAG = "--antios-scan-worker"


def worker_main(request_path: str, events_path: str) -> int:
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    with open(events_path, "w", encoding="utf-8") as stream:
        def emit(kind, value):
            stream.write(json.dumps([kind, value], ensure_ascii=True) + "\n")
            stream.flush()

        counts = [0, 0]
        last_sent = [0.0]

        def checkpoint(result):
            now = time.monotonic()
            if (now - last_sent[0] < 0.1 and not result["finished_at"]
                    and counts == [len(result["findings"]), len(result["issues"])]):
                return
            last_sent[0] = now
            # Send only new findings/issues: large scans must not copy their
            # entire accumulated report for every progress update.
            event = {k: v for k, v in result.items() if k not in {"findings", "issues"}}
            for index, key in enumerate(("findings", "issues")):
                event[key] = result[key][counts[index]:]
                counts[index] = len(result[key])
            emit("checkpoint", event)

        try:
            scan_files(request["path"], signature_path=request.get("signatures"),
                       engine=request.get("engine", "antios"),
                       max_files=None,
                       max_bytes=None,
                       engine_service=request.get("engine_service"),
                       require_verified_peer=bool(request.get("require_verified_peer", False)),
                       excluded_paths=(default_quarantine_path(),), checkpoint=checkpoint,
                       worker_files=(Path(request_path), Path(events_path)),
                       workers=request.get("workers"),
                       profile=request.get("profile", DEFAULT_SCAN_PROFILE),
                       gpu_mode=request.get("gpu_mode", DEFAULT_GPU_MODE),
                       cache_path=default_scan_cache_path(),
                       use_cache=bool(request.get("use_cache", True)))
            emit("done", None)
            return 0
        except Exception as exc:
            emit("error", str(exc))
            return 1


def worker_command(request: Path, events: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, WORKER_FLAG, str(request), str(events)]
    # pythonw has no console, but our transport does not rely on stdio.
    return [sys.executable, "-m", "antios.scan_process", str(request), str(events)]


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def _worker_workspace(scratch_dir: Path | None) -> tempfile.TemporaryDirectory:
    if scratch_dir is not None:
        return tempfile.TemporaryDirectory(prefix="antios-scan-", dir=checked_path(scratch_dir))
    # Keep ordinary scan traffic out of watched Temp when the local app
    # directory is writable. Otherwise preserve the system temp fallback.
    scratch_dir = default_scan_cache_path().absolute().parent
    try:
        ancestor = scratch_dir
        while ancestor != ancestor.parent and not ancestor.exists():
            ancestor = ancestor.parent
        checked_path(ancestor)
        scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return tempfile.TemporaryDirectory(prefix="antios-scan-", dir=checked_path(scratch_dir))
    except (OSError, ValueError):
        return tempfile.TemporaryDirectory(prefix="antios-scan-")


def run_scan_process(path: Path, *, signature_path: Path | None = None,
                     engine: str = "antios",
                     engine_service: str | None = None,
                     require_verified_peer: bool = False,
                     workers: int | None = None,
                     profile: str = DEFAULT_SCAN_PROFILE,
                     gpu_mode: str = DEFAULT_GPU_MODE,
                     use_cache: bool = True,
                     scratch_dir: Path | None = None,
                     timeout: float | None = None,
                     cancelled: Callable[[], bool] = lambda: False,
                     progress: Callable[[dict], None] | None = None) -> dict:
    result = None
    if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("Scan process timeout must be finite and positive")
    done, failure = False, None
    with _worker_workspace(scratch_dir) as folder:
        request, events = Path(folder) / "request.json", Path(folder) / "events.jsonl"
        request.write_text(json.dumps({
            "path": str(Path(path).absolute()),
            "engine": engine,
            "engine_service": engine_service,
            "require_verified_peer": bool(require_verified_peer),
            "workers": workers,
            "profile": profile,
            "gpu_mode": gpu_mode,
            "use_cache": bool(use_cache),
            "signatures": str(signature_path.absolute()) if signature_path else None,
        }), encoding="utf-8")
        events.touch()
        process = subprocess.Popen(
            worker_command(request, events),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **hidden_process_kwargs(),
        )
        forced = False
        timed_out = False
        deadline = time.monotonic() + timeout if timeout is not None else None
        pending = ""
        try:
            with events.open(encoding="utf-8") as stream:
                while True:
                    expired = deadline is not None and time.monotonic() >= deadline
                    if (cancelled() or expired) and process.poll() is None:
                        forced = True
                        timed_out = expired
                        _terminate(process)
                    # Once it has exited, drain the final complete records.
                    exited = process.poll() is not None
                    pending += stream.read()
                    lines = pending.split("\n")
                    pending = lines.pop()
                    for line in lines:
                        kind, value = json.loads(line)
                        if kind == "checkpoint":
                            if result is None:
                                result = value
                            else:
                                for key in ("findings", "issues"):
                                    previous = result[key]
                                    previous.extend(value[key])
                                    value[key] = previous
                                result = value
                            if progress:
                                progress(result["summary"])
                        elif kind == "done":
                            done = True
                        elif kind == "error":
                            failure = value
                    if exited:
                        break
                    time.sleep(0.05)
            if forced:
                if result is None:
                    # Cancellation can arrive before the interpreter starts.
                    result = {"schema": 1, "kind": "antivirus-scan", "path": str(path),
                              "started_at": utc_now(), "engine": {}, "limits": {"profile": profile},
                              "summary": {"files_seen": 0, "entries_seen": 0, "files_scanned": 0,
                                          "provider_scanned": 0, "bytes_scanned": 0, "threats": 0,
                                          "reviews": 0, "skipped": 0, "errors": 0, "limit_reached": False},
                              "findings": [], "issues": []}
                result["summary"].update(cancelled=True, forced_stop=True)
                if timed_out:
                    result["summary"]["timed_out"] = True
                finalize_scan_result(result)
                return result
            if failure or not done or result is None or process.returncode != 0:
                raise RuntimeError(failure or f"Scan worker exited unexpectedly ({process.returncode})")
            return result
        finally:
            _terminate(process)


if __name__ == "__main__":
    raise SystemExit(worker_main(*sys.argv[1:]))
