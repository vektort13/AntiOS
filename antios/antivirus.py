"""Bounded on-demand file scanner. Findings never mutate scanned files."""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import asdict
import hashlib
import json
import os
import re
import stat
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .engine import MAX_INLINE_BYTES, AntiOSEngine, inspection_limits
from .engine_types import ScanOutcome
from .scan_cache import ScanCache, engine_key as make_engine_key, signature_key as make_signature_key
from .scan_verdict import apply_scan_verdict
from .signature_bootstrap import AKIRA_SUPPLEMENT, CISA_2025_SUPPLEMENT
from .signature_catalog import load_active_catalog

DEFAULT_MAX_BYTES = MAX_INLINE_BYTES
MAX_EXPLICIT_SCAN_BYTES = 2 * 1024 * 1024 * 1024
SCAN_PROFILE_WORKERS = {"light": 2, "balanced": 4, "heavy": 8}
DEFAULT_SCAN_PROFILE = "balanced"
DEFAULT_SCAN_WORKERS = SCAN_PROFILE_WORKERS[DEFAULT_SCAN_PROFILE]
MAX_SCAN_WORKERS = 16
DEFAULT_MAX_FILES = 100_000
MAX_DETAILS = 1000
# Hash only: do not embed the EICAR test payload in packaged executables.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def _checked_path_info(path: str | Path) -> tuple[Path, os.stat_result]:
    target = Path(os.path.abspath(Path(path).expanduser()))
    return target, _checked_absolute_path_info(target, reversed(target.parents))


def _checked_absolute_path_info(target: Path, ancestors: Iterable[Path]) -> os.stat_result:
    if os.name == "nt" and any(":" in part for part in target.parts[1:]):
        raise ValueError("Alternate data streams are not supported")
    for component in ancestors:
        if is_link(component.lstat()):
            raise ValueError("Symbolic links and reparse points are not supported")
    info = target.lstat()
    if is_link(info):
        raise ValueError("Symbolic links and reparse points are not supported")
    return info


def checked_path(path: str | Path) -> Path:
    """Reject symlinks/junctions and Windows alternate streams, including parents."""
    return _checked_path_info(path)[0]


def read_regular(path: Path, max_bytes: int) -> tuple[bytes, os.stat_result]:
    target, before = _checked_path_info(path)
    return _read_checked_file(target, before, max_bytes)


def _read_checked_file(target, before, max_bytes) -> tuple[bytes, os.stat_result]:
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("Not a regular file")
    if before.st_size > max_bytes:
        raise ValueError("File exceeds the scan size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(target, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or fingerprint(before) != fingerprint(opened):
            raise ValueError("File changed while opening")
        # The size was checked against max_bytes before opening. Reading only
        # that size avoids a max_bytes-sized allocation for a tiny file.
        content = stream.read(opened.st_size + 1)
        after = os.fstat(stream.fileno())
    if len(content) != opened.st_size:
        raise ValueError("File changed while reading")
    if fingerprint(opened) != fingerprint(after) or fingerprint(after) != fingerprint(target.lstat()):
        raise ValueError("File changed while reading")
    return content, after


def load_managed_signatures() -> tuple[dict[str, str], dict]:
    catalog = load_active_catalog()
    rules = dict(catalog.rules)
    if catalog.version <= 3:
        for digest in AKIRA_SUPPLEMENT:
            rules.setdefault(digest, "Akira ransomware (CISA/FBI)")
        for digest, label in CISA_2025_SUPPLEMENT.items():
            rules.setdefault(digest, label)
    metadata = dict(
        catalog.metadata(),
        signature_bundled_supplement_entries=len(rules) - len(catalog.rules),
        signature_cisa_2025_entries=(
            len(CISA_2025_SUPPLEMENT) if catalog.version <= 3 else 0
        ),
    )
    rules[EICAR_SHA256] = "EICAR test file (not live malware)"
    return rules, metadata


def load_signatures(path: str | Path | None = None) -> dict[str, str]:
    if path is None:
        return load_managed_signatures()[0]
    signatures = {EICAR_SHA256: "EICAR test file (not live malware)"}
    content, _info = read_regular(Path(path), 8 * 1024 * 1024)
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate signature database key")
            result[key] = value
        return result

    try:
        data = json.loads(content, object_pairs_hook=unique_object)
    except RecursionError as exc:
        raise ValueError("Signature database is nested too deeply") from exc
    if not isinstance(data, dict) or type(data.get("schema")) is not int or data["schema"] != 1:
        raise ValueError("Signature database requires schema 1")
    entries = data.get("sha256")
    if not isinstance(entries, dict) or len(entries) > 100_000:
        raise ValueError("Signature database must contain at most 100000 SHA-256 entries")
    normalized = {}
    for digest, label in entries.items():
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ValueError("Invalid SHA-256 signature")
        if not isinstance(label, str) or not label.strip() or len(label) > 200 or not label.isprintable():
            raise ValueError("Invalid signature label")
        digest = digest.lower()
        if digest in normalized:
            raise ValueError("Duplicate SHA-256 signature")
        normalized[digest] = label
    signatures.update(normalized)
    return signatures


def _describe_inspection(outcome: ScanOutcome | None, label: str | None) -> dict[str, Any]:
    finding = None
    if label:
        finding = {"kind": "threat", "engine": "SHA-256", "name": label}
    elif outcome and outcome.kind:
        finding = {"kind": outcome.kind, "engine": outcome.engine, "name": outcome.name}
        if outcome.rule_id:
            finding["rule_id"] = outcome.rule_id
            finding["rule_family"] = outcome.rule_id.partition(".")[0]

    coverage_gaps = ()
    coverage_detail = ""
    if outcome and not outcome.complete:
        coverage_gaps = sorted(outcome.coverage_gaps) or ["engine-inspection-incomplete"]
        coverage_detail = outcome.detail or outcome.name or "Engine inspection was incomplete"
    return {"finding": finding, "provider_scanned": outcome is not None,
            "coverage_gaps": coverage_gaps, "coverage_detail": coverage_detail}


def _scan_large_file(item, before, provider, signatures, stopped):
    """Hash one stable snapshot while sending identical bytes to AntiOS Engine."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(item, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if fingerprint(opened) != fingerprint(before) or not stat.S_ISREG(opened.st_mode):
            raise ValueError("File changed while opening")
        digest = hashlib.sha256()
        complete = False
        block_size = 256 * 1024 if type(provider) is AntiOSEngine else 64 * 1024

        def blocks():
            nonlocal complete
            remaining = opened.st_size
            while remaining:
                if stopped():
                    raise InterruptedError("Scan cancelled")
                block = stream.read(min(block_size, remaining))
                if not block:
                    raise ValueError("File changed while reading")
                digest.update(block)
                remaining -= len(block)
                yield block
            complete = True

        chunks = blocks()
        outcome, error = None, None
        if provider is not None:
            try:
                if hasattr(provider, "scan_hashed_stream"):
                    outcome = provider.scan_hashed_stream(chunks, str(item), digest.hexdigest)
                elif hasattr(provider, "scan_stream_named"):
                    outcome = provider.scan_stream_named(chunks, str(item))
                elif hasattr(provider, "scan_stream"):
                    outcome = provider.scan_stream(chunks)
                else:
                    raise OSError("Engine does not support large-file streaming")
                if (not complete or not isinstance(outcome, ScanOutcome)
                        or outcome.kind not in (None, "review", "threat")):
                    raise OSError("Engine did not confirm the complete stream")
            except (OSError, RuntimeError) as exc:
                # Engine stream limits are per file. Continue hashing and
                # allow the next file to receive its own engine inspection.
                outcome, error = None, str(exc)
        for _block in chunks:
            pass
        after = os.fstat(stream.fileno())
        if (not complete or fingerprint(opened) != fingerprint(after)
                or fingerprint(after) != fingerprint(_checked_path_info(item)[1])):
            raise ValueError("File changed or could not be read completely")
    sha = digest.hexdigest()
    return {"item": item, "info": after, "size": after.st_size, "sha256": sha,
            "file_engine_error": error, **_describe_inspection(outcome, signatures.get(sha))}


def finalize_scan_result(result: dict[str, Any]) -> None:
    apply_scan_verdict(result)
    result["finished_at"] = utc_now()


def scan_files(
    path: str | Path,
    *,
    signature_path: str | Path | None = None,
    max_bytes: int | None = None,
    max_files: int | None = None,
    progress: Callable[[dict], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    provider_factory: Callable | None = None,
    engine: str = "antios",
    engine_service: str | None = None,
    require_verified_peer: bool = False,
    excluded_paths: tuple[Path, ...] = (),
    checkpoint: Callable[[dict], None] | None = None,
    workers: int | None = None,
    profile: str = DEFAULT_SCAN_PROFILE,
    cache_path: str | Path | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    if engine != "antios":
        raise ValueError("Unsupported scan engine: only independent AntiOS Engine is supported")
    depth_limits = inspection_limits(profile)
    if provider_factory is None:
        provider_factory = lambda: AntiOSEngine(signatures=signatures, profile=profile)
    if any(v is not None and (type(v) is not int or v <= 0) for v in (max_files, max_bytes)):
        raise ValueError("Explicit scan limits must be positive integers")
    if max_bytes is not None and max_bytes > MAX_EXPLICIT_SCAN_BYTES:
        raise ValueError("Explicit scan size limit cannot exceed 2 GiB")
    inline_limit = DEFAULT_MAX_BYTES if profile == DEFAULT_SCAN_PROFILE else depth_limits.inline_bytes
    buffer_limit = min(max_bytes or inline_limit, inline_limit)
    workers = SCAN_PROFILE_WORKERS[profile] if workers is None else workers
    if type(workers) is not int or not 1 <= workers <= MAX_SCAN_WORKERS:
        raise ValueError(f"Scan workers must be between 1 and {MAX_SCAN_WORKERS}")
    target, target_info = _checked_path_info(path)
    target_is_file = stat.S_ISREG(target_info.st_mode)
    if not target_is_file and not stat.S_ISDIR(target_info.st_mode):
        raise ValueError("Select a regular file or directory")
    signatures, catalog = (load_managed_signatures() if signature_path is None
                           else (load_signatures(signature_path), {}))
    signatures_sha256 = make_signature_key(signatures)
    result: dict[str, Any] = {
        "schema": 1, "kind": "antivirus-scan", "path": str(target),
        "started_at": utc_now(), "finished_at": None,
        "limits": {"max_file_bytes": max_bytes, "max_files": max_files,
                   "max_entries": max_files * 2 if max_files is not None else None, "workers": workers,
                   "profile": profile, "inspection": {**asdict(depth_limits), "inline_bytes": buffer_limit}},
        "engine": {"provider": "AntiOS Engine", "available": False,
                   "signatures": len(signatures), "signature_path": str(signature_path or ""),
                   "signature_source": "local-file" if signature_path is not None else "signed-catalog",
                   "signatures_sha256": signatures_sha256,
                   "inspection_profile": profile,
                   **catalog},
        "summary": {"files_seen": 0, "entries_seen": 0, "files_scanned": 0, "provider_scanned": 0,
                    "bytes_scanned": 0, "cache_hits": 0, "threats": 0, "reviews": 0, "skipped": 0,
                    "errors": 0, "cancelled": False, "limit_reached": False},
        "findings": [], "issues": [],
        "coverage": "limited", "verdict": "incomplete",
        "coverage_contract": {"status": "limited", "file_gaps": {}},
    }
    if checkpoint:
        checkpoint(result)
    summary = result["summary"]
    provider = None
    try:
        provider = provider_factory()
        result["engine"]["available"] = True
        result["engine"].update(getattr(provider, "metadata", {}))
    except (OSError, RuntimeError) as exc:
        result["engine"]["detail"] = str(exc)

    exclusions = tuple(Path(os.path.abspath(p)) for p in excluded_paths)
    stopped = cancelled or (lambda: False)

    def issue(item: Path, reason: str, *, error: bool = False) -> None:
        summary["errors" if error else "skipped"] += 1
        if len(result["issues"]) < MAX_DETAILS:
            result["issues"].append({"path": str(item), "reason": reason, "error": error})

    def exclude(item: Path) -> bool:
        return any(item == root or root in item.parents for root in exclusions)

    def candidates():
        ancestors = tuple(reversed(target.parents))
        if target_is_file:
            yield target, ancestors
            return
        # Keep one iterator per active ancestor. A drive with many sibling
        # directories never needs a drive-sized list of pending paths.
        stack = []
        def children(folder):
            with os.scandir(checked_path(folder)) as entries:
                yield from entries

        def descend(folder, parents):
            stack.append((folder, parents + (folder,), children(folder)))
        descend(target, ancestors)
        try:
            while stack and not stopped():
                folder, ancestors, entries = stack[-1]
                try:
                    entry = next(entries)
                except (StopIteration, OSError, ValueError) as exc:
                    if not isinstance(exc, StopIteration):
                        issue(folder, str(exc), error=True)
                    stack.pop()
                    entries.close()
                    continue
                if max_files is not None and summary["entries_seen"] >= max_files * 2:
                    summary["limit_reached"] = True
                    return
                summary["entries_seen"] += 1
                item = Path(entry.path)
                if exclude(item):
                    issue(item, "quarantine-excluded")
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    issue(item, str(exc), error=True)
                    continue
                if is_link(info):
                    issue(item, "link-or-reparse-point")
                elif stat.S_ISDIR(info.st_mode):
                    descend(item, ancestors)
                else:
                    yield item, ancestors
        finally:
            for _folder, _ancestors, entries in stack:
                entries.close()

    provider_failed = threading.Event()
    provider_probed = threading.Event()
    initial_probe = threading.Lock()
    cache = None
    cache_engine = ""
    cache_allowed = bool(
        use_cache and cache_path and provider is not None
        and result["engine"].get("database_freshness") == "local"
    )
    if cache_allowed:
        try:
            cache = ScanCache(cache_path)
            cache_engine = make_engine_key(result["engine"])
            result["engine"]["cache"] = "enabled"
        except (OSError, sqlite3.Error) as exc:
            result["engine"]["cache"] = "unavailable"
            result["engine"]["cache_detail"] = str(exc)[:300]
    else:
        result["engine"]["cache"] = "disabled"

    effective_workers = min(workers, 2) if provider is not None else 1
    if type(provider) is AntiOSEngine:
        effective_workers = min(workers, os.cpu_count() or 1)
    if target_is_file:
        effective_workers = 1
    large_slots = threading.BoundedSemaphore(1 if profile == "light" else 2)
    result["limits"]["effective_workers"] = effective_workers
    result["engine"]["limited_results"] = 0

    def apply_outcome(outcome: dict) -> None:
        item = outcome["item"]
        if outcome.get("issue"):
            issue(item, outcome["issue"], error=bool(outcome.get("error")))
            return
        summary["files_scanned"] += 1
        summary["bytes_scanned"] += outcome["size"]
        if outcome.get("provider_scanned"):
            summary["provider_scanned"] += 1
        if outcome.get("cached"):
            summary["cache_hits"] += 1
            return
        if outcome.get("provider_error"):
            issue(item, outcome["provider_error"], error=True)
            result["engine"]["detail"] = outcome["provider_error"]
            result["engine"]["failed_during_scan"] = True
        coverage_gaps = outcome["coverage_gaps"]
        if coverage_gaps:
            result["engine"]["limited_results"] += 1
            counts = result["coverage_contract"]["file_gaps"]
            for code in coverage_gaps:
                counts[code] = counts.get(code, 0) + 1
        coverage_detail = outcome["coverage_detail"]
        if outcome.get("file_engine_error"):
            issue(item, "Scan engine could not finish this file: " + outcome["file_engine_error"], error=True)
        finding = outcome.get("finding")
        if finding:
            finding.update(
                path=str(item),
                sha256=outcome["sha256"],
                size=outcome["size"],
                fingerprint=list(fingerprint(outcome["info"])),
            )
            if coverage_gaps:
                finding.update(detail=coverage_detail, coverage_gaps=coverage_gaps)
            summary["threats" if finding["kind"] == "threat" else "reviews"] += 1
            result["findings"].append(finding)
        elif coverage_gaps and len(result["issues"]) < MAX_DETAILS:
            result["issues"].append({"path": str(item), "reason": coverage_detail, "error": False,
                                     "coverage_gaps": coverage_gaps})
        elif (cache is not None and outcome.get("provider_scanned")
              and not coverage_gaps and not outcome.get("provider_error")
              and outcome["size"] <= inline_limit):
            try:
                cache.put(
                    item, outcome["info"], cache_engine, signatures_sha256, outcome["sha256"]
                )
            except (OSError, sqlite3.Error):
                pass

    def scan_one(candidate: tuple[Path, tuple[Path, ...], str | None]) -> dict:
        item, ancestors, cached_digest = candidate
        try:
            if stopped():
                return {"item": item, "issue": "cancelled"}
            # Reuse the path objects for siblings. Every ancestor is still
            # checked again before opening each file.
            info = _checked_absolute_path_info(item, ancestors)
            if not stat.S_ISREG(info.st_mode):
                return {"item": item, "issue": "not-a-regular-file"}
            if max_bytes is not None and info.st_size > max_bytes:
                return {"item": item, "issue": "file-size-limit"}
            with (large_slots if info.st_size > 16 * 1024 * 1024 else nullcontext()):
                if stopped():
                    return {"item": item, "issue": "cancelled"}
                if info.st_size > inline_limit:
                    return _scan_large_file(item, info, provider, signatures, stopped)
                return scan_buffered(item, info, cached_digest)
        except (OSError, ValueError) as exc:
            return {"item": item, "issue": str(exc), "error": True}

    def scan_buffered(item, info, cached_digest) -> dict:
        content, info = _read_checked_file(item, info, buffer_limit)
        digest = hashlib.sha256(content).hexdigest()
        # A cache hint only applies to the exact bytes of this verified snapshot.
        if digest == cached_digest:
            return {"item": item, "size": len(content), "provider_scanned": True, "cached": True}
        label = signatures.get(digest)
        if label is None and 68 <= len(content) <= 128:
            if hashlib.sha256(content.rstrip(b" \t\r\n\x1a")).hexdigest() == EICAR_SHA256:
                label = signatures[EICAR_SHA256]
        outcome = None
        provider_error = None
        if provider is not None:
            # Only the first real inspection is serialized. Cache validation can
            # proceed in parallel even when every file has a cache hint.
            with (nullcontext() if provider_probed.is_set() else initial_probe):
                if not provider_failed.is_set():
                    try:
                        value = (provider.scan_with_digest(content, str(item), digest)
                                 if hasattr(provider, "scan_with_digest")
                                 else provider.scan(content, str(item)))
                        if not isinstance(value, ScanOutcome) or value.kind not in (None, "review", "threat"):
                            raise OSError("AntiOS Engine returned an invalid result")
                        outcome = value
                    except (OSError, RuntimeError) as exc:
                        provider_failed.set()
                        provider_error = str(exc)
                    if not provider_probed.is_set():
                        provider_probed.set()
        return {
            "item": item,
            "info": info,
            "size": len(content),
            "sha256": digest,
            "provider_error": provider_error,
            **_describe_inspection(outcome, label),
        }

    def cache_hint(item: Path) -> str | None:
        if cache is None:
            return None
        try:
            info = item.lstat()
            if info.st_size <= buffer_limit and stat.S_ISREG(info.st_mode) and not is_link(info):
                return cache.get(item, info, cache_engine, signatures_sha256)
        except (OSError, sqlite3.Error):
            pass
        return None

    def after_item() -> None:
        if checkpoint:
            checkpoint(result)
        if progress and (summary["files_seen"] == 1 or summary["files_seen"] % 25 == 0):
            progress(dict(summary))

    pending: list[tuple[Path, tuple[Path, ...], str | None]] = []
    executor = ThreadPoolExecutor(max_workers=effective_workers) if effective_workers > 1 else None
    try:
        def flush_pending() -> None:
            nonlocal pending
            if not pending:
                return
            if executor is None or provider_failed.is_set():
                outcomes = map(scan_one, pending)
            else:
                outcomes = executor.map(scan_one, pending)
            for outcome in outcomes:
                apply_outcome(outcome)
                after_item()
            pending = []

        for item, ancestors in candidates():
            if stopped():
                break
            if max_files is not None and summary["files_seen"] >= max_files:
                summary["limit_reached"] = True
                break
            summary["files_seen"] += 1
            if exclude(item):
                issue(item, "quarantine-excluded")
                after_item()
                continue
            pending.append((item, ancestors, cache_hint(item)))
            if len(pending) >= effective_workers * 4:
                flush_pending()
        flush_pending()
        summary["cancelled"] = stopped()
    finally:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
        if provider is not None:
            provider.close()
        if cache is not None:
            try:
                cache.close()
            except (OSError, sqlite3.Error):
                pass
    finalize_scan_result(result)
    if progress:
        progress(dict(summary))
    if checkpoint:
        checkpoint(result)
    return result


def render_antivirus_scan(result: dict) -> str:
    summary = result["summary"]
    lines = ["AntiOS on-demand antivirus scan", f"Path: {result['path']}",
             f"Engine: {result['engine'].get('provider', 'unknown')}",
             f"Verdict: {result['verdict']}; coverage: {result['coverage']}",
             f"Scanned: {summary['files_scanned']}; threats: {summary['threats']}; "
             f"review: {summary['reviews']}; skipped: {summary['skipped']}; errors: {summary['errors']}"]
    limits = result.get("limits", {})
    if "profile" in limits and "effective_workers" in limits:
        lines.append(f"Profile: {limits['profile']}; workers: {limits['effective_workers']}")
    if "decision" in result:
        dimensions = result["decision"]["dimensions"]
        lines.append("Decision: " + ", ".join(f"{key}={value}" for key, value in dimensions.items()))
    for key in ("version", "database_freshness", "signature_source", "signature_catalog_version",
                "signature_catalog_status", "signature_bundled_supplement_entries",
                "signature_catalog_warning", "detail"):
        if key in result["engine"]:
            lines.append(f"{key}: {result['engine'][key]}")
    lines.extend(f"{f['kind']}: {f['name']} | {f['path']}" for f in result["findings"])
    lines.extend(f"issue: {item['reason']} | {item['path']}" for item in result["issues"])
    return "\n".join(lines)
