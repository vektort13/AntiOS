"""Bounded, opt-in file baselines. Not a Windows image or malware verdict.

Archives are ordinary unencrypted backups: keep a separate offline copy.
Restore exports into a fresh folder; manifest paths never become destinations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import zipfile
from typing import Callable
from contextlib import contextmanager
import struct
import ntpath
import re
import zlib
import lzma

from .antivirus import checked_path, read_regular

MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_MANIFEST = 8 * 1024 * 1024
MAX_ZIP_DIRECTORY = 2 * 1024 * 1024


class RecoveryLimitError(RuntimeError):
    pass


class RecoveryCancelled(RuntimeError):
    pass


def _checkpoint(cancelled: Callable[[], bool] | None, progress: Callable[[dict], None] | None,
                count: int, path: str) -> None:
    if cancelled and cancelled():
        raise RecoveryCancelled("Operation cancelled")
    if progress:
        progress({"files": count, "path": path})
    if cancelled and cancelled():
        raise RecoveryCancelled("Operation cancelled")


def system_targets() -> list[Path]:
    """A small core-file baseline, deliberately not a complete system image."""
    if os.name != "nt":
        raise ValueError("System baseline requires Windows")
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError("Cannot locate Windows directory")
    root = Path(buffer.value)
    return [root / path for path in (
        "explorer.exe", "System32/ntoskrnl.exe", "System32/ntdll.dll",
        "System32/kernel32.dll", "System32/services.exe", "System32/lsass.exe",
        "System32/drivers/etc/hosts",
    )]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_id(manifest: dict) -> str:
    return _digest(json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode("utf-8"))


@contextmanager
def _open_archive(path: Path):
    """Bound ZIP metadata before ZipFile allocates its central-directory objects.

Our sub-4GiB archives do not need ZIP64 or multi-disk support.
"""
    target = checked_path(path)
    with target.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_TOTAL + MAX_MANIFEST + MAX_ZIP_DIRECTORY:
            raise ValueError("Backup archive exceeds the input size limit")
        stream.seek(max(0, info.st_size - 65557))
        tail = stream.read(65557)
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or len(tail) - offset < 22:
            raise ValueError("Invalid backup ZIP footer")
        _, disk, central_disk, disk_count, count, central_size, central_offset, comment = struct.unpack(
            "<4s4H2LH", tail[offset:offset + 22])
        if (disk != 0 or central_disk != 0 or count != disk_count or count > MAX_ENTRIES + 1
                or central_size > MAX_ZIP_DIRECTORY or central_offset + central_size > info.st_size
                or offset + 22 + comment != len(tail)
                or tail[max(0, offset - 20):offset - 16] == b"PK\x06\x07"):
            raise ValueError("Unsupported or oversized backup ZIP directory")
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            yield archive


def _read_archive_entry(archive: zipfile.ZipFile, name: str) -> bytes:
    """Read one ZIP member while normalizing corrupt/unsupported compressed data."""
    try:
        return archive.read(name)
    except (zipfile.BadZipFile, zlib.error, lzma.LZMAError, OSError, EOFError,
            RuntimeError, NotImplementedError) as exc:
        raise ValueError(f"Cannot read backup archive entry: {name}") from exc


def _manifest(archive: zipfile.ZipFile) -> dict:
    names = archive.namelist()
    if len(names) > MAX_ENTRIES + 1 or len(names) != len(set(names)):
        raise ValueError("Invalid archive entry count or duplicate entries")
    names = set(names)
    if "manifest.json" not in names:
        raise ValueError("Missing recovery manifest")
    if archive.getinfo("manifest.json").file_size > MAX_MANIFEST:
        raise ValueError("Recovery manifest exceeds limit")
    data = json.loads(_read_archive_entry(archive, "manifest.json"))
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError("Unsupported recovery schema")
    entries = data.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError("Invalid recovery entries")
    paths = set()
    total = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError("Invalid recovery entry")
        path, size, digest = entry.get("path"), entry.get("size"), entry.get("sha256")
        if not isinstance(path, str) or not path or len(path) > 32768 or "\x00" in path:
            raise ValueError("Invalid original path")
        try:
            path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("Invalid original path Unicode") from exc
        if os.path.normcase(path) in paths:
            raise ValueError("Duplicate original path")
        paths.add(os.path.normcase(path))
        if type(size) is not int or not 0 <= size <= MAX_FILE:
            raise ValueError("Invalid file size")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid content digest")
        name = f"files/{index}.bin"
        if name not in names or archive.getinfo(name).file_size != size:
            raise ValueError("Missing content or size mismatch")
        total += size
    if total > MAX_TOTAL or len(names) != len(entries) + 1:
        raise ValueError("Archive exceeds limits or contains extra entries")
    return data


def _content(archive: zipfile.ZipFile, index: int, entry: dict) -> bytes:
    data = _read_archive_entry(archive, f"files/{index}.bin")
    if len(data) != entry["size"] or _digest(data) != entry["sha256"]:
        raise ValueError("Backup content failed integrity verification")
    return data


def inventory(source: Path, *, cancelled: Callable[[], bool] | None = None,
              progress: Callable[[dict], None] | None = None) -> dict:
    """Verify saved bytes and list them without accessing original file paths."""
    with _open_archive(source) as archive:
        manifest = _manifest(archive)
        for index, entry in enumerate(manifest["entries"]):
            _checkpoint(cancelled, progress, index, entry["path"])
            _content(archive, index, entry)
        _checkpoint(cancelled, progress, len(manifest["entries"]), "")
    return {"coverage": manifest.get("coverage", "unknown"), "archive_id": _manifest_id(manifest),
            "files": [dict(entry, index=index, state="saved")
                      for index, entry in enumerate(manifest["entries"])],
            "bytes": sum(entry["size"] for entry in manifest["entries"])}


def _local_original_path(original: str) -> Path:
    """Return a local absolute original path and reject network/device namespaces.

    Archive manifests are unauthenticated input. Inventory/export never dereference
    original paths; check() may do so only after this validation succeeds for every
    entry in the archive.
    """
    if os.name == "nt":
        value = original.replace("/", "\\")
        # UNC paths and Win32 device namespaces (\\?\, \\.\, named pipes)
        # must never be reached from an untrusted recovery manifest.
        if value.startswith("\\\\"):
            raise ValueError("Original path must be a local drive path")
        drive, tail = ntpath.splitdrive(value)
        if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\"):
            raise ValueError("Original path must be a local absolute path")
        for part in tail.split("\\"):
            if not part:
                continue
            trimmed = part.rstrip(" .")
            stem = trimmed.split(".", 1)[0].upper()
            if (part in {".", ".."} or not trimmed or trimmed != part or ":" in part
                    or stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                    or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem)):
                raise ValueError("Original path uses an unsafe Windows component")
        return Path(original)
    if not original.startswith("/") or original.startswith("//"):
        raise ValueError("Original path must be a local absolute path")
    return Path(original)


def _export_name(original: str) -> str:
    """Use only a portable basename; untrusted directories never reach disk."""
    name = ntpath.basename(original.replace("/", "\\"))
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f]', "_", name)
    # Strip direction controls which can visually disguise an extension.
    name = re.sub(r'[\u202a-\u202e\u2066-\u2069]', "", name).strip(" .")
    stem = name.split(".", 1)[0].rstrip(" .").upper()
    if (not name or len(name.encode("utf-8")) > 180 or stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
            or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem)):
        return "recovered.bin"
    return name


def create(paths: list[Path], destination: Path, *, previous: Path | None = None,
           expected_previous_id: str | None = None,
           cancelled: Callable[[], bool] | None = None,
           progress: Callable[[dict], None] | None = None) -> dict:
    """Create a new archive; extension preserves all previous baseline bytes."""
    destination = Path(os.path.abspath(destination))
    checked_path(destination.parent)
    entries: list[dict] = []
    errors: list[dict] = []
    seen: set[str] = set()
    total = 0
    visited = 0
    visited_directories: set[str] = set()
    _checkpoint(cancelled, progress, 0, "")
    # Exclusive creation: an existing backup must never be overwritten.
    with destination.open("xb") as output:
        try:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
                if previous is not None:
                    with _open_archive(previous) as old:
                        manifest = _manifest(old)
                        if expected_previous_id is not None and expected_previous_id != _manifest_id(manifest):
                            raise ValueError("Previous archive changed since it was listed; open it again before extending")
                        if manifest.get("coverage") != "selected-files":
                            errors.append({"path": str(previous), "error": "Previous baseline had incomplete coverage"})
                        for index, entry in enumerate(manifest["entries"]):
                            _checkpoint(cancelled, progress, len(entries), entry["path"])
                            archive.writestr(f"files/{index}.bin", _content(old, index, entry))
                            entries.append(entry)
                            seen.add(os.path.normcase(entry["path"]))
                            total += entry["size"]
                def visit(candidate: Path, depth: int = 0) -> None:
                    nonlocal total, visited
                    _checkpoint(cancelled, progress, len(entries), str(candidate))
                    visited += 1
                    if visited > MAX_ENTRIES or depth > 128:
                        raise RecoveryLimitError("Recovery traversal/entry limit reached; select smaller roots")
                    absolute = Path(os.path.abspath(candidate))
                    if absolute == destination or (previous and absolute == Path(os.path.abspath(previous))):
                        return
                    try:
                        target = checked_path(_local_original_path(str(absolute)))
                        info = target.lstat()
                    except (OSError, ValueError) as exc:
                        if len(errors) < 1000:
                            errors.append({"path": str(absolute), "error": str(exc)})
                        return
                    key = os.path.normcase(str(target))
                    if stat.S_ISDIR(info.st_mode):
                        if key in visited_directories:
                            return
                        visited_directories.add(key)
                        # Only enumeration errors are partial coverage. Output write
                        # errors must propagate and invalidate the entire new archive.
                        try:
                            with os.scandir(target) as children:
                                child_paths = []
                                for child in children:
                                    if len(child_paths) >= MAX_ENTRIES:
                                        raise RecoveryLimitError("Directory entry limit reached")
                                    child_paths.append(Path(child.path))
                        except OSError as exc:
                            if len(errors) < 1000:
                                errors.append({"path": str(absolute), "error": str(exc)})
                            return
                        for child in child_paths:
                            visit(child, depth + 1)
                        return
                    if key in seen:
                        return
                    if len(entries) >= MAX_ENTRIES:
                        raise RecoveryLimitError("Recovery entry limit reached")
                    try:
                        content, info = read_regular(target, MAX_FILE)
                    except (OSError, ValueError) as exc:
                        if len(errors) < 1000:
                            errors.append({"path": str(absolute), "error": str(exc)})
                        return
                    if total + len(content) > MAX_TOTAL:
                        raise RecoveryLimitError("Recovery byte limit reached; select smaller roots")
                    archive.writestr(f"files/{len(entries)}.bin", content)
                    entries.append({"path": str(target), "size": len(content),
                                    "sha256": _digest(content), "mtime_ns": info.st_mtime_ns})
                    seen.add(key)
                    total += len(content)
                for root in paths:
                    visit(root)
                _checkpoint(cancelled, progress, len(entries), "")
                manifest = {"schema": 1, "created_at": time.time(), "entries": entries,
                            "errors": errors, "coverage": "partial" if errors else "selected-files",
                            "trust": "user-selected baseline; not proof of malware-free state"}
                encoded = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
                if len(encoded) > MAX_MANIFEST:
                    raise ValueError("Recovery manifest exceeds limit")
                archive.writestr("manifest.json", encoded)
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            output.close()
            destination.unlink(missing_ok=True)
            raise
    return {"archive": str(destination), "files": len(entries), "bytes": total,
            "coverage": manifest["coverage"], "errors": errors}


def check(source: Path, *, cancelled: Callable[[], bool] | None = None,
          progress: Callable[[dict], None] | None = None) -> dict:
    results = []
    with _open_archive(source) as archive:
        manifest = _manifest(archive)
        entries = manifest["entries"]
        # Phase 1: verify every saved blob before dereferencing any path supplied
        # by the unauthenticated manifest. A corrupt later member must not allow
        # an earlier member to trigger filesystem/network/device access.
        for index, entry in enumerate(entries):
            _checkpoint(cancelled, progress, index, entry["path"])
            _content(archive, index, entry)
        # Phase 2: validate the complete path set before the first original read.
        originals = [_local_original_path(entry["path"]) for entry in entries]
        for index, (entry, original) in enumerate(zip(entries, originals)):
            _checkpoint(cancelled, progress, len(entries) + index, entry["path"])
            try:
                content, _ = read_regular(original, MAX_FILE)
                state = "unchanged" if _digest(content) == entry["sha256"] else "changed"
            except FileNotFoundError:
                state = "missing"
            except (OSError, ValueError):
                state = "unreadable"
            results.append({"path": entry["path"], "state": state, "index": index})
        _checkpoint(cancelled, progress, len(entries) * 2, "")
    return {"coverage": manifest.get("coverage", "unknown"), "files": results, "archive_id": _manifest_id(manifest),
            "note": "Changes are not malware verdicts; new files are not enumerated."}


def compare(before: Path, after: Path, *, cancelled: Callable[[], bool] | None = None,
            progress: Callable[[dict], None] | None = None) -> dict:
    """Compare verified saved bytes without opening original paths from either archive."""
    old = inventory(before, cancelled=cancelled, progress=progress)
    new = inventory(after, cancelled=cancelled, progress=progress)

    def indexed(items):
        result = {}
        for item in items:
            path = item["path"]
            key = ntpath.normcase(ntpath.normpath(path)) if ntpath.splitdrive(path)[0] else os.path.normcase(path)
            if key in result:
                raise ValueError("Ambiguous file paths in snapshot")
            result[key] = item
        return result

    left, right = indexed(old["files"]), indexed(new["files"])
    files = []
    counts = dict.fromkeys(("added", "removed", "changed", "unchanged"), 0)
    for key in sorted(left.keys() | right.keys()):
        previous, current = left.get(key), right.get(key)
        state = ("added" if previous is None else "removed" if current is None else
                 "unchanged" if previous["sha256"] == current["sha256"] else "changed")
        _checkpoint(cancelled, progress, len(files), (previous or current)["path"])
        counts[state] += 1
        files.append({"path": (previous or current)["path"], "state": state,
                      "index": previous["index"] if previous else None,
                      "before_size": previous["size"] if previous else None,
                      "after_size": current["size"] if current else None})
    return {"archive_id": old["archive_id"], "compared_id": new["archive_id"],
            "compared_archive": str(after), "files": files, "counts": counts,
            "coverage": "selected-files" if old["coverage"] == new["coverage"] == "selected-files" else "partial",
            "note": "Comparison of saved snapshots only. Changes do not mean infection."}


def export(source: Path, destination: Path, *, cancelled: Callable[[], bool] | None = None,
           progress: Callable[[dict], None] | None = None,
           indices: list[int] | None = None, named: bool = False,
           expected_id: str | None = None) -> dict:
    """Verify every blob before creating a fresh export directory; no in-place rollback."""
    destination = Path(os.path.abspath(destination))
    checked_path(destination.parent)
    if os.path.lexists(destination):
        raise FileExistsError(str(destination))
    with _open_archive(source) as archive:
        manifest = _manifest(archive)
        if expected_id is not None and expected_id != _manifest_id(manifest):
            raise ValueError("Archive changed since it was listed; open it again before recovering")
        selected = list(range(len(manifest["entries"]))) if indices is None else list(indices)
        if indices is not None and (not selected or len(selected) > MAX_ENTRIES
                or any(type(index) is not int or not 0 <= index < len(manifest["entries"]) for index in selected)
                or len(set(selected)) != len(selected)):
            raise ValueError("Select unique valid backup entry indices")
        selected.sort()
        for index, entry in enumerate(manifest["entries"]):
            _checkpoint(cancelled, progress, index, entry["path"])
            _content(archive, index, entry)
        destination.mkdir()  # must not exist, including symlinks
        checked_path(destination)
        created = []
        directories = []
        recovered = []
        try:
            for count, index in enumerate(selected):
                entry = manifest["entries"][index]
                _checkpoint(cancelled, progress, count, entry["path"])
                relative = f"{index:05d}/{_export_name(entry['path'])}" if named else f"{index}.bin"
                path = destination / relative
                if named:
                    path.parent.mkdir()
                    directories.append(path.parent)
                with path.open("xb") as output:
                    created.append(path)
                    output.write(_content(archive, index, entry))
                    output.flush()
                    os.fsync(output.fileno())
                recovered.append({"index": index, "original_path": entry["path"],
                                  "relative_path": relative, "sha256": entry["sha256"], "size": entry["size"]})
            _checkpoint(cancelled, progress, len(selected), "")
            report = {"schema": 1, "files": recovered,
                      "note": "Recovered bytes are not a malware-free verdict. Scan before reuse."}
            path = destination / "recovery-report.json"
            with path.open("x", encoding="utf-8") as output:
                created.append(path)
                json.dump(report, output, ensure_ascii=False, indent=2)
                output.flush()
                os.fsync(output.fileno())
            # Preserve the legacy full numbered export. A selected/named export
            # reports only recovered files, not private paths of unselected files.
            if not named and indices is None:
                path = destination / "manifest.json"
                with path.open("x", encoding="utf-8") as output:
                    created.append(path)
                    json.dump(manifest, output, ensure_ascii=False, indent=2)
                    output.flush()
                    os.fsync(output.fileno())
        except BaseException:
            # Remove only files created by this call, never unrelated data.
            # A cleanup failure remains visible as an I/O error.
            checked_path(destination)
            for path in reversed(created):
                path.unlink()
            for path in reversed(directories):
                path.rmdir()
            destination.rmdir()
            raise
    return {"directory": str(destination), "files": len(selected), "named": named,
            "note": "Exported paths are mapped in recovery-report.json. Scan before reuse."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="antios recovery")
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("create", "extend"):
        command = commands.add_parser(action)
        command.add_argument("archive", type=Path)
        command.add_argument("paths", nargs="*", type=Path)
        command.add_argument("--system", action="store_true", help="Include seven Windows core files, not a system image")
        if action == "extend":
            command.add_argument("--previous", type=Path, required=True)
            command.add_argument("--expected-previous-id", help="Reject a previous archive changed since it was listed")
    command = commands.add_parser("check")
    command.add_argument("archive", type=Path)
    command = commands.add_parser("list")
    command.add_argument("archive", type=Path)
    command = commands.add_parser("export")
    command.add_argument("archive", type=Path)
    command.add_argument("destination", type=Path)
    command.add_argument("--entry", type=int, action="append", help="Recover only this zero-based index; repeat to select more")
    command.add_argument("--named", action="store_true", help="Keep safe filenames in separate numbered folders")
    args = parser.parse_args(argv)
    try:
        if args.action in {"create", "extend"}:
            paths = args.paths + (system_targets() if args.system else [])
            if not paths:
                raise ValueError("Select at least one file/folder or --system")
            result = create(paths, args.archive, previous=getattr(args, "previous", None),
                            expected_previous_id=getattr(args, "expected_previous_id", None))
            code = 2 if result["errors"] else 0
        elif args.action == "check":
            result = check(args.archive)
            code = 2 if result["coverage"] != "selected-files" or any(x["state"] != "unchanged" for x in result["files"]) else 0
        elif args.action == "list":
            result = inventory(args.archive)
            code = 2 if result["coverage"] != "selected-files" else 0
        else:
            result = export(args.archive, args.destination, indices=args.entry, named=args.named)
            code = 0
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return code
