from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

ProgressCallback = Callable[[dict[str, Any]], None]
CancelCallback = Callable[[], bool]

ARCHIVE_INSTALLER_EXTENSIONS = {
    ".7z",
    ".appx",
    ".appxbundle",
    ".cab",
    ".iso",
    ".msi",
    ".msix",
    ".msixbundle",
    ".rar",
    ".tar",
    ".tgz",
    ".zip",
}

DEFAULT_OLD_DAYS = 180
DEFAULT_LARGE_BYTES = 500 * 1024 * 1024
DEFAULT_DUPLICATE_MIN_BYTES = 1 * 1024 * 1024
QUICK_HASH_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAX_SCAN_FILES = 200_000
MAX_SCAN_ENTRIES = 400_000


@dataclass(frozen=True)
class FileRecord:
    path: Path
    size: int
    modified: float
    modified_ns: int
    created_ns: int
    device: int
    inode: int

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def to_dict(self, *, now: float | None = None) -> dict[str, Any]:
        timestamp = time.time() if now is None else now
        age_days = max(0.0, (timestamp - self.modified) / 86400)
        return {
            "path": str(self.path),
            "size_bytes": self.size,
            "modified": self.modified,
            "modified_ns": self.modified_ns,
            "created_ns": self.created_ns,
            "device": self.device,
            "inode": self.inode,
            "age_days": round(age_days, 1),
        }


def default_scan_path() -> Path:
    downloads = Path.home() / "Downloads"
    return downloads if downloads.is_dir() else Path.home()


def _iter_files(
    root: Path,
    *,
    progress: ProgressCallback | None = None,
    cancelled: CancelCallback | None = None,
) -> tuple[list[FileRecord], list[str], bool]:
    records: list[FileRecord] = []
    errors: list[str] = []
    stack = [root]
    scanned_dirs = 0
    entries_seen = 0
    limit_reached = False

    while stack:
        if cancelled and cancelled():
            break

        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > MAX_SCAN_ENTRIES or len(records) >= MAX_SCAN_FILES:
                        limit_reached = True
                        errors.append('Storage scan reached bounded entry/file limit; select a smaller folder')
                        break
                    if cancelled and cancelled():
                        break
                    try:
                        if entry.is_symlink() or (hasattr(entry, 'is_junction') and entry.is_junction()):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        path = Path(entry.path)
                        # Windows DirEntry.stat can expose a different file-ID
                        # view than the Path/lstat call used immediately before
                        # deletion. Capture and verify with the same API family.
                        info = (
                            path.lstat()
                            if os.name == "nt"
                            else entry.stat(follow_symlinks=False)
                        )
                        records.append(
                            FileRecord(
                                path=path,
                                size=int(info.st_size),
                                modified=float(info.st_mtime),
                                modified_ns=int(info.st_mtime_ns),
                                created_ns=int(info.st_ctime_ns),
                                device=int(info.st_dev),
                                inode=int(info.st_ino),
                            )
                        )
                        if progress and len(records) % 250 == 0:
                            progress({
                                "phase": "enumerating",
                                "files_scanned": len(records),
                                "directories_scanned": scanned_dirs,
                            })
                    except (OSError, PermissionError) as exc:
                        errors.append(f"{entry.path}: {exc}")
        except (OSError, PermissionError) as exc:
            errors.append(f"{current}: {exc}")
        scanned_dirs += 1
        if limit_reached:
            break

    return records, errors, limit_reached


def _quick_fingerprint(path: Path, size: int) -> str:
    digest = hashlib.sha256()
    digest.update(str(size).encode("ascii"))

    with path.open("rb") as handle:
        first = handle.read(QUICK_HASH_BYTES)
        digest.update(first)
        if size > QUICK_HASH_BYTES:
            seek_to = max(0, size - QUICK_HASH_BYTES)
            handle.seek(seek_to)
            digest.update(handle.read(QUICK_HASH_BYTES))

    return digest.hexdigest()


def _full_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _duplicate_groups(
    records: Iterable[FileRecord],
    *,
    min_size: int,
    progress: ProgressCallback | None = None,
    cancelled: CancelCallback | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    by_size: dict[int, list[FileRecord]] = {}

    for record in records:
        if record.size >= min_size:
            by_size.setdefault(record.size, []).append(record)

    same_size = [
        group
        for group in by_size.values()
        if len(group) > 1
    ]

    quick_groups: dict[tuple[int, str], list[FileRecord]] = {}
    hashed = 0
    for group in same_size:
        for record in group:
            if cancelled and cancelled():
                return [], errors
            try:
                quick = _quick_fingerprint(record.path, record.size)
                quick_groups.setdefault((record.size, quick), []).append(record)
            except (OSError, PermissionError) as exc:
                errors.append(f"{record.path}: {exc}")
            hashed += 1
            if progress and hashed % 25 == 0:
                progress({
                    "phase": "hashing",
                    "files_hashed": hashed,
                })

    full_groups: dict[tuple[int, str], list[FileRecord]] = {}
    for group in quick_groups.values():
        if len(group) < 2:
            continue
        for record in group:
            if cancelled and cancelled():
                return [], errors
            try:
                digest = _full_hash(record.path)
                full_groups.setdefault((record.size, digest), []).append(record)
            except (OSError, PermissionError) as exc:
                errors.append(f"{record.path}: {exc}")
            hashed += 1
            if progress and hashed % 25 == 0:
                progress({
                    "phase": "hashing",
                    "files_hashed": hashed,
                })

    result: list[dict[str, Any]] = []
    for (size, digest), group in full_groups.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda item: str(item.path).casefold())
        # Hard links are names for one physical file, not independent copies.
        independent = len({(item.device, item.inode) for item in ordered})
        result.append({
            "size_bytes": size,
            "hash": digest,
            "count": len(ordered),
            "independent_files": independent,
            "reclaimable_bytes": size * max(0, independent - 1),
            "paths": [str(item.path) for item in ordered],
        })

    result.sort(
        key=lambda item: (
            -int(item["reclaimable_bytes"]),
            str(item["paths"][0]).casefold(),
        )
    )
    return result, errors


def scan_storage(
    root: str | os.PathLike[str],
    *,
    old_days: int = DEFAULT_OLD_DAYS,
    large_bytes: int = DEFAULT_LARGE_BYTES,
    duplicate_min_bytes: int = DEFAULT_DUPLICATE_MIN_BYTES,
    progress: ProgressCallback | None = None,
    cancelled: CancelCallback | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.exists():
        raise ValueError(f"Scan path does not exist: {base}")
    if not base.is_dir():
        raise ValueError(f"Scan path is not a directory: {base}")
    if old_days < 1:
        raise ValueError("old_days must be at least 1")
    if large_bytes < 1:
        raise ValueError("large_bytes must be positive")
    if duplicate_min_bytes < 1:
        raise ValueError("duplicate_min_bytes must be positive")

    timestamp = time.time() if now is None else now

    if progress:
        progress({"phase": "enumerating", "files_scanned": 0})

    records, errors, limit_reached = _iter_files(
        base,
        progress=progress,
        cancelled=cancelled,
    )

    if cancelled and cancelled():
        return {
            "root": str(base),
            "cancelled": True,
            "limit_reached": limit_reached,
            "summary": {
                "files_scanned": len(records),
                "bytes_scanned": sum(item.size for item in records),
            },
            "duplicates": [],
            "old_large_files": [],
            "installer_archives": [],
            "empty_files": [],
            "errors": errors,
        }

    old_cutoff = timestamp - (old_days * 86400)
    old_large = [
        record
        for record in records
        if record.size >= large_bytes and record.modified <= old_cutoff
    ]
    old_large.sort(key=lambda item: (-item.size, item.modified, str(item.path).casefold()))

    installer_archives = [
        record
        for record in records
        if record.suffix in ARCHIVE_INSTALLER_EXTENSIONS
    ]
    installer_archives.sort(key=lambda item: (-item.size, str(item.path).casefold()))

    empty = [record for record in records if record.size == 0]
    empty.sort(key=lambda item: str(item.path).casefold())

    duplicates, hash_errors = _duplicate_groups(
        records,
        min_size=duplicate_min_bytes,
        progress=progress,
        cancelled=cancelled,
    )
    errors.extend(hash_errors)

    candidate_paths = {
        str(path)
        for group in duplicates
        for path in group.get("paths", [])
    }
    candidate_paths.update(str(item.path) for item in old_large)
    candidate_paths.update(str(item.path) for item in installer_archives)
    candidate_paths.update(str(item.path) for item in empty)
    snapshots = {
        str(record.path): {
            "size_bytes": record.size,
            "modified_ns": record.modified_ns,
            "created_ns": record.created_ns,
            "device": record.device,
            "inode": record.inode,
        }
        for record in records
        if str(record.path) in candidate_paths
    }

    result = {
        "root": str(base),
        "cancelled": bool(cancelled and cancelled()),
        "limit_reached": limit_reached,
        "rules": {
            "old_days": old_days,
            "large_bytes": large_bytes,
            "duplicate_min_bytes": duplicate_min_bytes,
            "unused_claim": False,
            "note": (
                "Old-file results use last-modified time. AntiOS does not claim "
                "a file is unused because Windows last-access timestamps can be "
                "disabled, delayed, or unreliable."
            ),
        },
        "summary": {
            "files_scanned": len(records),
            "bytes_scanned": sum(item.size for item in records),
            "duplicate_groups": len(duplicates),
            "duplicate_files": sum(int(item["count"]) for item in duplicates),
            "duplicate_reclaimable_bytes": sum(
                int(item["reclaimable_bytes"]) for item in duplicates
            ),
            "old_large_files": len(old_large),
            "installer_archives": len(installer_archives),
            "empty_files": len(empty),
            "errors": len(errors),
        },
        "duplicates": duplicates,
        "old_large_files": [item.to_dict(now=timestamp) for item in old_large],
        "installer_archives": [
            item.to_dict(now=timestamp) for item in installer_archives
        ],
        "empty_files": [item.to_dict(now=timestamp) for item in empty],
        "errors": errors[:200],
        "candidate_snapshots": snapshots,
    }

    if progress:
        progress({
            "phase": "done",
            "files_scanned": len(records),
            "duplicate_groups": len(duplicates),
        })

    return result



def default_cleanup_backup_path() -> Path:
    documents = Path.home() / "Documents"
    root = documents if documents.is_dir() else Path.home()
    return root / "AntiOS Backups" / "Storage Cleanup"


def _lexical_path(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(Path(path).expanduser()))


def _same_snapshot(info: os.stat_result, snapshot: dict[str, Any]) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not bool(getattr(info, "st_file_attributes", 0) & 0x400)
        and int(info.st_size) == int(snapshot.get("size_bytes", -1))
        and int(info.st_mtime_ns) == int(snapshot.get("modified_ns", -1))
        and int(info.st_ctime_ns) == int(snapshot.get("created_ns", -1))
        and int(info.st_dev) == int(snapshot.get("device", -1))
        and int(info.st_ino) == int(snapshot.get("inode", -1))
    )


def _write_cleanup_manifest(folder: Path, payload: dict[str, Any]) -> None:
    temporary = folder / "manifest.json.tmp"
    final = folder / "manifest.json"
    # Never follow a pre-created manifest.json.tmp symlink into another file.
    # Repeated writes are atomic because os.replace() removes our own staged
    # file on success; a foreign/stale temp file is an explicit error.
    owned_temp = False
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            owned_temp = True
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, final)
    except (OSError, ValueError, TypeError):
        # Only unlink a temporary file created by this write. Do not delete
        # a foreign path that made the exclusive "x" creation fail.
        if owned_temp:
            temporary.unlink(missing_ok=True)
        raise


def cleanup_files(
    scan_result: dict[str, Any],
    selected_paths: Iterable[str | os.PathLike[str]],
    *,
    mode: str,
    backup_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Delete selected scan candidates permanently or after a verified backup.

    Only paths present in the scan's candidate snapshot may be acted on. Every
    file is revalidated immediately before the action. Backup mode copies into a
    unique session directory, verifies SHA-256, then deletes the original.
    """
    if mode not in {"delete", "backup"}:
        raise ValueError("cleanup mode must be 'delete' or 'backup'")
    if scan_result.get("limit_reached") or scan_result.get("cancelled"):
        raise ValueError("Cleanup requires a completed, bounded scan")

    root = _lexical_path(scan_result.get("root", ""))
    snapshots = scan_result.get("candidate_snapshots")
    if not isinstance(snapshots, dict):
        raise ValueError("cleanup scan does not contain candidate snapshots")

    requested: list[Path] = []
    seen: set[str] = set()
    for raw in selected_paths:
        target = _lexical_path(raw)
        key = str(target)
        if key in seen:
            continue
        seen.add(key)
        if key not in snapshots:
            raise ValueError(f"File is not an approved cleanup candidate: {target}")
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Cleanup candidate is outside the scanned root: {target}") from exc
        requested.append(target)

    if not requested:
        raise ValueError("Select at least one cleanup candidate")

    backup_dir: Path | None = None
    manifest: dict[str, Any] | None = None
    if mode == "backup":
        base = _lexical_path(backup_root or default_cleanup_backup_path())
        base.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        backup_dir = base / f"antios-cleanup-{stamp}-{uuid.uuid4().hex[:8]}"
        backup_dir.mkdir(parents=False, exist_ok=False)
        manifest = {
            "schema": 1,
            "kind": "antios-storage-cleanup-backup",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scan_root": str(root),
            "items": [],
        }
        _write_cleanup_manifest(backup_dir, manifest)

    result: dict[str, Any] = {
        "schema": 1,
        "kind": "antios-storage-cleanup-action",
        "mode": mode,
        "requested": len(requested),
        "deleted": 0,
        "backed_up": 0,
        "bytes_freed": 0,  # Estimated net space reclaimed on source volume.
        "gross_deleted_bytes": 0,
        "backup_dir": str(backup_dir) if backup_dir else None,
        "items": [],
        "errors": [],
    }

    for target in requested:
        key = str(target)
        snapshot = snapshots[key]
        item = {"path": key, "size_bytes": int(snapshot.get("size_bytes", 0))}
        try:
            # Recheck parent reparse points before opening a cleanup candidate.
            from .antivirus import checked_path
            checked_path(target)
            before = target.lstat()
            if not _same_snapshot(before, snapshot):
                raise ValueError("file changed since the cleanup scan")

            if mode == "backup":
                assert backup_dir is not None and manifest is not None
                relative = target.relative_to(root)
                destination = backup_dir / "files" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                # Exclusive creation is essential: shutil.copy2() follows
                # a symlink inserted after an exists() check, potentially
                # overwriting an unrelated file before deleting the source.
                # "xb" fails closed even if a link appears at the last moment.
                with target.open("rb") as original_stream, destination.open("xb") as backup_stream:
                    shutil.copyfileobj(original_stream, backup_stream, HASH_CHUNK_BYTES)
                    backup_stream.flush()
                    os.fsync(backup_stream.fileno())
                after_copy = target.lstat()
                if not _same_snapshot(after_copy, snapshot):
                    destination.unlink(missing_ok=True)
                    raise ValueError("file changed while creating the backup")

                source_hash = _full_hash(target)
                backup_hash = _full_hash(destination)
                if source_hash != backup_hash:
                    destination.unlink(missing_ok=True)
                    raise OSError("backup verification failed")

                item.update(
                    backup_path=str(destination),
                    sha256=source_hash,
                )

            checked_path(target)
            before_delete = target.lstat()
            if not _same_snapshot(before_delete, snapshot):
                raise ValueError("file changed before deletion")

            manifest_index = None
            if mode == "backup":
                assert manifest is not None and backup_dir is not None
                manifest_entry = dict(item, status="verified-pending-delete")
                manifest["items"].append(manifest_entry)
                manifest_index = len(manifest["items"]) - 1
                # Persist recoverability before removing the source.
                _write_cleanup_manifest(backup_dir, manifest)
                result["backed_up"] += 1

            # Determine the destination volume BEFORE removing the original.
            # A failed stat must never turn a successful deletion into an
            # incorrectly reported "skipped" item.
            same_volume_backup = (
                mode == "backup" and destination.stat().st_dev == before_delete.st_dev
            )
            target.unlink()

            result["deleted"] += 1
            result["gross_deleted_bytes"] += int(snapshot.get("size_bytes", 0))
            # No space is reclaimed if hard links retain the data or the
            # verified backup occupies the same source volume.
            if before_delete.st_nlink == 1 and not same_volume_backup:
                result["bytes_freed"] += int(snapshot.get("size_bytes", 0))
            item["status"] = "deleted"
            if mode == "backup":
                assert manifest is not None and backup_dir is not None
                assert manifest_index is not None
                manifest["items"][manifest_index] = dict(item)
                try:
                    _write_cleanup_manifest(backup_dir, manifest)
                except OSError as exc:
                    # The already-persisted manifest still identifies a verified
                    # backup and original path. Report the stale status, but do
                    # not misreport a successfully deleted source as skipped.
                    result["errors"].append({
                        "path": key,
                        "error": f"backup manifest finalization failed: {exc}",
                    })
        except (OSError, ValueError) as exc:
            item["status"] = "skipped"
            item["error"] = str(exc)
            result["errors"].append({"path": key, "error": str(exc)})
        result["items"].append(item)

    if manifest is not None and backup_dir is not None:
        manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        manifest["deleted"] = result["deleted"]
        manifest["bytes_freed"] = result["bytes_freed"]
        manifest["errors"] = result["errors"]
        try:
            _write_cleanup_manifest(backup_dir, manifest)
        except OSError as exc:
            result["errors"].append({
                "path": str(backup_dir / "manifest.json"),
                "error": f"backup manifest finalization failed: {exc}",
            })

    return result


def format_bytes(value: int | float) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"


def render_storage_scan(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    lines = [
        "AntiOS storage scan",
        "===================",
        f"Path: {result.get('root', '')}",
        f"Files scanned: {summary.get('files_scanned', 0)}",
        f"Data scanned: {format_bytes(summary.get('bytes_scanned', 0))}",
        "",
        (
            f"Duplicate groups: {summary.get('duplicate_groups', 0)} "
            f"({format_bytes(summary.get('duplicate_reclaimable_bytes', 0))} "
            "potentially reclaimable)"
        ),
        f"Old large files: {summary.get('old_large_files', 0)}",
        f"Installer/archive candidates: {summary.get('installer_archives', 0)}",
        f"Empty files: {summary.get('empty_files', 0)}",
        "",
        "Note: old files are classified by last-modified time, not by a claim that they are unused.",
    ]

    duplicates = result.get("duplicates", [])
    if duplicates:
        lines.extend(["", "Duplicates:"])
        for group in duplicates[:20]:
            lines.append(
                f"- {format_bytes(group.get('size_bytes', 0))} × "
                f"{group.get('count', 0)}"
            )
            for path in group.get("paths", []):
                lines.append(f"    {path}")

    return "\n".join(lines)
