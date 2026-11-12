"""Explicit, reversible, current-user DPAPI quarantine for confirmed findings."""
from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
import json
import os
import re
import subprocess

from .windows_process import hidden_process_kwargs, system_executable
import uuid
from pathlib import Path
from typing import Protocol

from .antivirus import checked_path, fingerprint, read_regular, utc_now

MAX_ITEM_BYTES = 256 * 1024 * 1024
MAX_SEALED_BYTES = MAX_ITEM_BYTES * 2


def default_quarantine_path() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local") / "AntiOS/Quarantine"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "antios/quarantine"


class Protector(Protocol):
    def protect(self, content: bytes) -> bytes: ...
    def unprotect(self, content: bytes) -> bytes: ...


class DPAPIProtector:
    """Payload and metadata are authenticated together, without a plaintext key."""
    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Encrypted quarantine requires Windows DPAPI")
        self.crypt = ctypes.WinDLL("crypt32.dll", use_last_error=True, winmode=0x800)
        self.kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)

        class Blob(ctypes.Structure):
            _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]

        self.Blob = Blob
        blob_ptr = ctypes.POINTER(Blob)
        self.crypt.CryptProtectData.argtypes = [blob_ptr, ctypes.c_wchar_p, blob_ptr,
                                              ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_uint32, blob_ptr]
        self.crypt.CryptUnprotectData.argtypes = [blob_ptr, ctypes.c_void_p, blob_ptr,
                                                ctypes.c_void_p, ctypes.c_void_p,
                                                ctypes.c_uint32, blob_ptr]
        self.crypt.CryptProtectData.restype = ctypes.c_int
        self.crypt.CryptUnprotectData.restype = ctypes.c_int
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.LocalFree.restype = ctypes.c_void_p

    def _transform(self, content: bytes, *, encrypt: bool) -> bytes:
        buffer = ctypes.create_string_buffer(content)
        source = self.Blob(len(content), ctypes.cast(buffer, ctypes.c_void_p))
        output = self.Blob()
        fn = self.crypt.CryptProtectData if encrypt else self.crypt.CryptUnprotectData
        if not fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(output.data, output.size)
        finally:
            self.kernel.LocalFree(output.data)

    def protect(self, content: bytes) -> bytes:
        return self._transform(content, encrypt=True)

    def unprotect(self, content: bytes) -> bytes:
        return self._transform(content, encrypt=False)


def _current_windows_sid() -> str:
    if os.name != "nt":
        raise OSError("Windows SID lookup requires Windows")
    whoami = system_executable("whoami.exe")
    result = subprocess.run(
        [str(whoami), "/user", "/fo", "csv", "/nh"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="ascii", errors="replace",
        timeout=5,
        **hidden_process_kwargs(),
    )
    if result.returncode != 0:
        raise OSError((result.stderr or "Unable to resolve current Windows SID").strip())
    rows = list(csv.reader(result.stdout.splitlines()))
    if not rows or len(rows[0]) < 2 or not re.fullmatch(r"S-1-[0-9-]+", rows[0][1].strip()):
        raise OSError("Unable to parse current Windows SID")
    return rows[0][1].strip()


def _harden_windows_directory(path: Path) -> None:
    """Remove inherited access and restrict the vault to user/SYSTEM/admins."""
    if os.name != "nt":
        return
    sid = _current_windows_sid()
    icacls = system_executable("icacls.exe")
    grants = (
        f"*{sid}:(OI)(CI)F",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
    )
    result = subprocess.run(
        [str(icacls), str(path), "/inheritance:r", "/grant:r", *grants, "/t", "/c"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        **hidden_process_kwargs(),
    )
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "Failed to harden quarantine ACL").strip())


def _move_without_overwrite(source: Path, target: Path) -> None:
    if os.name == "nt":
        # Windows rename refuses an existing destination.
        os.rename(source, target)
    else:
        os.link(source, target, follow_symlinks=False)
        source.unlink()


class Quarantine:
    def __init__(self, root: str | Path | None = None, *, protector: Protector | None = None) -> None:
        self.root = Path(os.path.abspath(Path(root) if root else default_quarantine_path()))
        self.protector = protector if protector is not None else DPAPIProtector()

    def _root(self, *, create: bool = False) -> Path:
        # Validate existing ancestors before creating anything through them.
        ancestor = self.root
        while not ancestor.exists():
            if ancestor.is_symlink():
                raise ValueError("Quarantine directory must not be a symbolic link")
            ancestor = ancestor.parent
        checked_path(ancestor)
        if create:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            _harden_windows_directory(self.root)
        root = checked_path(self.root)
        if not root.is_dir():
            raise ValueError("Quarantine location must be a directory")
        return root

    def _item_path(self, item_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", item_id):
            raise ValueError("Invalid quarantine item ID")
        return self._root() / (item_id + ".aq")

    def _read(self, item_id: str) -> tuple[dict, bytes]:
        sealed, _info = read_regular(self._item_path(item_id), MAX_SEALED_BYTES)
        data = json.loads(self.protector.unprotect(sealed))
        if not isinstance(data, dict) or data.get("schema") != 1 or data.get("id") != item_id:
            raise ValueError("Invalid quarantine record")
        original = data.get("original_path")
        digest = data.get("sha256")
        if not isinstance(original, str) or not Path(original).is_absolute():
            raise ValueError("Invalid original path")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid quarantine digest")
        try:
            content = base64.b64decode(data["payload"], validate=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Invalid quarantine payload") from exc
        if len(content) > MAX_ITEM_BYTES or len(content) != data.get("size"):
            raise ValueError("Invalid quarantine size")
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("Quarantine integrity check failed")
        return data, content

    def list_items(self) -> list[dict]:
        if not self.root.exists() and not self.root.is_symlink():
            return []
        items = []
        for path in sorted(self._root().glob("*.aq")):
            try:
                data, _content = self._read(path.stem)
                items.append({key: value for key, value in data.items() if key != "payload"})
            except (OSError, ValueError, TypeError) as exc:
                items.append({"id": path.stem, "error": str(exc)})
        return items

    def verify_all(self) -> dict:
        if not self.root.exists() and not self.root.is_symlink():
            return {"checked": 0, "valid": 0, "corrupt": 0, "issues": []}
        checked = valid = corrupt = 0
        issues = []
        for path in sorted(self._root().glob("*.aq")):
            checked += 1
            try:
                self._read(path.stem)
                valid += 1
            except (OSError, ValueError, TypeError) as exc:
                corrupt += 1
                if len(issues) < 1000:
                    issues.append({"id": path.stem, "error": str(exc)})
        return {"checked": checked, "valid": valid, "corrupt": corrupt, "issues": issues}

    def _save_record(self, record: dict, *, new: bool) -> Path:
        sealed = self.protector.protect(json.dumps(record).encode("utf-8"))
        stored = self._root(create=True) / (record["id"] + ".aq")
        temporary = stored.with_name(stored.name + ".tmp-" + uuid.uuid4().hex)
        try:
            with temporary.open("xb") as stream:
                stream.write(sealed)
                stream.flush()
                os.fsync(stream.fileno())
            if new:
                _move_without_overwrite(temporary, stored)
            else:
                os.replace(temporary, stored)
        finally:
            if temporary.exists():
                temporary.unlink()
        return stored

    def add(self, finding: dict, *, dry_run: bool = True) -> dict:
        if finding.get("kind") != "threat":
            raise ValueError("Only a confirmed scan finding can be quarantined")
        source = checked_path(finding["path"])
        if source == self.root or self.root in source.parents:
            raise ValueError("Cannot quarantine quarantine storage")
        content, info = read_regular(source, MAX_ITEM_BYTES)
        digest = hashlib.sha256(content).hexdigest()
        if digest != finding.get("sha256") or list(fingerprint(info)) != finding.get("fingerprint"):
            raise ValueError("File changed after scanning; rescan before quarantining")
        if info.st_nlink != 1:
            raise ValueError("Hard-linked files cannot be isolated safely")
        preview = {"dry_run": dry_run, "original_path": str(source), "sha256": digest,
                   "size": len(content), "name": finding.get("name", "Detected threat")}
        if dry_run:
            return preview
        item_id = uuid.uuid4().hex
        record = dict(preview, schema=1, id=item_id, captured_at=utc_now(), state="recovery-copy",
                      payload=base64.b64encode(content).decode("ascii"))
        del record["dry_run"]
        self._save_record(record, new=True)
        # Verify a durable, decryptable backup before touching the original.
        self._read(item_id)
        staged = source.with_name(".antios-isolate-" + item_id)
        _move_without_overwrite(source, staged)
        try:
            moved, moved_info = read_regular(staged, MAX_ITEM_BYTES)
            if hashlib.sha256(moved).hexdigest() != digest or fingerprint(moved_info) != fingerprint(info):
                raise ValueError("File changed during isolation; encrypted backup preserved")
            if moved_info.st_nlink != 1:
                raise ValueError("Hard link appeared during isolation; backup preserved")
            staged.unlink()
        except (OSError, ValueError) as exc:
            try:
                _move_without_overwrite(staged, source)
            except OSError:
                raise OSError(f"Isolation stopped; original remains at {staged}; backup ID {item_id}") from exc
            raise
        record["state"] = "isolated"
        try:
            self._save_record(record, new=False)
        except OSError as exc:
            raise OSError(f"File isolated; encrypted recovery copy preserved; backup ID {item_id}") from exc
        return {key: value for key, value in record.items() if key != "payload"}

    def restore(self, item_id: str, *, destination: str | Path | None = None, dry_run: bool = True) -> dict:
        data, content = self._read(item_id)
        target = Path(os.path.abspath(Path(destination).expanduser() if destination else Path(data["original_path"])))
        if target == self.root or self.root in target.parents:
            raise ValueError("Restore destination must be outside quarantine")
        checked_path(target.parent)
        if target.exists() or target.is_symlink():
            raise FileExistsError("Restore never overwrites an existing file")
        if os.name == "nt" and ":" in target.name:
            raise ValueError("Alternate data streams are not supported")
        if os.name == "nt" and getattr(os.path, "isreserved", lambda p: Path(p).is_reserved())(str(target)):
            raise ValueError("Windows device paths are not supported")
        preview = {"id": item_id, "destination": str(target), "dry_run": dry_run}
        if dry_run:
            return preview
        # Exclusive creation prevents races from becoming overwrites.
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        restored, _info = read_regular(target, MAX_ITEM_BYTES)
        if hashlib.sha256(restored).hexdigest() != data["sha256"]:
            raise ValueError("Restored file changed; encrypted backup preserved")
        self._item_path(item_id).unlink()
        return preview
