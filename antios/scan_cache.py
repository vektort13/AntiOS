"""Bounded persistent cache for clean antivirus results.

Only unchanged files scanned clean by a trusted/current engine are cached.  The
engine/database identity and the local signature set are part of the key, so an
engine/signature update invalidates old entries without destructive migrations.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import time

MAX_ROWS = 50_000
MAX_AGE_SECONDS = 30 * 24 * 60 * 60


def default_scan_cache_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
        return root / "AntiOS" / "scan-cache.sqlite3"
    root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return root / "antios" / "scan-cache.sqlite3"


def signature_key(signatures: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for key, value in sorted(signatures.items()):
        digest.update(key.encode("ascii"))
        digest.update(b"\0")
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def engine_key(metadata: dict) -> str:
    parts = (
        str(metadata.get("version", "")),
        str(metadata.get("database_freshness", "")),
        str(metadata.get("peer_identity", "")),
        str(metadata.get("inspection_profile", "balanced")),
    )
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


class ScanCache:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS clean_files (
                path TEXT NOT NULL,
                device INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                engine_key TEXT NOT NULL,
                signature_key TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                last_used INTEGER NOT NULL,
                PRIMARY KEY(path, device, inode, size, mtime_ns, engine_key, signature_key)
            )
            """
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS clean_files_last_used ON clean_files(last_used)")
        self.db.commit()

    @staticmethod
    def _identity(path: Path, info: os.stat_result) -> tuple:
        return (
            os.path.normcase(os.path.abspath(path)),
            f"d:{int(info.st_dev):x}",
            f"i:{int(info.st_ino):x}",
            int(info.st_size),
            int(info.st_mtime_ns),
        )

    def get(self, path: Path, info: os.stat_result, engine: str, signatures: str) -> str | None:
        row = self.db.execute(
            """
            SELECT sha256 FROM clean_files
            WHERE path=? AND device=? AND inode=? AND size=? AND mtime_ns=?
              AND engine_key=? AND signature_key=?
            """,
            (*self._identity(path, info), engine, signatures),
        ).fetchone()
        if not row:
            return None
        self.db.execute(
            """
            UPDATE clean_files SET last_used=?
            WHERE path=? AND device=? AND inode=? AND size=? AND mtime_ns=?
              AND engine_key=? AND signature_key=?
            """,
            (int(time.time()), *self._identity(path, info), engine, signatures),
        )
        return str(row[0])

    def put(self, path: Path, info: os.stat_result, engine: str, signatures: str, sha256: str) -> None:
        self.db.execute(
            """
            INSERT OR REPLACE INTO clean_files
            (path, device, inode, size, mtime_ns, engine_key, signature_key, sha256, last_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*self._identity(path, info), engine, signatures, sha256, int(time.time())),
        )

    def prune(self) -> None:
        cutoff = int(time.time()) - MAX_AGE_SECONDS
        self.db.execute("DELETE FROM clean_files WHERE last_used < ?", (cutoff,))
        count = self.db.execute("SELECT COUNT(*) FROM clean_files").fetchone()[0]
        excess = max(0, int(count) - MAX_ROWS)
        if excess:
            self.db.execute(
                """
                DELETE FROM clean_files WHERE rowid IN (
                    SELECT rowid FROM clean_files ORDER BY last_used ASC LIMIT ?
                )
                """,
                (excess,),
            )
        self.db.commit()

    def close(self) -> None:
        try:
            self.prune()
        finally:
            self.db.close()

    def __enter__(self) -> "ScanCache":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
