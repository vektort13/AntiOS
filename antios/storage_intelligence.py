"""Lightweight, explicit-on-scan storage intelligence.

No daemon, network, document contents, or whole-file usage surveillance.
Historical samples are recorded only after a user-requested scan.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import sqlite3
import statistics
import time
from typing import Any

CATEGORIES = ("duplicate", "old", "archive", "empty")
MAX_HISTORY_DAYS = 180
MAX_TRACKED_ROOTS = 32


def default_journal_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "AntiOS" / "storage-intelligence.sqlite3"
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "antios" / "storage-intelligence.sqlite3"


def _root_key(path: str | Path) -> str:
    """Pseudonymous stable scan-root ID; not encryption or an HMAC."""
    absolute = os.path.normcase(os.path.abspath(os.fspath(path)))
    return hashlib.sha256(("antios:storage:v1:" + absolute).encode("utf-8")).hexdigest()


class StorageJournal:
    """Small bounded SQLite journal; do not open with an elevated Windows token."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or default_journal_path())
        if os.name == "nt" and path is None:
            from .elevation import is_administrator
            if is_administrator():
                raise PermissionError("Per-user storage journal is not written by an elevated process")
        parent = self.path.parent
        ancestor = parent
        while not ancestor.exists():
            ancestor = ancestor.parent
        if ancestor.is_symlink():
            raise ValueError("Journal ancestor cannot be a symlink")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or self.path.is_symlink():
            raise ValueError("Journal path cannot be a symlink")
        self.db = sqlite3.connect(self.path, timeout=2)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS samples(
                root TEXT NOT NULL, day INTEGER NOT NULL, bytes INTEGER NOT NULL,
                files INTEGER NOT NULL, PRIMARY KEY(root, day))
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS preferences(
                category TEXT PRIMARY KEY, choice TEXT NOT NULL,
                confirmed_deletions INTEGER NOT NULL DEFAULT 0)
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS settings(
                name TEXT PRIMARY KEY, value TEXT NOT NULL)
        """)
        self.db.commit()

    def history_enabled(self) -> bool:
        row = self.db.execute(
            "SELECT value FROM settings WHERE name='history'"
        ).fetchone()
        return row is None or row[0] == "on"

    def set_history_enabled(self, enabled: bool) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO settings(name, value) VALUES('history', ?) "
                "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                ("on" if enabled else "off",),
            )

    def clear_history(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM samples")

    def __enter__(self) -> "StorageJournal":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.db.close()

    def capture(self, root: str | Path, bytes_used: int, files: int, *, now: float | None = None) -> None:
        if bytes_used < 0 or files < 0:
            raise ValueError("Negative storage measurements")
        day = int((time.time() if now is None else now) // 86400)
        key = _root_key(root)
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO samples(root, day, bytes, files) VALUES(?, ?, ?, ?)",
                (key, day, int(bytes_used), int(files)),
            )
            self.db.execute("DELETE FROM samples WHERE day < ?", (day - MAX_HISTORY_DAYS,))
            roots = self.db.execute(
                "SELECT root FROM samples GROUP BY root ORDER BY MAX(day) DESC, root"
            ).fetchall()
            for (old_root,) in roots[MAX_TRACKED_ROOTS:]:
                self.db.execute("DELETE FROM samples WHERE root=?", (old_root,))

    def timeline(self, root: str | Path) -> list[dict[str, int]]:
        rows = self.db.execute(
            "SELECT day, bytes, files FROM samples WHERE root=? ORDER BY day",
            (_root_key(root),),
        ).fetchall()
        return [{"day": int(day), "bytes": int(size), "files": int(files)}
                for day, size, files in rows]

    def preference(self, category: str) -> str:
        if category not in CATEGORIES:
            raise ValueError("Unsupported category")
        row = self.db.execute(
            "SELECT choice FROM preferences WHERE category=?", (category,)
        ).fetchone()
        return str(row[0]) if row else "normal"

    def set_preference(self, category: str, choice: str) -> None:
        if category not in CATEGORIES or choice not in {"prefer", "normal", "hide"}:
            raise ValueError("Unsupported cleanup preference")
        with self.db:
            self.db.execute(
                "INSERT INTO preferences(category, choice, confirmed_deletions) "
                "VALUES(?, ?, 0) ON CONFLICT(category) DO UPDATE SET choice=excluded.choice",
                (category, choice),
            )

    def confirmed_cleanup(self, categories: list[str]) -> None:
        """Only count successful, explicitly confirmed user deletions."""
        with self.db:
            for category in categories:
                if category not in CATEGORIES:
                    continue
                self.db.execute(
                    "INSERT INTO preferences(category, choice, confirmed_deletions) "
                    "VALUES(?, 'normal', 1) "
                    "ON CONFLICT(category) DO UPDATE SET "
                    "confirmed_deletions=MIN(10000, confirmed_deletions+1)",
                    (category,),
                )

    def preferences(self) -> dict[str, dict[str, Any]]:
        rows = self.db.execute(
            "SELECT category, choice, confirmed_deletions FROM preferences"
        ).fetchall()
        current = {cat: {"choice": "normal", "confirmed_deletions": 0}
                   for cat in CATEGORIES}
        current.update({cat: {"choice": choice, "confirmed_deletions": count}
                        for cat, choice, count in rows if cat in CATEGORIES})
        return current


def estimate_trend(samples: list[dict[str, int]]) -> dict[str, Any]:
    """MemoryMap + TimeDebt. A forecast is offered only after repeated days."""
    timeline = samples[-30:]
    output: dict[str, Any] = {
        "samples": timeline, "forecast": "insufficient-history",
        "bytes_per_day": None, "predicted_bytes_30_days": None,
    }
    if len(timeline) < 3 or timeline[-1]["day"] - timeline[0]["day"] < 7:
        return output
    rates = []
    for a, b in zip(timeline, timeline[1:]):
        elapsed = b["day"] - a["day"]
        if elapsed > 0:
            rates.append((b["bytes"] - a["bytes"]) / elapsed)
    if len(rates) < 2:
        return output
    slope = int(statistics.median(rates))
    output.update({
        "forecast": "experimental-trend-not-guaranteed",
        "bytes_per_day": slope,
        "predicted_bytes_30_days": max(0, timeline[-1]["bytes"] + slope * 30),
        "confidence": "low" if len(timeline) < 7 else "moderate",
    })
    return output


def candidate_categories(scan: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for group in scan.get("duplicates", []):
        for path in group.get("paths", []):
            result.setdefault(str(path), []).append("duplicate")
    for kind, key in (("old", "old_large_files"), ("archive", "installer_archives"),
                      ("empty", "empty_files")):
        for record in scan.get(key, []):
            path = str(record["path"])
            if kind not in result.setdefault(path, []):
                result[path].append(kind)
    return result


def copy_evidence(scan: dict[str, Any], selected: list[str] | None = None) -> dict[str, dict[str, Any]]:
    """Only assert copies verified within this completed scan.

    A hard link is another name for the SAME physical content, not an
    independent surviving copy. Missing matches are not proof of uniqueness.
    """
    snapshots = scan.get("candidate_snapshots", {})
    groups: dict[str, tuple[int, int]] = {}
    for group in scan.get("duplicates", []):
        identities: set[tuple[int, int]] = set()
        for path in group["paths"]:
            snap = snapshots.get(str(path), {})
            if "device" in snap and "inode" in snap:
                identities.add((int(snap["device"]), int(snap["inode"])))
        for path in group["paths"]:
            groups[str(path)] = (len(identities), len(group["paths"]))
    paths = selected if selected is not None else list(snapshots)
    output: dict[str, dict[str, Any]] = {}
    for path in paths:
        copies = groups.get(str(path))
        if copies and copies[0] > 1:
            output[str(path)] = {
                "status": "verified-other-file-in-scan",
                "independent_files_in_group": copies[0],
                "scope": "scanned folder only",
            }
        else:
            output[str(path)] = {
                "status": "no-independent-copy-verified",
                "independent_files_in_group": copies[0] if copies else 0,
                "scope": "not proof of a unique or last existing copy",
            }
    return output


def survival_report(scan: dict[str, Any]) -> dict[str, Any]:
    """Read-only preparedness hints, not a whole-PC disaster recovery claim."""
    evidence = copy_evidence(scan)
    unverified = sum(
        item["status"] == "no-independent-copy-verified" for item in evidence.values()
    )
    return {
        "scope": scan.get("root"),
        "assessed_cleanup_candidates": len(evidence),
        "candidates_without_verified_independent_copy": unverified,
        "needs_verified_external_backup": unverified > 0,
        "note": ("Only candidates in this scan were assessed; cloud, disconnected "
                 "drives, other folders, installed applications and OS recovery "
                 "were not checked. A matching copy is not a verified backup."),
    }


def insights_for_scan(scan: dict[str, Any], *, journal_path: str | Path | None = None,
                      now: float | None = None) -> dict[str, Any]:
    """Non-destructive analysis with low bounded overhead; journal failures stay visible."""
    categories = candidate_categories(scan)
    evidence = copy_evidence(scan)
    result: dict[str, Any] = {
        "lastcopy": evidence,
        "survival": survival_report(scan),
        "categories": categories,
        "history": {"forecast": "unavailable"},
        "recommendations": [],
        "preferences": {},
    }
    if scan.get("cancelled") or scan.get("limit_reached"):
        result["history"] = {
            "forecast": "unavailable",
            "reason": "cancelled-or-incomplete-scan",
        }
        result["survival"]["note"] += " Scan was incomplete; evidence may be missing."
        return result
    prefs: dict[str, dict[str, Any]] = {}
    try:
        with StorageJournal(journal_path) as store:
            summary = scan["summary"]
            enabled = store.history_enabled()
            result["history_enabled"] = enabled
            if enabled:
                store.capture(scan["root"], summary["bytes_scanned"],
                              summary["files_scanned"], now=now)
                result["history"] = estimate_trend(store.timeline(scan["root"]))
            else:
                result["history"] = {"forecast": "disabled-by-user", "samples": []}
            prefs = store.preferences()
    except (OSError, ValueError, sqlite3.Error) as exc:
        result["history"] = {"forecast": "unavailable", "reason": str(exc)[:200]}
    result["preferences"] = prefs
    for path, kinds in categories.items():
        choices = [prefs.get(k, {}).get("choice", "normal") for k in kinds]
        hidden = bool(choices) and all(choice == "hide" for choice in choices)
        learned = any(
            prefs.get(k, {}).get("choice") == "normal"
            and prefs.get(k, {}).get("confirmed_deletions", 0) >= 3
            for k in kinds
        )
        preferred = "prefer" in choices or learned
        result["recommendations"].append({
            "path": path, "categories": kinds,
            "priority": "hidden-by-user" if hidden else "preferred" if preferred else "review",
            "priority_reason": ("explicit-user-choice" if "prefer" in choices else
                                "repeated-confirmed-cleanups" if learned else
                                "not-classified-as-unused"),
            "copy_evidence": evidence.get(path, {}).get("status", "not-checked"),
        })
    result["recommendations"].sort(
        key=lambda row: ({"preferred": 0, "review": 1, "hidden-by-user": 2}[row["priority"]],
                         row["path"].casefold())
    )
    return result


def background_permission(*, min_idle_seconds: int = 300) -> dict[str, Any]:
    """SmartSleep: a fail-closed gate for optional background maintenance.

    Explicit user scans and time-critical antivirus protection MUST NOT use it.
    """
    if os.name != "nt":
        return {"allowed": False, "reason": "Windows idle/battery probe unavailable"}
    try:
        class LastInput(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint32)]
        class Power(ctypes.Structure):
            _fields_ = [
                ("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                ("BatteryLifeTime", ctypes.c_uint32), ("BatteryFullLifeTime", ctypes.c_uint32),
            ]
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetTickCount64.restype = ctypes.c_uint64
        data = LastInput(ctypes.sizeof(LastInput), 0)
        power = Power()
        if not user32.GetLastInputInfo(ctypes.byref(data)):
            raise OSError("GetLastInputInfo failed")
        if not kernel32.GetSystemPowerStatus(ctypes.byref(power)):
            raise OSError("GetSystemPowerStatus failed")
        if power.ACLineStatus != 1:
            return {"allowed": False, "reason": "battery or unknown power source"}
        idle_ms = (int(kernel32.GetTickCount64()) & 0xFFFFFFFF) - int(data.dwTime)
        idle_ms &= 0xFFFFFFFF
        if idle_ms < min_idle_seconds * 1000:
            return {"allowed": False, "reason": "user recently active"}
        return {"allowed": True, "reason": "AC power and idle threshold met"}
    except (OSError, AttributeError, ValueError) as exc:
        return {"allowed": False, "reason": f"idle probe failed: {exc}"}
