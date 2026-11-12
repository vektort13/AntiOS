"""Current-user guard status, bounded history and inter-process stop requests."""
from __future__ import annotations

import json
import math
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import time

from .antivirus import checked_path
from .quarantine import default_quarantine_path
from .windows_process import hidden_process_kwargs, system_executable


def default_guard_path():
    return default_quarantine_path().parent / "Guard"


def _grant_creator_access(folder: Path) -> None:
    """Keep a newly created private directory usable by the unelevated user.

    Windows mkdir(0700) uses OWNER RIGHTS; an elevated token can make the
    Administrators group the owner. Grant the actual token user explicitly.
    Call only on a new, empty, checked directory, never recursively.
    """
    if os.name != "nt":
        return
    from .quarantine import _current_windows_sid
    try:
        sid = _current_windows_sid()
        result = subprocess.run(
            [system_executable("icacls.exe"), str(folder), "/grant:r",
             f"*{sid}:(OI)(CI)F", "/L", "/Q"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, **hidden_process_kwargs(),
        )
    except subprocess.SubprocessError as exc:
        raise OSError("Unable to prepare current-user Guard access") from exc
    if result.returncode:
        raise PermissionError("Unable to grant the current user access to Guard state")


class GuardState:
    def __init__(self, folder):
        folder = Path(folder).absolute()
        # Validate existing ancestors before creation, then the actual directory.
        ancestor = folder
        while not ancestor.exists():
            ancestor = ancestor.parent
        checked_path(ancestor)
        created = False
        try:
            folder.mkdir(parents=True, mode=0o700)
            created = True
        except FileExistsError:
            pass
        self.folder = checked_path(folder)
        if not self.folder.is_dir():
            raise ValueError("Guard state location must be a directory")
        if created:
            try:
                _grant_creator_access(self.folder)
            except OSError:
                # Never leave a failed, empty directory looking initialized on
                # the next attempt. rmdir refuses to remove any actual data.
                try:
                    self.folder.rmdir()
                except OSError:
                    pass
                raise
        self.path = folder / "guard.sqlite3"
        if self.path.exists():
            checked_path(self.path)
            info = self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Guard database must be a regular, unlinked file")
        self.db = sqlite3.connect(self.path, timeout=5)
        # Guard is a frequent writer while GUI/CLI/tests query status. WAL
        # allows readers to use a stable snapshot instead of colliding with
        # short writer transactions on Windows (especially Python 3.13).
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS control (id INTEGER PRIMARY KEY CHECK(id=1), stop_run TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at REAL NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL);
        """)
        self.lock = None

    def acquire(self):
        path = self.folder / "guard.lock"
        if path.exists():
            checked_path(path)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0), 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(descriptor)
            raise ValueError("Invalid guard lock file")
        self.lock = os.fdopen(descriptor, "r+b")
        try:
            if os.name == "nt":
                import msvcrt
                if info.st_size == 0:
                    self.lock.write(b"0")
                    self.lock.flush()
                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.lock.close()
            self.lock = None
            raise OSError("AntiOS Guard is already running for this state directory") from exc

    def publish(self, value):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO state VALUES(1, ?)", (json.dumps(value),))

    def event(self, kind, value):
        with self.db:
            self.db.execute("INSERT INTO events(at, kind, payload) VALUES(?, ?, ?)",
                            (time.time(), kind, json.dumps(value)))
            self.db.execute("DELETE FROM events WHERE id <= (SELECT MAX(id)-1000 FROM events)")

    def stopped(self, run_id):
        row = self.db.execute("SELECT stop_run FROM control WHERE id=1").fetchone()
        return bool(row and row[0] == run_id)

    def close(self):
        if self.lock is not None:
            self.lock.close()
            self.lock = None
        self.db.close()


def read_guard_state(folder=None, *, history=False, stop=False):
    path = Path(folder or default_guard_path()) / "guard.sqlite3"
    if not path.exists():
        return {"state": "not-running", "running": False, "pre_execution_blocking": False}
    checked_path(path)
    uri = path.absolute().as_uri() + ("?mode=rw" if stop else "?mode=ro")
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db, db:
        row = db.execute("SELECT payload FROM state WHERE id=1").fetchone()
        status = json.loads(row[0]) if row else {"state": "not-running", "running": False}
        if not isinstance(status, dict) or not isinstance(status.get("running"), bool):
            raise ValueError("Invalid Guard status record")
        heartbeat = status.get("heartbeat", 0)
        if not isinstance(heartbeat, (int, float)) or not math.isfinite(heartbeat):
            raise ValueError("Invalid Guard heartbeat")
        published_running = status.get("running") is True
        if published_running and abs(time.time() - heartbeat) > 90:
            status.update(state="unresponsive", running=False)
        # A stale heartbeat does not prove that the process is gone. It may be
        # hung while still holding guard.lock, so preserve the published run
        # identity for a cooperative stop request before reporting it stopped.
        if stop and published_running:
            if not isinstance(status.get("run_id"), str) or not status["run_id"]:
                raise ValueError("Invalid Guard run identity")
            db.execute("INSERT OR REPLACE INTO control VALUES(1, ?)", (status["run_id"],))
            status["stop_requested"] = True
        if history:
            status["events"] = [{"at": at, "kind": kind, "data": json.loads(payload)}
                                for at, kind, payload in db.execute(
                                    "SELECT at, kind, payload FROM events ORDER BY id DESC LIMIT 100")]
        return status



def read_incident_history(folder=None, *, limit=50):
    """Return newest bounded Incident Graph snapshots, deduplicated by incident id."""
    if not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("incident history limit must be between 1 and 100")

    path = Path(folder or default_guard_path()) / "guard.sqlite3"
    if not path.exists():
        return []
    checked_path(path)
    uri = path.absolute().as_uri() + "?mode=ro"

    newest: dict[str, dict] = {}
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
        row = db.execute("SELECT payload FROM state WHERE id=1").fetchone()
        if row:
            try:
                status = json.loads(row[0])
            except (TypeError, ValueError):
                status = {}
            incidents = status.get("incidents") if isinstance(status, dict) else {}
            latest = incidents.get("latest") if isinstance(incidents, dict) else None
            if isinstance(latest, dict):
                incident_id = latest.get("id")
                if isinstance(incident_id, str) and incident_id:
                    current = dict(latest)
                    heartbeat = status.get("heartbeat")
                    if isinstance(heartbeat, (int, float)) and math.isfinite(heartbeat):
                        current["_journal_at"] = float(heartbeat)
                    newest[incident_id] = current

        # Read more rows than the requested incident count because one incident
        # can have multiple coalesced snapshots across its lifetime.
        rows = db.execute(
            "SELECT at, payload FROM events WHERE kind='incident-update' "
            "ORDER BY id DESC LIMIT ?",
            (min(1000, limit * 12),),
        )
        for journal_at, payload in rows:
            try:
                value = json.loads(payload)
            except (TypeError, ValueError):
                continue
            incident = value.get("incident") if isinstance(value, dict) else None
            if not isinstance(incident, dict):
                continue
            incident_id = incident.get("id")
            if not isinstance(incident_id, str) or not incident_id:
                continue
            if incident_id not in newest:
                snapshot = dict(incident)
                snapshot["_journal_at"] = float(journal_at)
                newest[incident_id] = snapshot
            else:
                # The current status may contain a newer graph snapshot, while
                # the journal carries the precise wall-clock time of its most
                # recent persisted update.
                newest[incident_id]["_journal_at"] = float(journal_at)
            if len(newest) >= limit:
                break

    values = list(newest.values())
    values.sort(
        key=lambda item: (
            float(item.get("_journal_at", 0) or 0),
            str(item.get("id", "")),
        ),
        reverse=True,
    )
    return values[:limit]
