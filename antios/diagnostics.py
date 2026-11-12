"""Bounded, user-local diagnostics for AntiOS.

This is a journal, never a command interpreter. It stores sanitized structured
events per process, tolerates write failures without affecting antivirus work,
and exports only deliberately whitelisted information (no configs or samples).
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import uuid
from zipfile import ZIP_DEFLATED, ZipFile

_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_COMPONENTS = {
    "Guard", "ClamAV", "AntiOS Engine", "Scanner", "Quarantine", "Updater",
    "Installer", "Protection", "UI", "Defender", "System",
}
_MAX_BYTES = 1024 * 1024
_MAX_DETAIL = 7000
_MAX_FILES = 24
_IO_LOCK = threading.RLock()

# Never persist bearer tokens, email addresses or credentials in a support log.
_PRIVATE = (
    (re.compile(r"(?i)\bAuthorization[ \t]*[:=][ \t]*[^\r\n,;]+"), "Authorization: [REDACTED]"),
    (re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/\-]{8,}=*"), "[AUTH_CREDENTIAL]"),
    (re.compile(r"""(?i)\b(authorization|bearer|password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token)[ \t]*[:=][ \t]*(?:"[^"]*"|'[^']*'|[^\s,;]+)"""), r"\1=[REDACTED]"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"(?i)\b([?&](?:token|code|key|secret|password|auth|sig|signature)=)[^&\s]+"), r"\1[REDACTED]"),
)
# Export masking deliberately favours privacy over verbatim file locations.
# Unlike ordinary journal display, support ZIPs must not contain usernames in
# paths with spaces or expose custom drive letters / UNC shares.
_WINDOWS_HOME = re.compile(r"(?i)(?:[A-Z]:\\Users\\|/Users/)[^\\/\r\n\"<>|]+")
_WINDOWS_PATH = re.compile(r"(?i)(?<![A-Z0-9])(?:[A-Z]:\\|\\\\[^\\\s]+\\[^\\\s]+\\)[^\r\n,;\"<>|]+")
_POSIX_HOME = re.compile(r"/home/[^/\r\n]+")
_POSIX_PATH = re.compile(r"(?<![A-Za-z0-9:/])/(?:[^/\s]+/)*[^/\s]+")

_HELP = {
    "ENGINE_SIGNATURE_INVALID": {
        "ru": ("Не удалось подтвердить подпись ClamAV",
               "AntiOS не может доверять clamd.exe или freshclam.exe. Проверка не запускается, пока источник исполняемых файлов не подтверждён.",
               "Запустите «Восстановить защиту» через AntiOS. Если ошибка повторится, отправьте обезличенный отчёт разработчику. Не отключайте проверку подписей."),
        "en": ("ClamAV signature could not be verified",
               "AntiOS cannot trust clamd.exe or freshclam.exe and will not run unverified engine binaries.",
               "Use Repair protection in AntiOS. If it continues, export the redacted report. Do not disable signature checks."),
    },
    "ENGINE_NOT_READY": {
        "ru": ("Движок защиты недоступен",
               "Локальный движок AntiOS или его сигнатуры недоступны. Проверку нельзя считать завершённой.",
               "Проверьте установку AntiOS и локальную базу сигнатур. Не отключайте постоянную защиту."),
        "en": ("Protection engine not ready",
               "The local AntiOS Engine or its signatures are unavailable. The scan cannot be considered complete.",
               "Check the AntiOS installation and local signature database. Keep primary protection enabled."),
    },
    "ELEVATION_REQUIRED": {
        "ru": ("Требуются права администратора",
               "Для изменения системного движка нужны отдельные повышенные права. Обычный интерфейс остаётся без них.",
               "Нажмите «Восстановить защиту» и подтвердите запрос UAC, если доверяете операции."),
        "en": ("Administrator approval required",
               "Machine-wide protection maintenance needs a separate elevated operation.",
               "Choose Repair protection and approve UAC only if you trust the operation."),
    },
    "OPERATION_FAILED": {
        "ru": ("Операция завершилась ошибкой",
               "Один из компонентов не выполнил запрос. Подробности доступны в техническом журнале.",
               "Проверьте источник и время события. При повторении экспортируйте обезличенный отчёт."),
        "en": ("Operation failed",
               "A component could not complete its operation. The technical details are in the journal.",
               "Check the component and timestamp. Export a redacted report if the error recurs."),
    },
    "OPERATION_STARTED": {
        "ru": ("Операция запущена", "AntiOS выполняет запрошенное действие.",
               "Дождитесь завершения или остановите проверку штатной кнопкой."),
        "en": ("Operation started", "AntiOS is performing the requested action.",
               "Wait for completion or use the normal Cancel action."),
    },
    "OPERATION_COMPLETED": {
        "ru": ("Операция завершена", "Запрошенное действие завершилось без исключения.",
               "Проверьте фактическое состояние компонента перед оценкой защищённости."),
        "en": ("Operation completed", "The requested operation returned without an exception.",
               "Check the component's actual state before assuming protection is active."),
    },
    "ACCESS_DENIED": {
        "ru": ("Доступ запрещён", "Windows отказала в доступе к ресурсу или операции.",
               "Проверьте права доступа. Для обслуживания движка используйте отдельное подтверждение UAC."),
        "en": ("Access denied", "Windows denied access to a resource or operation.",
               "Check file permissions. Use the separate UAC flow for engine maintenance."),
    },
    "OPERATION_TIMEOUT": {
        "ru": ("Истекло время ожидания", "Ответ компонента не поступил вовремя; результат операции неизвестен.",
               "Обновите состояние компонента перед повторной попыткой, не считайте действие завершённым."),
        "en": ("Operation timed out", "The component did not respond in time; the outcome is unknown.",
               "Refresh component status before retrying; do not assume it completed."),
    },
    "GUARD_UNRESPONSIVE": {
        "ru": ("Guard не отвечает",
               "Нет подтверждения, что фоновый мониторинг работает. Нельзя считать защиту активной.",
               "Проверьте AntiOS Engine и перезапустите Guard после устранения ошибки."),
        "en": ("Guard is unresponsive",
               "Resident monitoring is not confirmed; protection must not be shown as active.",
               "Check AntiOS Engine and restart Guard after resolving engine errors."),
    },
    "GUARD_POLICY_INVALID": {
        "ru": ("Настройки Guard несовместимы",
               "Guard не смог загрузить сохранённые параметры запуска.",
               "Обновите AntiOS и заново включите Guard, чтобы пересоздать настройки."),
        "en": ("Guard settings are incompatible",
               "Guard could not load its saved startup settings.",
               "Update AntiOS and enable Guard again to regenerate its settings."),
    },
    "GUARD_STATE_CHANGED": {
        "ru": ("Изменилось состояние Guard",
               "Состояние резидентной защиты изменилось. Это не всегда ошибка.",
               "Если состояние «не отвечает» или «сбой», откройте последние ошибки движка."),
        "en": ("Guard state changed",
               "Resident protection changed its state. This is not always a failure.",
               "If Guard is unresponsive or failed, inspect recent engine errors."),
    },
    "SCAN_COMPLETED": {
        "ru": ("Проверка завершена",
               "Результаты проверки файлов обновлены.", "Посмотрите находки и покрытие проверки."),
        "en": ("Scan completed", "The file scan results have been updated.", "Review findings and scan coverage."),
    },
}


def diagnostics_directory() -> Path:
    if os.name == "nt":
        home = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return home / "AntiOS" / "Diagnostics"
    xdg = os.environ.get("XDG_STATE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "state") / "antios" / "diagnostics"


def redact(text: object, *, exported: bool = False) -> str:
    result = str(text or "")[:_MAX_DETAIL]
    for pattern, replacement in _PRIVATE:
        result = pattern.sub(replacement, result)
    if exported:
        result = _WINDOWS_HOME.sub(lambda _: r"C:\Users\[USER]", result)
        result = _POSIX_HOME.sub("/home/[USER]", result)
        result = _WINDOWS_PATH.sub("[PATH]", result)
        result = _POSIX_PATH.sub("[PATH]", result)
        try:
            home = str(Path.home())
            if home and len(home) > 3:
                result = re.sub(re.escape(home), "[USER_HOME]", result, flags=re.I)
        except Exception:
            pass
    return result


def explanation(code: str, language: str = "en") -> tuple[str, str, str]:
    entry = _HELP.get(code, _HELP["OPERATION_FAILED"])
    return entry["ru" if language == "ru" else "en"]


def classify_error(message: str, *, component: str = "") -> str:
    lower = str(message).lower()
    if ("authenticode" in lower or "digital signature" in lower or "цифров" in lower) and (
        "clam" in lower or "freshclam" in lower or "engine" in lower
    ):
        return "ENGINE_SIGNATURE_INVALID"
    if ("administrator" in lower or "uac" in lower or "elevation" in lower) and (
        "require" in lower or "deny" in lower or "cancel" in lower
    ):
        return "ELEVATION_REQUIRED"
    if ("[winerror 5]" in lower or "access denied" in lower or "permission denied" in lower or
            "доступ запрещ" in lower or "отказано в доступе" in lower):
        return "ACCESS_DENIED"
    if component == "Guard" and "unknown guard policy field" in lower:
        return "GUARD_POLICY_INVALID"
    if "timed out" in lower or "timeout" in lower or "время ожидания" in lower:
        return "OPERATION_TIMEOUT"
    if ("unresponsive" in lower or "не отвечает" in lower) and component == "Guard":
        return "GUARD_UNRESPONSIVE"
    if ("clamav" in lower or "clamd" in lower or "engine" in lower) and (
        "not ready" in lower or "unavailable" in lower or "не готов" in lower
    ):
        return "ENGINE_NOT_READY"
    return "OPERATION_FAILED"


def _safe_component(value: str) -> str:
    name = str(value).strip()
    return name if name in _COMPONENTS else "System"


def _safe_code(value: str) -> str:
    name = str(value).upper()
    return name if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", name) else "OPERATION_FAILED"


def _prepare(directory: Path) -> bool:
    try:
        if directory.is_symlink():
            return False
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return directory.is_dir() and not directory.is_symlink()
    except OSError:
        return False


def _rotate(path: Path) -> None:
    if path.is_symlink():
        raise OSError("Refusing diagnostic symlink")
    if path.exists() and path.stat().st_size >= _MAX_BYTES:
        older = path.with_suffix(".old.jsonl")
        if older.is_symlink():
            raise OSError("Refusing diagnostic archive symlink")
        path.replace(older)


def _safe_to_write_default_journal() -> bool:
    """Never use a user-controlled LocalAppData path as a privileged writer.

    On Windows an unelevated user can arrange filesystem redirections inside
    their profile. Python on Windows does not provide O_NOFOLLOW. An elevated
    child therefore must not open a log there with its administrator token.
    The interactive non-elevated GUI remains the durable error collector.
    """
    if os.name != "nt":
        return True
    try:
        from .elevation import is_administrator
        return not is_administrator()
    except (OSError, RuntimeError, AttributeError):
        return False


def record_event(
    component: str, level: str, message: str, *,
    code: str = "OPERATION_FAILED",
    details: str = "",
    context: dict | None = None,
    directory: Path | None = None,
) -> dict:
    """Best-effort journal write; must never interrupt protection operations."""
    name = _safe_component(component)
    if not isinstance(context, dict):
        context = {}
    severity = str(level).upper()
    if severity not in _LEVELS:
        severity = "ERROR"
    event = {
        "schema": 1,
        "id": uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "level": severity,
        "component": name,
        "code": _safe_code(code),
        "message": redact(message)[:700],
        "details": redact(details),
        "context": {
            str(key)[:50]: redact(value)[:250]
            for key, value in (context or {}).items()
            if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,49}", str(key))
            and str(key).lower() not in {"password", "token", "secret", "path", "command"}
        },
    }
    try:
        if directory is None and not _safe_to_write_default_journal():
            return event
        root = Path(directory) if directory is not None else diagnostics_directory()
        with _IO_LOCK:
            if _prepare(root):
                path = root / ("events-" + str(os.getpid()) + ".jsonl")
                _rotate(path)
                # Opening with O_NOFOLLOW where available avoids a symlink
                # replacement redirecting diagnostic data outside the log dir.
                flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(path, flags, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    except (OSError, ValueError, TypeError):
        pass
    return event


def journal_fingerprint(*, directory: Path | None = None) -> tuple[tuple[str, int, int], ...]:
    """Cheap change detector, so an open GUI does not reread megabytes every 2 s."""
    root = Path(directory) if directory is not None else diagnostics_directory()
    result = []
    try:
        for path in root.glob("events-*.jsonl"):
            if path.is_symlink() or not path.is_file():
                continue
            info = path.stat()
            result.append((path.name, info.st_size, info.st_mtime_ns))
        result.sort(key=lambda item: item[2], reverse=True)
    except OSError:
        pass
    return tuple(result[:_MAX_FILES])


def recent_events(*, limit: int = 300, directory: Path | None = None) -> list[dict]:
    """Read bounded journal tails and isolate corrupted/inaccessible files."""
    root = Path(directory) if directory is not None else diagnostics_directory()
    limit = max(1, min(1000, int(limit)))
    found: list[dict] = []
    with _IO_LOCK:
        candidates = []
        try:
            for path in root.glob("events-*.jsonl"):
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    candidates.append((path.stat().st_mtime_ns, path))
                except OSError:
                    # A different process may rotate a file during enumeration.
                    continue
        except OSError:
            return []
        for _modified, path in sorted(candidates, reverse=True)[:_MAX_FILES]:
            try:
                # Do not follow a link inserted between enumeration and open.
                if path.is_symlink():
                    continue
                with path.open("rb") as stream:
                    stream.seek(0, os.SEEK_END)
                    end = stream.tell()
                    stream.seek(max(0, end - min(end, _MAX_BYTES + 16384)), os.SEEK_SET)
                    if stream.tell() > 0:
                        stream.readline()
                    for line in stream:
                        if len(line) > 16000:
                            continue
                        try:
                            entry = json.loads(line)
                        except (ValueError, UnicodeDecodeError, RecursionError, TypeError):
                            continue
                        if (
                            isinstance(entry, dict)
                            and entry.get("schema") == 1
                            and entry.get("level") in _LEVELS
                            and isinstance(entry.get("message"), str)
                            and isinstance(entry.get("timestamp"), str)
                        ):
                            found.append(entry)
            except (OSError, ValueError):
                # One inaccessible or changing log must not hide all other logs.
                continue
    found.sort(key=lambda item: (item["timestamp"], str(item.get("id", ""))), reverse=True)
    return found[:limit]


def export_report(destination: Path, *, directory: Path | None = None, metadata: dict | None = None) -> int:
    """One redacted ZIP, no raw logs, credentials, configs, user files or system commands."""
    events = recent_events(limit=500, directory=directory)
    clean = []
    for event in events:
        event_context = event.get("context")
        if not isinstance(event_context, dict):
            event_context = {}
        clean.append({
            "timestamp": str(event.get("timestamp", ""))[:60],
            "level": str(event.get("level", ""))[:20],
            "component": _safe_component(event.get("component", "")),
            "code": _safe_code(event.get("code", "")),
            "message": redact(event.get("message", ""), exported=True),
            "details": redact(event.get("details", ""), exported=True),
            "context": {
                str(k)[:50]: redact(v, exported=True)[:250]
                for k, v in event_context.items()
                if str(k) in {"operation", "state", "action", "exit_code", "source",
                              "errors", "coverage"}
            },
        })
    approved = {"app_version", "os_name", "os_release", "python_version", "language"}
    header = {k: redact(v, exported=True)[:100] for k, v in (metadata or {}).items() if k in approved}
    # Never truncate an existing support ZIP before the replacement is fully
    # written. A disk-full error or interrupted export must leave the previous
    # file intact and not advertise a partially generated diagnostics bundle.
    destination = Path(destination)
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=".antios-diagnostics-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            staged = Path(temporary.name)
        with ZipFile(staged, "w", ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr(
                "README.txt",
                "AntiOS diagnostics — redacted support bundle.\n"
                "No settings, binaries, samples or quarantine files are included.\n"
                "Review before sharing.\n",
            )
            archive.writestr(
                "summary.json",
                json.dumps(
                    {"schema": 1, "metadata": header, "events": len(clean)},
                    ensure_ascii=False, indent=2,
                ),
            )
            archive.writestr("events.json", json.dumps(clean, ensure_ascii=False, indent=2))
        os.replace(staged, destination)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    return len(clean)
