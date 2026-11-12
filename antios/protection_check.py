"""Opt-in, non-destructive functional checks of local protection."""
from __future__ import annotations

from datetime import datetime, timezone
import os
import sqlite3
from pathlib import Path
import tempfile

from . import recovery
from .engine import AntiOSEngine
from .antivirus import load_signatures
from .guard_state import read_guard_state

_CHECKS = {
    "engine": (("Работоспособность AntiOS Engine", "AntiOS Engine readiness"),
               ("Проверьте установку AntiOS Engine.",
                "Check the installed AntiOS Engine runtime.")),
    "database": (("Локальная база AntiOS", "Local AntiOS signatures"),
                 ("Проверьте локальную базу сигнатур.", "Check local signature availability.")),
    "benign-scan": (("Проверка безопасного содержимого", "Benign content control"),
                    ("Движок не подтвердил корректную обработку безопасного образца. Восстановите его и повторите проверку.",
                     "The engine did not correctly process the benign control. Repair it and check again.")),
    "test-detection": (("Обнаружение безопасного теста EICAR", "Harmless EICAR detection test"),
                       ("Тестовое обнаружение не подтверждено. Обновите базы или восстановите движок.",
                        "Test detection was not confirmed. Update signatures or repair the engine.")),
    "guard-status": (("Состояние фонового Guard", "Resident Guard status"),
                     ("Включите фоновую защиту для выбранных папок и проверьте её журнал. Здесь проверяется только текущее состояние Guard.",
                      "Enable resident protection for your folders and review its journal. This check only reads Guard's current status.")),
    "recovery": (("Сохранение и извлечение тестовой копии", "Temporary backup and recovery"),
                 ("Проверьте свободное место и доступ к временной папке. Повторите проверку перед созданием важных снимков.",
                  "Check free space and temporary-folder access. Repeat the check before creating important snapshots.")),
}


def describe_check(item: dict, language="ru") -> tuple[str, str, str]:
    index = 0 if language == "ru" else 1
    label, advice = _CHECKS.get(item.get("id"), (("Проверка", "Check"), ("Посмотрите журнал.", "Review the journal.")))
    states = {"passed": ("Пройдено", "Passed"), "warning": ("Внимание", "Attention"),
              "failed": ("Не пройдено", "Failed"), "skipped": ("Не выполнено", "Not run")}
    state = item.get("state")
    detail = (("Проверка завершилась успешно.", "The check completed successfully.")[index]
              if state == "passed" else advice[index])
    if item.get("id") == "guard-status" and state == "passed":
        detail = ("Guard сообщает о работе. Это проверка состояния; перехват новых файлов этим тестом не проверяется.",
                  "Guard reports that it is running. This status check does not exercise new-file detection.")[index]
    elif item.get("id") == "guard-status" and item.get("detail"):
        detail = ("Не удалось прочитать состояние Guard. Откройте AntiOS от имени администратора и заново включите фоновую защиту. Если ошибка повторяется, экспортируйте диагностику.",
                  "Guard status could not be read. Open AntiOS as administrator and enable resident protection again. If the error persists, export diagnostics.")[index]
    return label[index], states.get(state, ("Неизвестно", "Unknown"))[index], detail


def render_report(report: dict, language="en") -> str:
    lines = ["AntiOS · " + ("Самопроверка защиты" if language == "ru" else "Protection self-check")]
    for item in report["checks"]:
        label, state, advice = describe_check(item, language)
        lines.append(f"{label}: {state}")
        if item["state"] != "passed":
            lines.append(advice)
    lines.append(("Результат: " if language == "ru" else "Result: ") + report["status"])
    return "\n".join(lines)


def _now():
    return datetime.now(timezone.utc).isoformat()


def run_checks(*, scanner_factory=None, guard_reader=None,
               cancelled=lambda: False, progress=lambda value: None) -> dict:
    """Test real scan responses and a temporary backup round trip; no system writes."""
    result = {"schema": 1, "kind": "antios-self-check", "started_at": _now(), "checks": []}
    checks = result["checks"]

    def record(name, state, detail=""):
        item = {"id": name, "state": state, "detail": str(detail)[:320]}
        checks.append(item)
        progress(dict(item))

    engine = None
    try:
        if not cancelled():
            try:
                factory = scanner_factory or (lambda: AntiOSEngine(signatures=load_signatures()))
                engine = factory()
                metadata = dict(engine.metadata)
                verified = metadata.get("database_freshness") in {"local", "current"}
                record("engine", "passed" if verified else "failed")
                record("database", "passed" if metadata.get("database_freshness") in {"local", "current"} else "warning")
                if not verified:
                    engine.close()
                    engine = None
            except (OSError, ValueError, RuntimeError) as exc:
                record("engine", "failed", exc)
        # This standard harmless antivirus test stays entirely in memory.
        # A benign control must pass too: an engine that flags everything fails.
        samples = (
            ("benign-scan", b"AntiOS self-check: ordinary benign content.", False),
            ("test-detection", bytes.fromhex(
                "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d"
                "5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"), True),
        )
        for name, content, detected in samples:
            if cancelled():
                break
            if engine is None:
                record(name, "skipped")
                continue
            try:
                outcome = engine.scan(content, "AntiOS self-check")
                passed = (outcome.kind == "threat" and "eicar" in outcome.name.lower()) if detected else outcome.kind is None
                record(name, "passed" if passed else "failed")
            except (OSError, ValueError, RuntimeError) as exc:
                record(name, "failed", exc)
    finally:
        if engine is not None:
            engine.close()

    if not cancelled():
        try:
            guard = (guard_reader or read_guard_state)()
            ready = (guard.get("running") is True and guard.get("state") in {"monitoring", "scanning", "attention"}
                     and not guard.get("capacity_exceeded") and not guard.get("inventory_issues"))
            record("guard-status", "passed" if ready else "warning")
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            record("guard-status", "warning", exc)
    if not cancelled():
        try:
            with tempfile.TemporaryDirectory(prefix="AntiOS-self-check-") as folder:
                root = Path(folder)
                original = root / "benign.txt"
                content = b"AntiOS temporary recovery self-check.\n"
                original.write_bytes(content)
                archive = root / "baseline.zip"
                created = recovery.create([original], archive, cancelled=cancelled)
                if created["coverage"] != "selected-files" or created["files"] != 1:
                    raise ValueError("Temporary baseline could not be completed")
                destination = root / "recovered"
                recovery.export(archive, destination, cancelled=cancelled)
                if (destination / "0.bin").read_bytes() != content:
                    raise ValueError("Recovered temporary bytes differ")
                record("recovery", "passed")
        except recovery.RecoveryCancelled:
            pass
        except (OSError, ValueError, RuntimeError) as exc:
            record("recovery", "failed", exc)
    result["cancelled"] = bool(cancelled())
    result["status"] = ("cancelled" if result["cancelled"] else
                        "failed" if any(c["state"] == "failed" for c in checks) else
                        "attention" if any(c["state"] != "passed" for c in checks) else "passed")
    result["finished_at"] = _now()
    return result
