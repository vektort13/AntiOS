from __future__ import annotations

from typing import Any

from .i18n import Translator


def _check(
    id: str,
    level: str,
    title: str,
    detail: str,
    action: str | None = None,
    settings_uri: str | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "level": level,
        "title": title,
        "detail": detail,
        "action": action,
        "settings_uri": settings_uri,
    }


def _bitlocker_on(value: Any) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"on", "1", "true"}:
        return True
    if normalized in {"off", "0", "false"}:
        return False
    return None


def evaluate_health(
    scan_data: dict[str, Any],
    health_data: dict[str, Any],
    *,
    language: str = "en",
) -> dict[str, Any]:
    tr = Translator(language)
    t = tr.t
    checks: list[dict[str, Any]] = []

    storage = health_data.get("storage", {})
    if storage.get("available"):
        pct = storage.get("percent_free")
        free_gb = (storage.get("free_bytes") or 0) / (1024 ** 3)
        if pct is not None and (pct < 10 or free_gb < 10):
            checks.append(_check(
                "storage",
                "warn",
                t("health.storage.title"),
                t("health.storage.low", pct=pct, free_gb=free_gb),
                t("health.storage.action_free"),
                "ms-settings:storagesense",
            ))
        elif pct is not None and pct < 20:
            checks.append(_check(
                "storage",
                "advisory",
                t("health.storage.title"),
                t("health.storage.review", pct=pct, free_gb=free_gb),
                t("health.storage.action_review"),
                "ms-settings:storagesense",
            ))
        else:
            checks.append(_check(
                "storage",
                "ok",
                t("health.storage.title"),
                t("health.storage.ok", pct=pct)
                if pct is not None
                else t("health.storage.available"),
            ))
    else:
        checks.append(_check(
            "storage",
            "info",
            t("health.storage.title"),
            t("health.storage.unavailable"),
        ))

    defender = health_data.get("defender", {})
    if defender.get("available"):
        antivirus = defender.get("antivirus_enabled")
        realtime = defender.get("real_time_protection")
        if antivirus is False or realtime is False:
            checks.append(_check(
                "defender",
                "warn",
                t("health.defender.title"),
                t("health.defender.off"),
                t("health.defender.action"),
                "windowsdefender:",
            ))
        elif antivirus is True and realtime is True:
            age = defender.get("signature_age_days")
            detail = t("health.defender.on")
            if isinstance(age, int):
                detail += t("health.defender.signatures", age=age)
            checks.append(_check(
                "defender",
                "ok",
                t("health.defender.title"),
                detail,
            ))
        else:
            checks.append(_check(
                "defender",
                "info",
                t("health.defender.title"),
                t("health.defender.partial"),
                t("health.defender.action"),
                "windowsdefender:",
            ))
    else:
        checks.append(_check(
            "defender",
            "info",
            t("health.defender.title"),
            t("health.defender.unavailable"),
            t("health.defender.action"),
            "windowsdefender:",
        ))

    bitlocker = health_data.get("bitlocker", {})
    if bitlocker.get("available"):
        protected = _bitlocker_on(bitlocker.get("protection_status"))
        if protected is True:
            checks.append(_check(
                "bitlocker",
                "ok",
                t("health.bitlocker.title"),
                t("health.bitlocker.on"),
            ))
        elif protected is False:
            checks.append(_check(
                "bitlocker",
                "advisory",
                t("health.bitlocker.title"),
                t("health.bitlocker.off"),
                t("health.bitlocker.action"),
                "ms-settings:deviceencryption",
            ))
        else:
            checks.append(_check(
                "bitlocker",
                "info",
                t("health.bitlocker.title"),
                t(
                    "health.bitlocker.status",
                    status=bitlocker.get("protection_status") or t("value.unknown"),
                ),
            ))
    else:
        checks.append(_check(
            "bitlocker",
            "info",
            t("health.bitlocker.title"),
            t("health.bitlocker.unavailable"),
        ))

    pending = health_data.get("pending_reboot", {})
    if pending.get("available") and pending.get("pending"):
        checks.append(_check(
            "pending-reboot",
            "advisory",
            t("health.reboot.title"),
            t("health.reboot.pending"),
            t("health.reboot.action"),
            "ms-settings:windowsupdate",
        ))
    elif pending.get("available"):
        checks.append(_check(
            "pending-reboot",
            "ok",
            t("health.reboot.title"),
            t("health.reboot.none"),
        ))
    else:
        checks.append(_check(
            "pending-reboot",
            "info",
            t("health.reboot.title"),
            t("health.reboot.unavailable"),
        ))

    startup = health_data.get("startup", {})
    if startup.get("available"):
        count = int(startup.get("count") or 0)
        if count >= 20:
            checks.append(_check(
                "startup",
                "advisory",
                t("health.startup.title"),
                t("health.startup.many", count=count),
                t("health.startup.action_many"),
                "ms-settings:startupapps",
            ))
        else:
            checks.append(_check(
                "startup",
                "ok",
                t("health.startup.title"),
                t("health.startup.count", count=count),
                t("health.startup.action_slow") if count else None,
                "ms-settings:startupapps" if count else None,
            ))
    else:
        checks.append(_check(
            "startup",
            "info",
            t("health.startup.title"),
            t("health.startup.unavailable"),
            t("health.startup.action_settings"),
            "ms-settings:startupapps",
        ))

    security = scan_data.get("system", {}).get("security", {})
    secure_boot = security.get("secure_boot", {})
    if secure_boot.get("enabled") is True:
        checks.append(_check(
            "secure-boot",
            "ok",
            t("health.secure_boot.title"),
            t("health.secure_boot.on"),
        ))
    elif secure_boot.get("enabled") is False:
        checks.append(_check(
            "secure-boot",
            "advisory",
            t("health.secure_boot.title"),
            t("health.secure_boot.off"),
            t("health.secure_boot.action"),
            "windowsdefender:",
        ))
    else:
        checks.append(_check(
            "secure-boot",
            "info",
            t("health.secure_boot.title"),
            t("health.secure_boot.unavailable"),
        ))

    tpm = security.get("tpm", {})
    if tpm.get("present") is True and tpm.get("ready") is True:
        checks.append(_check(
            "tpm",
            "ok",
            t("health.tpm.title"),
            t("health.tpm.ready"),
        ))
    elif tpm.get("present") is True:
        checks.append(_check(
            "tpm",
            "advisory",
            t("health.tpm.title"),
            t("health.tpm.not_ready"),
            t("health.tpm.action"),
            "windowsdefender:",
        ))
    elif tpm.get("present") is False:
        checks.append(_check(
            "tpm",
            "info",
            t("health.tpm.title"),
            t("health.tpm.not_present"),
        ))
    else:
        checks.append(_check(
            "tpm",
            "info",
            t("health.tpm.title"),
            t("health.tpm.unavailable"),
        ))

    counts = {"ok": 0, "info": 0, "advisory": 0, "warn": 0}
    for item in checks:
        counts[item["level"]] = counts.get(item["level"], 0) + 1

    if counts["warn"]:
        overall = "needs-attention"
        headline = t("headline.attention")
    elif counts["advisory"]:
        overall = "review"
        headline = t("headline.review")
    else:
        overall = "good"
        headline = t("headline.good")

    return {
        "overall": overall,
        "headline": headline,
        "summary": counts,
        "checks": checks,
        "language": language,
    }


def render_quick_check(
    data: dict[str, Any],
    *,
    language: str = "en",
) -> str:
    tr = Translator(language)
    t = tr.t
    summary = data.get("summary", {})
    lines = [
        t("quick.title"),
        "=" * len(t("quick.title")),
        data.get("headline", t("quick.completed")),
        t(
            "quick.summary",
            ok=summary.get("ok", 0),
            review=summary.get("advisory", 0),
            warn=summary.get("warn", 0),
            info=summary.get("info", 0),
        ),
        "",
    ]

    labels = {
        "ok": t("status.ok"),
        "info": t("status.info"),
        "advisory": t("status.advisory"),
        "warn": t("status.warn"),
    }
    for item in data.get("checks", []):
        label = labels.get(str(item.get("level")), t("status.info"))
        lines.append(f"[{label}] {item.get('title')}")
        lines.append(f"  {item.get('detail')}")
        if item.get("action"):
            lines.append(
                "  " + t("quick.suggestion", action=item.get("action"))
            )
        lines.append("")

    return "\n".join(lines).rstrip()
