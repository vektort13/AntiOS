from __future__ import annotations

from typing import Any

from .terminal import paint


def _yn(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _value(value: Any) -> str:
    return "unknown" if value in (None, "") else str(value)


def _status_word(level: str) -> str:
    return {
        "ok": "OK",
        "info": "INFO",
        "advisory": "NOTE",
        "warn": "WARN",
    }.get(level, level.upper())


def render_scan_human(data: dict[str, Any], color: bool = False) -> str:
    info = data.get("system", {})
    host = info.get("host", {})
    win = info.get("windows", {})
    sec = info.get("security", {})
    runtime = info.get("runtime", {})

    secure_boot = sec.get("secure_boot", {})
    tpm = sec.get("tpm", {})

    title = paint("AntiOS v2 system scan", "heading", color)
    lines = [
        title,
        "======================",
        "",
        paint("Host", "heading", color),
        f"  Computer name : {_value(host.get('computer_name'))}",
        f"  User          : {_value(host.get('user'))}",
        f"  Architecture  : {_value(host.get('architecture'))}",
        f"  Processor     : {_value(host.get('processor'))}",
        "",
        paint("Windows", "heading", color),
        f"  Generation    : {_value(win.get('generation'))}",
        f"  Product       : {_value(win.get('product_name'))}",
        f"  Edition       : {_value(win.get('edition_id'))}",
        f"  Version       : {_value(win.get('display_version'))}",
        f"  Build         : {_value(win.get('full_build'))}",
        f"  Install type  : {_value(win.get('installation_type'))}",
        f"  Owner         : {_value(win.get('registered_owner'))}",
        "",
        paint("Platform security", "heading", color),
        f"  Secure Boot   : {_yn(secure_boot.get('enabled'))}",
        f"  TPM present   : {_yn(tpm.get('present'))}",
        f"  TPM ready     : {_yn(tpm.get('ready'))}",
        f"  TPM enabled   : {_yn(tpm.get('enabled'))}",
        f"  TPM activated : {_yn(tpm.get('activated'))}",
        f"  TPM vendor    : {_value(tpm.get('manufacturer'))}",
        f"  TPM version   : {_value(tpm.get('version'))}",
        "",
        paint("Runtime", "heading", color),
        f"  Python        : {_value(runtime.get('python'))}",
        f"  Implementation: {_value(runtime.get('python_implementation'))}",
        "",
        paint("Read-only identifiers", "heading", color),
    ]

    for entry in data.get("registry", []):
        target = entry.get("target", {})
        name = target.get("name", "unknown")
        description = target.get("description") or ""
        value = entry.get("value") if entry.get("exists") else None
        suffix = f" — {description}" if description else ""
        lines.append(f"  {name}: {_value(value)}{suffix}")

    return "\n".join(lines)


def render_doctor_human(data: dict[str, Any], color: bool = False) -> str:
    lines = [
        paint("AntiOS v2 doctor", "heading", color),
        "================",
        "",
    ]

    for check in data.get("checks", []):
        level = str(check.get("level", "info"))
        label = paint(f"[{_status_word(level):4}]", level, color)
        lines.append(f"{label} {check.get('title', 'Check')}")
        detail = check.get("detail")
        if detail:
            lines.append(f"       {detail}")

    summary = data.get("summary", {})
    lines.extend([
        "",
        paint("Summary", "heading", color),
        (
            f"  OK: {summary.get('ok', 0)} | "
            f"Notes: {summary.get('advisory', 0)} | "
            f"Info: {summary.get('info', 0)} | "
            f"Warnings: {summary.get('warn', 0)}"
        ),
    ])
    return "\n".join(lines)


def _short_target(target: str) -> str:
    if target.endswith("::RegisteredOwner"):
        return "RegisteredOwner"
    if target.endswith("::ComputerName"):
        if "ActiveComputerName" in target:
            return "ComputerName(active)"
        return "ComputerName"
    return target.rsplit("::", 1)[-1]


def render_operations_human(
    operations: list[dict[str, Any]],
    *,
    title: str,
    dry_run: bool,
    color: bool = False,
) -> str:
    headers = ("Change", "Before", "After", "Reboot")
    rows: list[tuple[str, str, str, str]] = []
    for item in operations:
        rows.append((
            _short_target(str(item.get("target", ""))),
            _value(item.get("before")),
            _value(item.get("after")),
            "yes" if item.get("requires_reboot") else "no",
        ))

    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = min(max(widths[index], len(cell)), 36)

    def clipped(value: str, width: int) -> str:
        if len(value) <= width:
            return value
        if width <= 3:
            return value[:width]
        return value[: width - 3] + "..."

    def line(row: tuple[str, str, str, str]) -> str:
        cells = [
            clipped(cell, widths[index]).ljust(widths[index])
            for index, cell in enumerate(row)
        ]
        return "  " + " | ".join(cells)

    mode = "DRY RUN" if dry_run else "APPLY"
    lines = [
        paint(title, "heading", color),
        paint(f"Mode: {mode}", "advisory" if dry_run else "warn", color),
        "",
        line(headers),
        "  " + "-+-".join("-" * width for width in widths),
    ]
    lines.extend(line(row) for row in rows)

    changed = sum(1 for item in operations if item.get("changed"))
    reboot = any(item.get("changed") and item.get("requires_reboot") for item in operations)
    lines.extend([
        "",
        f"Changed entries: {changed}/{len(operations)}",
    ])
    if reboot:
        lines.append(
            paint(
                "A computer-name change requires a Windows restart before all components observe the new name.",
                "advisory",
                color,
            )
        )
    if dry_run:
        lines.append("No registry values were written.")
    return "\n".join(lines)
