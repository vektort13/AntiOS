from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
from pathlib import Path

from .build_info import render_version, version_info
from .antivirus import (
    DEFAULT_SCAN_PROFILE, MAX_SCAN_WORKERS, SCAN_PROFILE_WORKERS, read_regular, render_antivirus_scan, scan_files,
)
from .config import default_config_path, load_config, write_default_config
from .consumer import evaluate_health, render_quick_check
from .core import (
    apply_plan,
    generate_plan,
    load_backup,
    restore,
    save_backup,
    scan,
    snapshot,
)
from .doctor import diagnose
from .health import collect_health
from .i18n import LANGUAGE_NAMES, detect_language
from .logging_utils import configure_logging
from .registry import WindowsRegistryBackend, is_windows
from .quarantine import Quarantine, default_quarantine_path
from .scan_cache import default_scan_cache_path
from .scan_verdict import MAX_REPLAY_BYTES, replay_scan_json
from .windows_defender import defender_action
from .report import render_doctor_human, render_operations_human, render_scan_human
from .storage_cleanup import (
    DEFAULT_DUPLICATE_MIN_BYTES,
    DEFAULT_LARGE_BYTES,
    DEFAULT_OLD_DAYS,
    default_scan_path,
    render_storage_scan,
    scan_storage,
)
from .system_name import WindowsComputerNameBackend
from .terminal import color_enabled


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _require_windows() -> None:
    if not is_windows():
        raise RuntimeError("AntiOS v2 Windows commands currently require Windows.")


def _backend() -> WindowsRegistryBackend:
    _require_windows()
    return WindowsRegistryBackend()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antios",
        description="AntiOS: antivirus companion, storage intelligence and system diagnostics",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=render_version(),
        help="Show AntiOS version and exit.",
    )
    parser.add_argument(
        "--config",
        help="Path to antios.toml. Defaults to the per-user configuration path.",
    )
    parser.add_argument(
        "--log-file",
        help="Override the configured log file for this invocation.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors for this invocation.",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    recovery = sub.add_parser("recovery", help="Create, extend, check and export bounded file backups.")
    recovery.add_argument("recovery_args", nargs=argparse.REMAINDER)
    guard = sub.add_parser("guard", help="Resident post-write scanning, status and stop control.")
    guard.add_argument("guard_args", nargs=argparse.REMAINDER,
                       help="run ROOT, status, stop or history; use run --help for options")

    protection_cmd = sub.add_parser(
        "protection-status",
        help="Show independent engine, resident Guard and native enforcement status.",
    )
    protection_cmd.add_argument("--json", action="store_true")

    coexist_cmd = sub.add_parser(
        "coexistence-status",
        help="Show read-only coexistence state (Defender on Windows; Kaspersky/Dr.Web on Linux).",
    )
    coexist_cmd.add_argument("--json", action="store_true")

    version_cmd = sub.add_parser("version", help="Show AntiOS and Python versions.")
    version_cmd.add_argument("--json", action="store_true")
    check_cmd = sub.add_parser("self-check", help="Run harmless local engine and backup functional checks.")
    check_cmd.add_argument("--json", action="store_true")
    check_cmd.add_argument("--language", choices=("en", "ru"), default="en")

    update_cmd = sub.add_parser(
        "update",
        help="Check for AntiOS updates or download/schedule a verified signed Setup.",
    )
    update_cmd.add_argument("--download-only", action="store_true",
                            help="Download and verify the newest Setup without launching it.")
    update_cmd.add_argument("--yes", action="store_true",
                            help="Download, verify and schedule the signed Setup after AntiOS exits.")
    update_cmd.add_argument("--directory", help="Optional directory for downloaded update files.")
    update_cmd.add_argument("--json", action="store_true")

    config_cmd = sub.add_parser("config", help="Inspect or initialize AntiOS configuration.")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    config_show = config_sub.add_parser("show", help="Show effective configuration.")
    config_show.add_argument("--json", action="store_true")
    config_init = config_sub.add_parser("init", help="Create a default configuration file.")
    config_init.add_argument("--force", action="store_true", help="Overwrite an existing config.")

    quick = sub.add_parser(
        "quick-check",
        aliases=["check"],
        help="Run a friendly platform health and protection check.",
    )
    quick.add_argument("--json", action="store_true")
    quick.add_argument(
        "--lang",
        choices=list(LANGUAGE_NAMES),
        help="Output language: en, ru, es, zh-CN, fi, pl, mn. Defaults to Windows locale.",
    )

    dashboard_cmd = sub.add_parser(
        "dashboard",
        help="Open the AntiOS desktop dashboard.",
    )
    dashboard_cmd.add_argument(
        "--lang",
        choices=list(LANGUAGE_NAMES),
        help="UI language: en, ru, es, zh-CN, fi, pl, mn. Defaults to Windows locale.",
    )

    storage_cmd = sub.add_parser(
        "storage-scan",
        aliases=["cleanup-scan"],
        help="Read-only scan for duplicate and cleanup-candidate files.",
    )
    storage_cmd.add_argument(
        "path",
        nargs="?",
        help="Folder to scan. Defaults to Downloads, or the user profile if Downloads is unavailable.",
    )
    storage_cmd.add_argument(
        "--old-days",
        type=int,
        default=DEFAULT_OLD_DAYS,
        help=f"Old-file threshold in days (default: {DEFAULT_OLD_DAYS}).",
    )
    storage_cmd.add_argument(
        "--large-mb",
        type=int,
        default=DEFAULT_LARGE_BYTES // (1024 * 1024),
        help=f"Large-file threshold in MB (default: {DEFAULT_LARGE_BYTES // (1024 * 1024)}).",
    )
    storage_cmd.add_argument(
        "--duplicate-min-mb",
        type=int,
        default=DEFAULT_DUPLICATE_MIN_BYTES // (1024 * 1024),
        help=f"Minimum duplicate file size in MB (default: {DEFAULT_DUPLICATE_MIN_BYTES // (1024 * 1024)}).",
    )
    storage_cmd.add_argument("--json", action="store_true")
    storage_cmd.add_argument("--background", action="store_true",
                             help="Optional maintenance: skip unless PC is idle on AC power.")

    history_cmd = sub.add_parser("storage-history", help="View, disable or clear MemoryMap history.")
    history_cmd.add_argument("action", choices=["status", "on", "off", "clear"])
    history_cmd.add_argument("--json", action="store_true")

    proof_cmd = sub.add_parser("storage-proof", help="Verify a Storage Cleanup backup and test a sandbox restore.")
    proof_cmd.add_argument("directory")
    proof_cmd.add_argument("--hash-only", action="store_true", help="Skip the sandbox restore test.")
    proof_cmd.add_argument("--json", action="store_true")

    preference_cmd = sub.add_parser("storage-preference", help="Set lightweight CleanupDNA recommendations.")
    preference_cmd.add_argument("category", choices=["duplicate", "old", "archive", "empty"])
    preference_cmd.add_argument("choice", choices=["prefer", "normal", "hide"])
    preference_cmd.add_argument("--json", action="store_true")

    av = sub.add_parser("virus-scan", help="Read-only, on-demand antivirus scan of a file or folder.")
    av.add_argument("path")
    av.add_argument("--engine", choices=("antios",), default="antios",
                    help="Independent AntiOS Engine (the only supported detection engine).")
    av.add_argument("--signatures", help="Override the signed catalog with a local schema-1 SHA-256 database.")
    av.add_argument("--max-mb", type=int, help="Optional per-file limit in MiB; larger files use bounded streaming.")
    av.add_argument("--max-files", type=int, help="Optional maximum number of files. Default: scan the entire selection.")
    av.add_argument("--profile", choices=tuple(SCAN_PROFILE_WORKERS), default=DEFAULT_SCAN_PROFILE,
                    help="Inspection depth and default workers (default: balanced).")
    av.add_argument("--workers", type=int, metavar="N",
                    help=f"Override the profile's workers, 1..{MAX_SCAN_WORKERS}, subject to CPU limits.")
    av.add_argument("--no-cache", action="store_true",
                    help="Do not reuse clean results for unchanged files.")
    av.add_argument("--json", action="store_true")

    replay = sub.add_parser("virus-scan-replay", help="Recompute the verdict from an exported AntiOS JSON report.")
    replay.add_argument("report", type=Path)
    replay.add_argument("--json", action="store_true")

    benchmark = sub.add_parser("virus-scan-benchmark", help="Check scan profiles on a labeled, inert control corpus.")
    benchmark.add_argument("--profile", choices=tuple(SCAN_PROFILE_WORKERS), help="Default: run all profiles.")
    benchmark.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    benchmark.add_argument("--json", action="store_true")

    catalog = sub.add_parser("signatures", help="Inspect or install a signed AntiOS signature catalog.")
    catalog_sub = catalog.add_subparsers(dest="signatures_command", required=True)
    catalog_status = catalog_sub.add_parser("status")
    catalog_status.add_argument("--json", action="store_true")
    catalog_install = catalog_sub.add_parser("install")
    catalog_install.add_argument("package", type=Path)
    catalog_install.add_argument("--json", action="store_true")

    quarantine_cmd = sub.add_parser("quarantine", help="Inspect, isolate or restore encrypted threats.")
    quarantine_sub = quarantine_cmd.add_subparsers(dest="quarantine_command", required=True)
    quarantine_list = quarantine_sub.add_parser("list")
    quarantine_list.add_argument("--json", action="store_true")
    quarantine_verify = quarantine_sub.add_parser("verify", help="Verify encrypted quarantine integrity.")
    quarantine_verify.add_argument("--json", action="store_true")
    quarantine_add = quarantine_sub.add_parser("add", help="Rescan a file, then preview or isolate a confirmed detection.")
    quarantine_add.add_argument("path")
    quarantine_add.add_argument("--engine", choices=("antios",), default="antios")
    quarantine_add.add_argument("--signatures")
    quarantine_add.add_argument("--yes", action="store_true")
    quarantine_add.add_argument("--json", action="store_true")
    quarantine_restore = quarantine_sub.add_parser("restore", help="Preview or restore a quarantined item without overwriting.")
    quarantine_restore.add_argument("id")
    quarantine_restore.add_argument("--to", help="Optional new destination; its parent must exist.")
    quarantine_restore.add_argument("--yes", action="store_true")
    quarantine_restore.add_argument("--json", action="store_true")

    defender_cmd = sub.add_parser("defender", help="Preview or run an allowlisted Microsoft Defender action.")
    defender_cmd.add_argument("action", choices=["quick", "full", "update"])
    defender_cmd.add_argument("--yes", action="store_true",
                              help="Run the operation using Defender's configured remediation/cloud policy.")
    defender_cmd.add_argument("--json", action="store_true")

    scan_cmd = sub.add_parser(
        "scan",
        help="Read Windows identity, version and platform-security metadata.",
    )
    scan_cmd.add_argument("--json", action="store_true")

    doctor_cmd = sub.add_parser(
        "doctor",
        help="Run technical runtime and Windows security/inventory diagnostics.",
    )
    doctor_cmd.add_argument("--json", action="store_true")

    plan = sub.add_parser("plan", help="Generate a reversible metadata-change plan.")
    plan.add_argument("--computer-name")
    plan.add_argument("--registered-owner")

    backup = sub.add_parser("backup", help="Back up v2-mutable metadata before a change.")
    backup.add_argument("path", nargs="?")

    apply_cmd = sub.add_parser("apply", help="Preview or apply a v2 metadata plan.")
    apply_cmd.add_argument("--computer-name")
    apply_cmd.add_argument("--registered-owner")
    apply_cmd.add_argument(
        "--yes",
        action="store_true",
        help="Actually write changes. Without --yes, apply is a dry run.",
    )
    apply_cmd.add_argument(
        "--backup",
        help="Backup path created immediately before a real write.",
    )
    apply_cmd.add_argument("--json", action="store_true")

    restore_cmd = sub.add_parser("restore", help="Preview or restore from a v2 backup.")
    restore_cmd.add_argument("path")
    restore_cmd.add_argument(
        "--yes",
        action="store_true",
        help="Actually restore. Without --yes, restore is a dry run.",
    )
    restore_cmd.add_argument("--json", action="store_true")

    return parser


def _render_config(config_path: Path, config: object) -> str:
    cfg = config.to_dict()
    general = cfg["general"]
    logging_cfg = cfg["logging"]
    ui = cfg["ui"]
    cleanup = cfg["cleanup"]
    return "\n".join([
        "AntiOS configuration",
        "====================",
        f"Path                  : {config_path}",
        f"Computer name prefix  : {general['computer_name_prefix']}",
        f"Default backup path   : {general['backup_path']}",
        f"Terminal color        : {general['color']}",
        f"Log level             : {logging_cfg['level']}",
        f"Log file              : {logging_cfg['file'] or '(disabled)'}",
        f"UI language           : {ui['language']}",
        f"UI theme              : {ui['theme']}",
        f"Cleanup old days      : {cleanup['old_days']}",
        f"Cleanup large MB      : {cleanup['large_mb']}",
        f"Duplicate minimum MB  : {cleanup['duplicate_min_mb']}",
        f"Remember cleanup path : {cleanup['remember_folder']}",
        f"Last cleanup path     : {cleanup['last_path'] or '(none)'}",
    ])


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = Path(args.config) if args.config else default_config_path()

    try:
        if args.command == "self-check":
            from .protection_check import run_checks, render_report
            report = run_checks()
            if args.json:
                _print_json(report)
            else:
                print(render_report(report, args.language))
            return 0 if report["status"] == "passed" else 1
        if args.command == "recovery":
            from .recovery import main as recovery_main
            return recovery_main(args.recovery_args)
        if args.command == "guard":
            from .guard import main as guard_main
            return guard_main(args.guard_args)
        if args.command == "config" and args.config_command == "init":
            created = write_default_config(config_path, overwrite=args.force)
            print(f"Created configuration: {created}")
            return 0

        config = load_config(config_path)
        log_file = args.log_file if args.log_file is not None else config.logging.file
        logger = configure_logging(config.logging.level, log_file)
        logger.info("command=%s", args.command)

        color_mode = "never" if args.no_color else config.general.color
        use_color = color_enabled(mode=color_mode)

        if args.command == "version":
            if args.json:
                _print_json(version_info())
            else:
                print(render_version())
            return 0

        if args.command == "update":
            if os.name != "nt":
                raise RuntimeError("Automatic AntiOS Setup updater currently requires Windows")
            if args.download_only and args.yes:
                raise ValueError("--download-only and --yes cannot be used together")
            from .updater import download_update, latest_alpha, schedule_install
            if not args.download_only and not args.yes:
                payload = latest_alpha()
            else:
                payload = download_update(args.directory, require_signature=args.yes)
                if args.yes and payload.get("downloaded"):
                    payload["installer"] = schedule_install(
                        payload["setup_path"], payload["sha256"]
                    )
            if args.json:
                _print_json(payload)
            else:
                print(f"Current: {payload.get('current_version')}")
                print(f"Latest: {payload.get('latest_version')}")
                print(f"Update available: {payload.get('update_available')}")
                if payload.get("downloaded"):
                    print(f"Verified Setup: {payload.get('setup_path')}")
                if payload.get("installer"):
                    print("Update scheduled. AntiOS Setup will start after this process exits.")
            return 0

        if args.command == "protection-status":
            from .protection import (
                collect_linux_protection_status,
                collect_protection_status,
                render_protection_status,
            )
            status = (
                collect_linux_protection_status()
                if sys.platform.startswith("linux")
                else collect_protection_status()
            )
            if args.json:
                _print_json(status)
            else:
                print(render_protection_status(status))
            return 0

        if args.command == "coexistence-status":
            from .coexistence import collect_coexistence_status, render_coexistence_status
            status = collect_coexistence_status()
            if args.json:
                _print_json(status)
            else:
                print(render_coexistence_status(status))
            return 0

        if args.command == "config":
            if args.config_command == "show":
                if args.json:
                    _print_json({
                        "path": str(config_path),
                        "config": config.to_dict(),
                    })
                else:
                    print(_render_config(config_path, config))
                return 0

        if args.command == "dashboard":
            if os.name != "nt" and not sys.platform.startswith("linux"):
                raise RuntimeError("AntiOS dashboard currently supports Windows and Linux")
            from .dashboard import main as dashboard_main
            dashboard_args = []
            if args.lang:
                dashboard_args.extend(["--lang", args.lang])
            return dashboard_main(dashboard_args)

        if args.command == "storage-history":
            from .storage_intelligence import StorageJournal
            with StorageJournal() as journal:
                if args.action == "on":
                    journal.set_history_enabled(True)
                elif args.action == "off":
                    journal.set_history_enabled(False)
                elif args.action == "clear":
                    journal.clear_history()
                payload = {"enabled": journal.history_enabled(), "action": args.action}
            if args.json:
                _print_json(payload)
            else:
                print(f"MemoryMap: {'enabled' if payload['enabled'] else 'disabled'}; {args.action}")
            return 0

        if args.command == "storage-preference":
            from .storage_intelligence import StorageJournal
            with StorageJournal() as journal:
                journal.set_preference(args.category, args.choice)
                payload = journal.preferences()
            if args.json:
                _print_json(payload)
            else:
                print(f"CleanupDNA: {args.category} = {args.choice}")
            return 0

        if args.command == "storage-proof":
            from .backup_proof import prove_cleanup_backup
            payload = prove_cleanup_backup(args.directory, restore_sample=not args.hash_only)
            if args.json:
                _print_json(payload)
            else:
                print(f"RecoveryProof: {payload['status']} ({payload['verified']}/{payload['entries']} verified)")
                if payload['errors']:
                    print("Problems: " + "; ".join(payload['errors'][:10]))
            return 0 if not payload['errors'] else 2

        if args.command in {"storage-scan", "cleanup-scan"}:
            from .storage_intelligence import background_permission, insights_for_scan
            if args.background:
                permission = background_permission()
                if not permission['allowed']:
                    if args.json:
                        _print_json({"skipped": True, "reason": permission['reason']})
                    else:
                        print('SmartSleep: skipped maintenance: ' + permission['reason'])
                    return 0
            target = Path(args.path).expanduser() if args.path else default_scan_path()
            result = scan_storage(
                target,
                old_days=args.old_days,
                large_bytes=args.large_mb * 1024 * 1024,
                duplicate_min_bytes=args.duplicate_min_mb * 1024 * 1024,
            )
            result["intelligence"] = insights_for_scan(result)
            logger.info(
                "storage-scan path=%s files=%d duplicate_groups=%d",
                target,
                result.get("summary", {}).get("files_scanned", 0),
                result.get("summary", {}).get("duplicate_groups", 0),
            )
            if args.json:
                _print_json(result)
            else:
                print(render_storage_scan(result))
                info = result['intelligence']
                trend = info['history']
                print('MemoryMap / TimeDebt: ' + trend['forecast'])
                if trend.get('bytes_per_day') is not None:
                    print(f"  Estimated directory change/day: {trend['bytes_per_day']} bytes")
                print('Survival: ' + str(info['survival']['candidates_without_verified_independent_copy']) +
                      ' cleanup candidates without a verified independent copy in this scan')
            return 0

        if args.command == "signatures":
            from .signature_catalog import install_catalog, load_active_catalog
            catalog = (install_catalog(args.package) if args.signatures_command == "install"
                       else load_active_catalog())
            if args.json:
                _print_json(catalog.metadata())
            else:
                print(f"AntiOS signature catalog v{catalog.version} ({catalog.published}) · "
                      f"{len(catalog.rules)} hashes · {catalog.source}")
                if catalog.warning:
                    print(catalog.warning)
            return 3 if catalog.warning else 0

        if args.command == "virus-scan":
            result = scan_files(args.path, signature_path=args.signatures,
                                engine=args.engine,
                                require_verified_peer=False,
                                max_bytes=(args.max_mb * 1024 * 1024 if args.max_mb is not None
                                           else None),
                                max_files=args.max_files,
                                workers=args.workers,
                                profile=args.profile,
                                cache_path=default_scan_cache_path(),
                                use_cache=not args.no_cache,
                                excluded_paths=(default_quarantine_path(),))
            if sys.platform.startswith("linux"):
                from .linux_companion import collect_linux_companion_status
                result["companion"] = collect_linux_companion_status()["coexistence"]
            if args.json:
                _print_json(result)
            else:
                print(render_antivirus_scan(result))
            logger.info("virus-scan verdict=%s scanned=%d threats=%d", result["verdict"],
                        result["summary"]["files_scanned"], result["summary"]["threats"])
            # 0: fully scanned/no findings, 1: threats/review, 3: incomplete/limited.
            return 1 if result["findings"] else (0 if result["verdict"] == "no-threats-found" else 3)

        if args.command == "virus-scan-replay":
            data, _ = read_regular(args.report, MAX_REPLAY_BYTES)
            replayed = replay_scan_json(data)
            if args.json:
                _print_json(replayed)
            else:
                print(f"Replayed verdict: {replayed['verdict']} ({replayed['policy']})")
                for key, value in replayed["dimensions"].items():
                    print(f"{key}: {value}")
            return 0

        if args.command == "virus-scan-benchmark":
            from .scan_benchmark import run_detection_benchmark

            benchmark = run_detection_benchmark(profile=args.profile, repeat=args.repeat)
            if args.json:
                _print_json(benchmark)
            else:
                for profile, result in benchmark["profiles"].items():
                    replay_status = "stable replay" if result["stable_replay"] else "replay mismatch"
                    print(f"{profile}: {result['passed']}/{result['total']} control cases passed, "
                          f"median {result['median_seconds']:.3f} s, {replay_status}")
                    for case in result["cases"]:
                        if not case["passed"]:
                            print(f"  {case['name']}: expected {case['expected']}, observed {case['observed']}")
            return 0 if benchmark["passed"] else 1

        if args.command == "quarantine":
            if os.name != "nt":
                raise RuntimeError("AntiOS encrypted quarantine currently requires Windows DPAPI")
            store = Quarantine()
            if args.quarantine_command == "list":
                payload = {"items": store.list_items()}
            elif args.quarantine_command == "verify":
                payload = store.verify_all()
            elif args.quarantine_command == "restore":
                payload = store.restore(args.id, destination=args.to, dry_run=not args.yes)
            else:
                result = scan_files(args.path, signature_path=args.signatures,
                                    engine=args.engine,
                                    require_verified_peer=False,
                                    excluded_paths=(default_quarantine_path(),))
                if not Path(args.path).is_file():
                    raise ValueError("Quarantine add requires one file")
                findings = [f for f in result["findings"] if f["kind"] == "threat"]
                if len(findings) != 1:
                    raise ValueError("No confirmed detection; file was not quarantined")
                payload = store.add(findings[0], dry_run=not args.yes)
            if args.json:
                _print_json(payload)
            else:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        if args.command == "defender":
            _require_windows()
            payload = defender_action(args.action) if args.yes else {
                "action": args.action, "dry_run": True,
                "note": "Use --yes to run. Scans follow Defender's remediation policy; results are in Windows Security.",
            }
            _print_json(payload)
            return 0

        if args.command in {"quick-check", "check"} and sys.platform.startswith("linux"):
            from .linux_health import collect_linux_health, render_linux_health
            payload = collect_linux_health()
            if args.json:
                _print_json(payload)
            else:
                print(render_linux_health(payload))
            return 0

        backend = _backend()
        computer_backend = WindowsComputerNameBackend()

        if args.command in {"quick-check", "check"}:
            language = args.lang or detect_language()
            scan_data = scan(backend)
            health_data = collect_health()
            result = evaluate_health(
                scan_data,
                health_data,
                language=language,
            )
            payload = {
                "scan": scan_data,
                "health": health_data,
                "evaluation": result,
            }
            if args.json:
                _print_json(payload)
            else:
                print(render_quick_check(result, language=language))
            logger.info(
                "quick-check overall=%s warnings=%d review=%d",
                result.get("overall"),
                result.get("summary", {}).get("warn", 0),
                result.get("summary", {}).get("advisory", 0),
            )
            return 1 if result.get("summary", {}).get("warn", 0) else 0

        if args.command == "scan":
            data = scan(backend)
            if args.json:
                _print_json(data)
            else:
                print(render_scan_human(data, color=use_color))
            return 0

        if args.command == "doctor":
            data = diagnose(scan(backend))
            if args.json:
                _print_json(data)
            else:
                print(render_doctor_human(data, color=use_color))
            return int(data.get("exit_code", 0))

        if args.command == "plan":
            _print_json(generate_plan(
                args.computer_name,
                args.registered_owner,
                computer_name_prefix=config.general.computer_name_prefix,
            ).to_dict())
            return 0

        if args.command == "backup":
            target = args.path or config.general.backup_path
            out = save_backup(target, snapshot(backend, computer_backend))
            logger.info("backup-created path=%s", out)
            _print_json({"backup": str(out.resolve())})
            return 0

        if args.command == "apply":
            plan_data = generate_plan(
                args.computer_name,
                args.registered_owner,
                computer_name_prefix=config.general.computer_name_prefix,
            )
            dry_run = not args.yes
            backup_path: Path | None = None
            backup_target = args.backup or config.general.backup_path

            if not dry_run:
                if not _is_admin():
                    raise PermissionError("Administrator privileges are required for system writes.")
                backup_path = save_backup(
                    backup_target,
                    snapshot(backend, computer_backend),
                ).resolve()
                logger.info("apply backup-created path=%s", backup_path)

            operations = apply_plan(
                backend,
                plan_data,
                computer_backend=computer_backend,
                dry_run=dry_run,
            )
            logger.info(
                "apply dry_run=%s changed=%d reboot=%s",
                dry_run,
                sum(1 for item in operations if item.get("changed")),
                any(item.get("changed") and item.get("requires_reboot") for item in operations),
            )
            payload = {
                "plan": plan_data.to_dict(),
                "operations": operations,
                "backup": str(backup_path) if backup_path else None,
                "note": (
                    "Dry run only. Re-run with --yes to write."
                    if dry_run
                    else "Changes written."
                ),
            }

            if args.json:
                _print_json(payload)
            else:
                print(render_operations_human(
                    operations,
                    title="AntiOS v2 apply plan",
                    dry_run=dry_run,
                    color=use_color,
                ))
                if backup_path:
                    print(f"Backup: {backup_path}")
            return 0

        if args.command == "restore":
            dry_run = not args.yes
            if not dry_run and not _is_admin():
                raise PermissionError("Administrator privileges are required for system writes.")

            data = load_backup(args.path)
            operations = restore(
                backend,
                data,
                computer_backend=computer_backend,
                dry_run=dry_run,
            )
            logger.info(
                "restore dry_run=%s changed=%d reboot=%s",
                dry_run,
                sum(1 for item in operations if item.get("changed")),
                any(item.get("changed") and item.get("requires_reboot") for item in operations),
            )
            payload = {
                "operations": operations,
                "note": "Dry run only." if dry_run else "Restore completed.",
            }

            if args.json:
                _print_json(payload)
            else:
                print(render_operations_human(
                    operations,
                    title="AntiOS v2 restore plan",
                    dry_run=dry_run,
                    color=use_color,
                ))
            return 0

    except (OSError, RuntimeError, PermissionError, ValueError) as exc:
        from .diagnostics import classify_error, record_event
        operation = str(getattr(args, "command", "cli") or "cli")
        component = (
            "AntiOS Engine" if operation.startswith("protection") or operation == "signatures" else
            "Scanner" if operation.startswith("virus-scan") else
            "Updater" if operation == "update" else "System"
        )
        record_event(component, "ERROR", str(exc),
                     code=classify_error(str(exc), component=component),
                     context={"operation": operation})
        try:
            logger.error("command failed: %s", exc)
        except UnboundLocalError:
            pass
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 1
