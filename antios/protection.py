"""Truthful aggregate status for AntiOS antivirus protection layers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from .clamav import ClamAVScanner
from .coexistence import amsi_provider_status
from .guard_state import read_guard_state
from .private_core import (
    INTERFACE_VERSION as PRIVATE_CORE_INTERFACE_VERSION,
    PrivateCoreError,
    invoke_private_core,
)
from .windows_antivirus import coexistence_profile, defender_status
from .windows_process import hidden_process_kwargs, system_executable


def _managed_runtime_status() -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "windows-only"}
    program_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
    program_data = Path(os.environ.get("ProgramData") or r"C:\ProgramData")
    install = program_files / "AntiOS" / "ClamAV"
    data = program_data / "AntiOS-ClamAV"
    required = {
        "clamd": install / "clamd.exe",
        "freshclam": install / "freshclam.exe",
        "clamd_config": data / "config" / "clamd.conf",
        "freshclam_config": data / "config" / "freshclam.conf",
        "database": data / "database",
    }
    files = {key: path.exists() for key, path in required.items()}
    task = {"available": False}
    schtasks = system_executable("schtasks.exe")
    try:
        process = subprocess.run(
            [str(schtasks), "/Query", "/TN", "AntiOS ClamAV Signature Update", "/FO", "LIST"],
            stdin=subprocess.DEVNULL,
            # Only the exit code is needed; do not decode localized OEM text
            # with Python's potentially unrelated default encoding.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            **hidden_process_kwargs(),
        )
        task = {
            "available": process.returncode == 0,
            "exit_code": process.returncode,
        }
    except (OSError, subprocess.SubprocessError) as exc:
        task = {"available": False, "error": str(exc)[:300]}

    bootstrap_exit = None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\DargonITP\AntiOS") as key:
            bootstrap_exit = int(winreg.QueryValueEx(key, "ProtectionBootstrapExitCode")[0])
    except (OSError, ValueError):
        pass

    healthy = all(files.values()) and task.get("available") is True
    return {
        "available": install.exists(),
        "healthy": healthy,
        "install_root": str(install),
        "data_root": str(data),
        "files": files,
        "updater_task": task,
        "bootstrap_exit_code": bootstrap_exit,
    }


def _native_status() -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "windows-only"}
    program_files = os.environ.get("ProgramFiles")
    if not program_files:
        return {"available": False, "reason": "ProgramFiles unavailable"}
    executable = Path(program_files) / "AntiOSNative" / "AntiOS-Service.exe"
    if not executable.is_file():
        return {"available": False, "reason": "not-installed"}
    result = {"available": True, "path": str(executable)}
    for key, flag in (("service", "--status"), ("driver", "--driver-status")):
        try:
            process = subprocess.run(
                [str(executable), flag],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                **hidden_process_kwargs(),
            )
            payload = json.loads(process.stdout) if process.stdout.strip() else {}
            payload["exit_code"] = process.returncode
            if process.stderr.strip():
                payload["stderr"] = process.stderr.strip()[:500]
            result[key] = payload
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            result[key] = {"error": str(exc)[:500]}
    return result


def native_pre_execution_active(native: dict | None = None) -> bool | None:
    """Return truthful native pre-exec state, or None when it cannot be determined."""
    state = _native_status() if native is None else native
    if not isinstance(state, dict) or state.get("available") is False:
        return None
    service = state.get("service") if isinstance(state.get("service"), dict) else {}
    driver = state.get("driver") if isinstance(state.get("driver"), dict) else {}
    if "error" in service or "error" in driver:
        return None
    return bool(
        service.get("service_state") == 4 and
        service.get("exit_code") == 0 and
        driver.get("driver_available") is True and
        driver.get("exit_code") == 0 and
        driver.get("enforcement") == 1
    )


def _native_coexistence_health(native_running: bool, driver: dict) -> dict:
    configured = bool(
        native_running and
        driver.get("driver_available") is True and
        driver.get("exit_code") == 0 and
        isinstance(driver.get("protocol"), int) and
        driver.get("protocol") >= 4 and
        driver.get("coexistence_mode") == 1 and
        driver.get("fail_open_on_incomplete") is True and
        isinstance(driver.get("max_pending"), int) and
        1 <= driver.get("max_pending") <= 4 and
        isinstance(driver.get("pending"), int) and
        0 <= driver.get("pending") <= driver.get("max_pending") and
        isinstance(driver.get("clean_cache_ttl_ms"), int) and
        0 <= driver.get("clean_cache_ttl_ms") <= 300000 and
        isinstance(driver.get("database_generation"), int) and
        driver.get("database_generation") > 0
    )
    if not configured:
        return {
            "configured": False,
            "observed": False,
            "state": "inactive/not-validated",
            "attention_reasons": [],
        }

    counters = {}
    for key in (
        "attempts", "incomplete", "busy_bypass", "section_conflicts",
        "delivery_timeouts", "completion_timeouts", "cancelled_opens", "max_wait_ms",
        "cache_hits", "cache_expired", "cache_invalidations",
        "database_generation", "database_generation_changes",
    ):
        value = driver.get(key)
        counters[key] = value if isinstance(value, int) and value >= 0 else None

    attempts = counters["attempts"]
    reasons = []
    if counters["delivery_timeouts"]:
        reasons.append("delivery-timeouts")
    if counters["completion_timeouts"]:
        reasons.append("completion-timeouts")
    if counters["max_wait_ms"] is not None and counters["max_wait_ms"] > 15000:
        reasons.append("latency-ceiling-exceeded")

    if attempts is None:
        state = "configured-unmeasured"
        observed = False
    elif attempts == 0:
        state = "configured-unexercised"
        observed = False
    elif reasons:
        state = "attention"
        observed = True
    elif any(counters[key] for key in ("incomplete", "busy_bypass", "section_conflicts")):
        state = "operational-with-gaps"
        observed = True
    else:
        state = "operational"
        observed = True

    return {
        "configured": True,
        "observed": observed,
        "state": state,
        "attention_reasons": reasons,
        "telemetry": counters,
    }


def _private_core_protection_status(engine_service: str | None = None) -> dict | None:
    """Prefer the private core when its narrow public contract is available.

    The open implementation remains a migration fallback until the sensitive
    components have actually moved to the private repository.
    """
    payload = {}
    if engine_service is not None:
        payload["engine_service"] = engine_service
    try:
        result = invoke_private_core("protection.status", payload, timeout_seconds=10)
    except PrivateCoreError:
        return None

    if (
        result.get("schema") != 1
        or result.get("kind") != "antios-protection-status"
        or not isinstance(result.get("capabilities"), dict)
    ):
        return None
    status = dict(result)
    status["private_core"] = {
        "active": True,
        "interface": PRIVATE_CORE_INTERFACE_VERSION,
    }
    return status


def collect_protection_status(engine_service: str | None = None) -> dict:
    private_status = _private_core_protection_status(engine_service)
    if private_status is not None:
        return private_status

    engine: dict
    try:
        scanner = ClamAVScanner(
            service_name=engine_service,
            require_verified_peer=os.name == "nt",
            timeout=5,
        )
        try:
            engine = dict(scanner.metadata, available=True)
        finally:
            scanner.close()
    except (OSError, RuntimeError, ValueError) as exc:
        engine = {"available": False, "detail": str(exc)[:500]}

    guard = read_guard_state()
    managed = _managed_runtime_status()
    native = _native_status()
    defender = defender_status()
    coexistence = coexistence_profile(defender)
    amsi = amsi_provider_status()
    from .windows_companion import collect_windows_companion_status
    vendor_companion = collect_windows_companion_status() if os.name == "nt" else {
        "coexistence": {"vendor_products_detected": [], "vendor_realtime_confirmed": []},
        "products": [],
    }
    peer_ok = (not engine.get("peer_verification_required") or
               engine.get("peer_verified") is True)
    engine_ready = bool(
        engine.get("available") and
        engine.get("database_freshness") == "current" and
        peer_ok
    )
    guard_running = bool(
        guard.get("running") and
        guard.get("state") not in {"failed", "stopped", "unresponsive", "not-running"}
    )
    # A live Guard process can still have incomplete filesystem, engine or
    # process telemetry coverage. Do not count a degraded Guard as a verified
    # resident protection layer in the headline capability/coexistence status.
    guard_operational = bool(
        guard_running and guard.get("state") in {"monitoring", "attention", "scanning"}
        and not guard.get("capacity_exceeded")
        and not guard.get("inventory_issues")
        and not guard.get("behavior_alerts_dropped", 0)
    )
    behavior = guard.get("behavior", {}) if isinstance(guard.get("behavior"), dict) else {}
    risk = guard.get("risk", {}) if isinstance(guard.get("risk"), dict) else {}
    last_risk = risk.get("last") if isinstance(risk.get("last"), dict) else {}
    incidents = guard.get("incidents", {}) if isinstance(guard.get("incidents"), dict) else {}
    latest_incident = incidents.get("latest") if isinstance(incidents.get("latest"), dict) else {}
    behavior_monitoring = bool(
        guard_running and behavior.get("mode") == "detect-only"
    )
    behavior_process_visibility = bool(
        behavior_monitoring and behavior.get("collector") in {"toolhelp-snapshot", "injected"}
    )
    service = native.get("service", {})
    driver = native.get("driver", {})
    native_running = service.get("service_state") == 4 and service.get("exit_code") == 0
    native_health = _native_coexistence_health(native_running, driver)
    native_coexistence = native_health["configured"]
    pre_execution = native_pre_execution_active(native) is True
    antios_resident = bool(engine_ready and (guard_operational or pre_execution))
    defender_realtime = defender.get("realtime_active") is True
    layered_active = bool(defender_realtime and antios_resident)
    vendor_detected = vendor_companion["coexistence"].get("vendor_products_detected") or []
    vendor_realtime = vendor_companion["coexistence"].get("vendor_realtime_confirmed") or []
    layered_vendor = bool(engine_ready and vendor_realtime)
    amsi_registered = bool(amsi.get("registered") and amsi.get("module_exists"))
    coexistence = dict(coexistence)
    coexistence["layered_with_defender"] = layered_active
    coexistence["vendor_products_detected"] = vendor_detected
    coexistence["vendor_realtime_confirmed"] = vendor_realtime
    coexistence["layered_with_vendor"] = layered_vendor
    coexistence["vendor_mode"] = vendor_companion["coexistence"].get("mode")
    if layered_vendor:
        coexistence["mode"] = "vendor-companion-layered"
    elif layered_active:
        coexistence["mode"] = "layered"
    elif vendor_detected:
        coexistence["mode"] = "vendor-companion-detected"
    elif defender_realtime:
        coexistence["mode"] = "defender-active-antios-incomplete"

    blockers = []
    if not engine_ready:
        blockers.append("trusted-current-engine")
    if not guard_operational:
        blockers.append("resident-post-write-guard")
    if not pre_execution:
        blockers.append("signed-native-pre-execution-enforcement")
    # These are intentionally never inferred from local process state.
    blockers.extend(["windows-security-center-registration", "elam-ppl-production-approval"])

    return {
        "schema": 1,
        "kind": "antios-protection-status",
        "engine": engine,
        "guard": guard,
        "managed_runtime": managed,
        "native": native,
        "native_coexistence": native_health,
        "defender": defender,
        "windows_vendor_companion": vendor_companion,
        "coexistence": coexistence,
        "amsi": amsi,
        "risk": risk,
        "incidents": incidents,
        "capabilities": {
            "standalone_detection_engine": engine_ready,
            "resident_post_write_detection": guard_operational and engine_ready,
            "resident_post_write_partial": guard_running and not guard_operational,
            "behavior_monitoring": behavior_monitoring,
            "behavior_process_visibility": behavior_process_visibility,
            "risk_fusion": guard_running and risk.get("mode") == "fusion",
            "incident_graph": guard_running and incidents.get("mode") == "correlation-graph",
            "pre_execution_blocking": pre_execution and engine_ready,
            "native_coexistence_ready": native_coexistence,
            "native_coexistence_observed_operational": (
                native_health["state"] in {"operational", "operational-with-gaps"}
            ),
            "defender_dependency": False,
            "defender_realtime_active": defender_realtime,
            "layered_with_defender": layered_active,
            "third_party_vendor_detected": bool(vendor_detected),
            "third_party_vendor_realtime_confirmed": bool(vendor_realtime),
            "layered_with_vendor": layered_vendor,
            "amsi_provider_registered": amsi_registered,
            "amsi_provider_engine_ready": amsi_registered and engine_ready,
        },
        "production_primary_antivirus": False,
        "remaining_gates": blockers,
    }


def collect_linux_protection_status() -> dict:
    """Linux-specific companion protection view without changing Windows contracts."""
    engine: dict
    try:
        scanner = ClamAVScanner(require_verified_peer=False, timeout=5)
        try:
            engine = dict(scanner.metadata, available=True)
        finally:
            scanner.close()
    except (OSError, RuntimeError, ValueError) as exc:
        engine = {"available": False, "detail": str(exc)[:500]}

    guard = read_guard_state()
    from .linux_companion import collect_linux_companion_status
    companion = collect_linux_companion_status()
    peer_ok = (not engine.get("peer_verification_required") or
               engine.get("peer_verified") is True)
    engine_ready = bool(
        engine.get("available") and
        engine.get("database_freshness") == "current" and
        peer_ok
    )
    guard_running = bool(
        guard.get("running") and
        guard.get("state") not in {"failed", "stopped", "unresponsive", "not-running"}
    )
    vendor_realtime = companion["coexistence"]["vendor_realtime_confirmed"]
    blockers = []
    if not engine_ready:
        blockers.append("local-clamd-with-current-signatures")
    return {
        "schema": 1,
        "kind": "antios-linux-protection-status",
        "engine": engine,
        "guard": guard,
        "companion": companion,
        "capabilities": {
            "standalone_detection_engine": engine_ready,
            "on_demand_second_opinion": engine_ready,
            "resident_post_write_detection": guard_running and engine_ready,
            "vendor_realtime_confirmed": bool(vendor_realtime),
            "layered_with_vendor": bool(vendor_realtime and engine_ready),
            "storage_intelligence": True,
        },
        "production_primary_antivirus": False,
        "remaining_gates": blockers,
    }


def render_protection_status(status: dict) -> str:
    if status.get("kind") == "antios-linux-protection-status":
        caps = status["capabilities"]
        engine = status["engine"]
        guard = status["guard"]
        companion = status["companion"]["coexistence"]
        products = status["companion"]["products"]
        detected = companion["vendor_products_detected"]
        realtime = companion["vendor_realtime_confirmed"]
        return "\n".join([
            "AntiOS Linux protection status",
            f"Engine: {'ready' if caps['standalone_detection_engine'] else 'not ready'}"
            f" ({engine.get('version', engine.get('detail', 'unavailable'))})",
            f"Database: {engine.get('database_freshness', 'unknown')}",
            f"Vendor AV detected: {', '.join(detected) if detected else 'none'}",
            f"Vendor realtime confirmed: {', '.join(realtime) if realtime else 'none'}",
            f"Companion mode: {companion['mode']}",
            f"Resident Guard: {guard.get('state', 'not-running')} (opt-in)",
            "AntiOS role: supplemental second opinion; vendor settings unchanged",
            "Primary Linux antivirus role: not claimed",
            "Remaining gates: " + (", ".join(status["remaining_gates"]) or "none"),
        ])
    caps = status["capabilities"]
    engine = status["engine"]
    guard = status["guard"]
    managed = status.get("managed_runtime", {})
    native = status["native"]
    defender = status.get("defender", {})
    coexistence = status.get("coexistence", {})
    native_health = status.get("native_coexistence", {})
    amsi = status.get("amsi", {}) if isinstance(status.get("amsi"), dict) else {}
    vendor = status.get("windows_vendor_companion", {})
    vendor_coexist = vendor.get("coexistence", {}) if isinstance(vendor, dict) else {}
    vendor_detected = vendor_coexist.get("vendor_products_detected") or []
    vendor_realtime = vendor_coexist.get("vendor_realtime_confirmed") or []
    telemetry = native_health.get("telemetry", {})
    risk = status.get("risk", {}) if isinstance(status.get("risk"), dict) else {}
    last_risk = risk.get("last") if isinstance(risk.get("last"), dict) else {}
    incidents = status.get("incidents", {}) if isinstance(status.get("incidents"), dict) else {}
    latest_incident = incidents.get("latest") if isinstance(incidents.get("latest"), dict) else {}
    return "\n".join([
        "AntiOS protection status",
        f"Engine: {'ready' if caps['standalone_detection_engine'] else 'not ready'}"
        f" ({engine.get('version', engine.get('detail', 'unavailable'))})",
        f"Database: {engine.get('database_freshness', 'unknown')}",
        f"Engine identity: {engine.get('peer_identity', 'unknown')}",
        f"Resident Guard: {guard.get('state', 'not-running')}",
        "Behavior monitor: "
        f"{guard.get('behavior', {}).get('state', 'unavailable')} "
        f"({guard.get('behavior', {}).get('collector', 'unavailable')}, "
        f"score={guard.get('behavior', {}).get('highest_score', 0)}, "
        f"findings={guard.get('behavior', {}).get('recent_findings', 0)})",
        "Risk fusion: "
        f"{last_risk.get('classification', 'unavailable')} "
        f"(score={last_risk.get('score', 0)}, "
        f"origin={last_risk.get('origin', 'unknown')}, "
        f"native={last_risk.get('native_pre_execution', risk.get('native_pre_execution', 'unknown'))}, "
        f"auto-enforce={last_risk.get('automatic_enforcement_eligible', False)})",
        "Incident graph: "
        f"{incidents.get('state', 'unavailable')} "
        f"(active={incidents.get('active_incidents', 0)}, "
        f"score={incidents.get('highest_score', 0)}, "
        f"latest={latest_incident.get('id', 'none')}, "
        f"nodes={latest_incident.get('node_count', 0)}, "
        f"edges={latest_incident.get('edge_count', 0)})",
        f"Managed runtime: {'healthy' if managed.get('healthy') else 'needs review'}",
        f"Updater task: {'ready' if managed.get('updater_task', {}).get('available') else 'missing'}",
        f"Native service: {native.get('service', {}).get('service_state', 'not-running')}",
        f"Native coexistence: {native_health.get('state', 'inactive/not-validated')}",
        f"Native max wait: {native.get('driver', {}).get('max_wait_ms', 'unknown')} ms",
        "Native clean cache: "
        f"ttl={native.get('driver', {}).get('clean_cache_ttl_ms', 'unknown')} ms, "
        f"hits={telemetry.get('cache_hits', 'unknown')}, "
        f"expired={telemetry.get('cache_expired', 'unknown')}, "
        f"invalidations={telemetry.get('cache_invalidations', 'unknown')}, "
        f"db-gen={telemetry.get('database_generation', 'unknown')}, "
        f"db-changes={telemetry.get('database_generation_changes', 'unknown')}",
        "Native gaps: "
        f"busy={telemetry.get('busy_bypass', 'unknown')}, "
        f"section-conflicts={telemetry.get('section_conflicts', 'unknown')}, "
        f"delivery-timeouts={telemetry.get('delivery_timeouts', 'unknown')}, "
        f"completion-timeouts={telemetry.get('completion_timeouts', 'unknown')}",
        f"Pre-execution enforcement: {'active' if caps['pre_execution_blocking'] else 'inactive'}",
        f"Microsoft Defender: {'real-time active' if defender.get('realtime_active') else defender.get('running_mode', 'unavailable')}",
        f"Kaspersky / Dr.Web detected: {', '.join(vendor_detected) if vendor_detected else 'none'}",
        f"Vendor real-time confirmed: {', '.join(vendor_realtime) if vendor_realtime else 'none'}",
        f"Coexistence mode: {coexistence.get('mode', 'unknown')}",
        f"AntiOS AMSI provider: {'registered' if amsi.get('registered') and amsi.get('module_exists') else 'not registered'}",
        "AntiOS role: independent companion; Defender settings unchanged; Kaspersky/Dr.Web settings unchanged",
        "Primary Windows antivirus registration: not claimed",
        "Remaining gates: " + ", ".join(status["remaining_gates"]),
    ])
