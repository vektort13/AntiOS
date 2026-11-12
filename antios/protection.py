"""Truthful aggregate status for AntiOS antivirus protection layers."""
from __future__ import annotations

import os
import sqlite3

from .engine import AntiOSEngine
from .antivirus import load_managed_signatures
from .guard_state import read_guard_state
from .windows_defender import coexistence_profile, defender_status


def _engine_status() -> dict:
    try:
        rules, catalog = load_managed_signatures()
        scanner = AntiOSEngine(signatures=rules)
        try:
            return dict(scanner.metadata, available=True, **catalog)
        finally:
            scanner.close()
    except (OSError, RuntimeError, ValueError) as exc:
        return {"available": False, "detail": str(exc)[:500]}


def _managed_runtime_status(engine: dict | None = None) -> dict:
    """Report the health of the bundled engine and its selected catalog."""
    engine = _engine_status() if engine is None else engine
    if not engine["available"]:
        return dict(engine, healthy=False, inspection_complete=True, files={},
                    updater_task={"available": False})
    return {"available": True, "healthy": engine.get("signature_catalog_status") != "fallback",
            "inspection_complete": True,
            "kind": "bundled-antios-engine", "files": {},
            "updater_task": {"available": False, "not_required": True}}



def native_pre_execution_active(native: dict | None = None) -> bool | None:
    """No AntiOS Engine pre-execution backend is implemented."""
    return None


def _native_coexistence_health(native_running: bool, driver: dict) -> dict:
    """Legacy ClamAV driver cannot enforce AntiOS Engine verdicts."""
    return {"configured": False, "observed": False, "state": "inactive/not-implemented",
            "attention_reasons": [], "telemetry": {}}


def _legacy_registration_status(reader=None) -> dict:
    """Read fixed historical AntiOS registry markers without changing services."""
    if reader is None:
        if os.name != "nt":
            return {"available": False, "state": "not-applicable", "markers": []}
        import winreg

        def reader(path, name):
            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access) as key:
                return winreg.QueryValueEx(key, name)[0]

    clsid = "{8E8A9D7D-814F-4A83-A127-8C4894E41121}"
    probes = (
        (r"SOFTWARE\AntiOS", "EngineServiceName", "service-binding"),
        (r"SOFTWARE\DargonITP\AntiOS", "EngineServiceName", "service-binding"),
        (rf"SOFTWARE\Microsoft\AMSI\Providers\{clsid}", "", "amsi-registration"),
        (rf"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32", "", "amsi-registration"),
    )
    markers, complete = set(), True
    for path, name, marker in probes:
        try:
            value = reader(path, name)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            complete = False
            continue
        if isinstance(value, str) and value.strip():
            markers.add(marker)
    return {"available": True, "read_only": True,
            "state": ("attention" if markers else
                      "none-observed" if complete else "incomplete"),
            "markers": sorted(markers), "inspection_complete": complete}


def _guard_status() -> dict:
    try:
        return read_guard_state()
    except (OSError, ValueError, sqlite3.Error) as exc:
        return {"running": False, "state": "unavailable",
                "pre_execution_blocking": False,
                "detail": f"Guard state unreadable: {exc}"[:500]}


def collect_protection_status(engine_service: str | None = None) -> dict:
    # Use the installed AntiOS Engine, not a legacy external service.
    engine = _engine_status()

    # A denied/corrupt Guard state database must not make the entire protection
    # probe fail and be incorrectly reported as a ClamAV engine failure. Keep
    # the Guard explicitly unavailable (fail closed) while inspecting the other
    # independent layers.
    guard = _guard_status()
    managed = _managed_runtime_status(engine)
    # The previous native service is ClamAV-backed; it cannot enforce the
    # new AntiOS Engine's verdicts. Do not probe/credit it as native protection.
    native = {"available": False, "reason": "legacy-service-not-an-antios-engine-backend"}
    defender = defender_status()
    coexistence = coexistence_profile(defender)
    amsi = {"registered": False, "module_exists": False, "active": False}
    from .windows_companion import collect_windows_companion_status
    vendor_companion = collect_windows_companion_status() if os.name == "nt" else {
        "coexistence": {"vendor_products_detected": [], "vendor_realtime_confirmed": []},
        "products": [],
    }
    engine_ready = bool(engine.get("available") and
                        engine.get("database_freshness") == "local")
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
    native_running = False
    native_health = _native_coexistence_health(native_running, driver)
    native_coexistence = False
    # Legacy native service still depends on ClamAV; not our enforcement.
    pre_execution = False
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

    legacy = _legacy_registration_status()
    blockers = []
    if legacy.get("state") in {"attention", "incomplete"}:
        blockers.append("legacy-engine-registration-requires-migration")
    if not engine_ready:
        blockers.append("antios-native-engine")
    if not guard_operational:
        blockers.append("resident-post-write-guard")
    blockers.append("antios-native-pre-execution-enforcement-not-implemented")
    # These are intentionally never inferred from local process state.
    blockers.extend(["windows-security-center-registration", "elam-ppl-production-approval"])

    return {
        "schema": 1,
        "kind": "antios-protection-status",
        "engine": engine,
        "guard": guard,
        "managed_runtime": managed,
        "legacy_registrations": legacy,
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
    engine = _engine_status()

    guard = _guard_status()
    from .linux_companion import collect_linux_companion_status
    companion = collect_linux_companion_status()
    engine_ready = bool(engine.get("available") and
                        engine.get("database_freshness") == "local")
    guard_running = bool(
        guard.get("running") and
        guard.get("state") not in {"failed", "stopped", "unresponsive", "not-running"}
    )
    vendor_realtime = companion["coexistence"]["vendor_realtime_confirmed"]
    blockers = []
    if not engine_ready:
        blockers.append("antios-native-engine")
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
    engine = status["engine"]
    catalog_warning = engine.get("signature_catalog_warning")
    catalog_lines = []
    if engine.get("signature_catalog_version") is not None:
        catalog_lines.append(f"Signature catalog: v{engine['signature_catalog_version']}"
                             f" ({engine['signature_catalog_status']})")
    if catalog_warning:
        catalog_lines.append(catalog_warning)
    if status.get("kind") == "antios-linux-protection-status":
        caps = status["capabilities"]
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
            *catalog_lines,
            f"Vendor AV detected: {', '.join(detected) if detected else 'none'}",
            f"Vendor realtime confirmed: {', '.join(realtime) if realtime else 'none'}",
            f"Companion mode: {companion['mode']}",
            f"Resident Guard: {guard.get('state', 'not-running')} (opt-in)",
            "AntiOS role: supplemental second opinion; vendor settings unchanged",
            "Primary Linux antivirus role: not claimed",
            "Remaining gates: " + (", ".join(status["remaining_gates"]) or "none"),
        ])
    caps = status["capabilities"]
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
        *catalog_lines,
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
        f"Managed runtime: {'not fully inspected (access unavailable)' if managed.get('inspection_complete') is False else 'healthy' if managed.get('healthy') else 'needs review'}",
        "External engine updater task: not required",
        "Legacy registration markers: "
        + status.get("legacy_registrations", {}).get("state", "uninspected"),
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
        "AntiOS Engine: local inspection; no AMSI provider",
        "AntiOS role: independent companion; Defender settings unchanged; Kaspersky/Dr.Web settings unchanged",
        "Primary Windows antivirus registration: not claimed",
        "Remaining gates: " + ", ".join(status["remaining_gates"]),
    ])
