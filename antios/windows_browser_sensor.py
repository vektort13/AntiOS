"""Read-only Chrome and Edge extension and registration inventory."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re

from .antivirus import checked_path, read_regular
from .security_sensors import (
    Acquisition, BudgetGuard, CapabilityState, Coverage, SensorDescriptor,
    SensorReport, Surface, sensor_evidence,
)


_EXTENSION_ID = re.compile(r"[a-p]{32}\Z")
_PROFILE = re.compile(r"(?:Default|Profile [0-9]+)\Z")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}(?:_[0-9]+)?\Z")
_HOST_NAME = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)*\Z")
_BROWSERS = {
    "chrome": ("Google/Chrome/User Data", r"Google\Chrome"),
    "edge": ("Microsoft/Edge/User Data", r"Microsoft\Edge"),
}
_MAX_MANIFEST_BYTES = 256 * 1024


@dataclass
class _Coverage:
    errors: int = 0
    skipped: int = 0
    limited: bool = False


def _directories(root, pattern, budget, coverage):
    try:
        with os.scandir(checked_path(root)) as entries:
            for entry in entries:
                if not budget.take():
                    coverage.limited = True
                    break
                if pattern.fullmatch(entry.name):
                    if entry.is_dir(follow_symlinks=False):
                        yield Path(entry.path)
                    else:
                        coverage.skipped += 1
    except FileNotFoundError:
        return
    except (OSError, ValueError):
        coverage.errors += 1


def _extensions(root, budget, max_bytes, coverage):
    # Each manifest occupies the fifth relative level under User Data.
    for profile in _directories(root, _PROFILE, budget, coverage):
        for extension in _directories(profile / "Extensions", _EXTENSION_ID, budget, coverage):
            for version in _directories(extension, _VERSION, budget, coverage):
                remaining = min(_MAX_MANIFEST_BYTES, max_bytes - budget.bytes)
                if not remaining or not budget.can_take():
                    coverage.limited = True
                    return
                try:
                    data, _ = read_regular(version / "manifest.json", remaining)
                    if not budget.take(byte_count=len(data)):
                        coverage.limited = True
                        return
                    manifest = json.loads(data)
                    if not isinstance(manifest, dict) or manifest.get("manifest_version") not in (2, 3):
                        raise ValueError("Invalid Chromium extension manifest")
                except (OSError, ValueError, RecursionError):
                    coverage.errors += 1
                    continue
                permissions = manifest.get("permissions")
                hosts = manifest.get("host_permissions")
                permissions = permissions if isinstance(permissions, list) else []
                hosts = hosts if isinstance(hosts, list) else []
                yield extension.name, {
                    "manifest_version": manifest["manifest_version"],
                    "native_messaging_permission": "nativeMessaging" in permissions,
                    "all_sites_permission": any(
                        entry in ("<all_urls>", "*://*/*", "https://*/*", "http://*/*")
                        for entry in (*permissions, *hosts) if isinstance(entry, str)
                    ),
                }


def _registry_entries(vendor, budget, max_bytes, coverage):
    import winreg

    keys = (
        ("native-host", rf"SOFTWARE\{vendor}\NativeMessagingHosts"),
        ("forced-extension", rf"SOFTWARE\Policies\{vendor}\ExtensionInstallForcelist"),
    )
    seen = set()
    for hive, scope in ((winreg.HKEY_CURRENT_USER, "user"), (winreg.HKEY_LOCAL_MACHINE, "machine")):
        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            for kind, path in keys:
                if not budget.can_take():
                    coverage.limited = True
                    return
                try:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
                        subkeys, values, _ = winreg.QueryInfoKey(key)
                        size = subkeys if kind == "native-host" else values
                        for index in range(size):
                            if not budget.take():
                                coverage.limited = True
                                return
                            if kind == "native-host":
                                # Inventory only. Do not follow the registered manifest path.
                                entry = winreg.EnumKey(key, index)
                                valid = len(entry) <= 255 and _HOST_NAME.fullmatch(entry)
                            else:
                                _, value, value_type = winreg.EnumValue(key, index)
                                if value_type != winreg.REG_SZ or not isinstance(value, str):
                                    coverage.skipped += 1
                                    continue
                                value_bytes = len(value.encode("utf-16-le", errors="surrogatepass"))
                                if value_bytes > max_bytes - budget.bytes or not budget.take(
                                    items=0, byte_count=value_bytes,
                                ):
                                    coverage.limited = True
                                    return
                                entry = value.split(";", 1)[0].strip()
                                valid = _EXTENSION_ID.fullmatch(entry)
                            record = kind, scope, entry
                            if valid and record not in seen:
                                seen.add(record)
                                yield record
                            elif not valid:
                                coverage.skipped += 1
                except FileNotFoundError:
                    continue
                except OSError:
                    coverage.errors += 1


class WindowsBrowserSensor:
    descriptor = SensorDescriptor(
        "antios.browser", Surface.BROWSER, Acquisition.QUERY,
        capability=CapabilityState.AVAILABLE, experimental=False,
    )

    def __init__(self, local_app_data=None, *, registry_entries=_registry_entries):
        self.local_app_data = Path(local_app_data or os.environ.get("LOCALAPPDATA")
                                   or Path.home() / "AppData/Local")
        self.registry_entries = registry_entries

    def collect(self, context):
        budget = BudgetGuard(context.budget)
        coverage = _Coverage()
        evidence = []
        for browser, (relative, vendor) in _BROWSERS.items():
            if context.budget.max_depth < 5:
                coverage.limited = True
            else:
                installed = {}
                for extension, attributes in _extensions(
                    self.local_app_data / relative, budget, context.budget.max_bytes, coverage,
                ):
                    observed = installed.setdefault(extension, attributes)
                    # Several versions/profiles can coexist during updates.
                    observed["manifest_version"] = max(
                        observed["manifest_version"], attributes["manifest_version"],
                    )
                    for key in ("native_messaging_permission", "all_sites_permission"):
                        observed[key] |= attributes[key]
                for extension, attributes in installed.items():
                    evidence.append(sensor_evidence(
                        self.descriptor, context, kind="browser",
                        subject=f"{browser}:extension:{extension}", rule_id="browser.extension-on-disk",
                        detail="Extension files present in a standard browser profile",
                        attributes={"browser": browser, "extension_id": extension, **attributes},
                    ))
            for kind, scope, entry in self.registry_entries(
                vendor, budget, context.budget.max_bytes, coverage,
            ):
                evidence.append(sensor_evidence(
                    self.descriptor, context, kind="browser", subject=f"{browser}:{kind}:{entry}",
                    rule_id=f"browser.{kind}", detail="Browser registry registration",
                    attributes={"browser": browser, "registry_scope": scope, "identifier": entry},
                ))

        reason = "Chrome and Edge standard profiles and selected registry keys. Activation is unverified"
        if coverage.limited or budget.expired():
            reason += ". Collection reached a budget"
        if coverage.errors or coverage.skipped:
            reason += ". Some entries could not be inspected"
        return SensorReport(
            self.descriptor, Coverage.PARTIAL, tuple(evidence), reason=reason,
            inspected_items=budget.items, inspected_bytes=budget.bytes,
            skipped_items=coverage.skipped, error_items=coverage.errors,
        )
