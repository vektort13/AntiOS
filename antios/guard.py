"""Resident, current-user post-write detection. Never claims pre-execution blocking."""
from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass
import errno
import json
import os
import queue
import re
from pathlib import Path
import sqlite3
import stat
import sys
import threading
import time
import uuid

from .antivirus import checked_path, fingerprint, is_link
from .behavior import BehaviorEngine
from .coexistence import companion_protected_roots, defender_protected_roots
from .detection_signatures import DEFAULT_DETECTION_SIGNATURES
from .evidence import EvidenceBus
from .incident import IncidentGraph
from .guard_notifications import ChangeBatch, DirectoryNotifications, PollNotifications
from .guard_state import GuardState, default_guard_path, read_guard_state
from .quarantine import Quarantine, default_quarantine_path
from .risk import evaluate_risk
from .scan_process import run_scan_process
from .security_sensors import (
    CoverageSummary, ScanBudget, ScanContext, Surface, runtime_registry,
)
from .windows_process import hidden_process_kwargs


# Files that commonly become an execution boundary should reach the scanner
# sooner than ordinary documents. This is still post-write protection: the
# signed native minifilter remains the only AntiOS pre-execution enforcement
# path. Early scans are revalidated and rescanned when bytes keep changing.
_FAST_SCAN_SUFFIXES = frozenset({
    ".exe", ".dll", ".com", ".scr", ".sys", ".msi", ".msp",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".lnk", ".url",
})
_FAST_SETTLE_SECONDS = 0.20
_MAX_TRANSIENT_SCAN_RETRIES = 3
_DEFAULT_GUARD_INTERVAL = 15 if os.name != "nt" else 2
_DEFAULT_GUARD_RESCAN = 1800 if os.name != "nt" else 900
_DEEP_INITIAL_DELAY = 15.0
_DEEP_RUNTIME_INTERVAL = 60.0
_DEEP_PERSISTENCE_INTERVAL = 300.0
_DEEP_PLATFORM_INTERVAL = 300.0


def _transient_scan_conflict(exc: BaseException) -> bool:
    """Return True for short-lived file ownership conflicts common with parallel AVs."""
    if not isinstance(exc, OSError):
        return False
    if getattr(exc, "winerror", None) in {32, 33}:  # sharing / lock violation
        return True
    return getattr(exc, "errno", None) in {errno.EAGAIN, errno.EBUSY, getattr(errno, "ETXTBSY", -1)}


@dataclass(frozen=True)
class GuardPolicy:
    roots: tuple[Path, ...]
    auto_quarantine: bool = False
    interval: float = _DEFAULT_GUARD_INTERVAL
    settle: float = 1
    rescan: float = _DEFAULT_GUARD_RESCAN
    max_files: int = 50000
    max_queue: int = 256
    engine_service: str | None = None
    scan_engine: str = "antios"

    def validate(self):
        if not 1 <= len(self.roots) <= 16:
            raise ValueError('Select 1..16 directories')
        if not 0.1 <= self.interval <= 60 or not 0 <= self.settle <= 10 or not 30 <= self.rescan <= 86400:
            raise ValueError('Invalid guard time limits')
        if not 1 <= self.max_files <= 100000 or not 1 <= self.max_queue <= 4096:
            raise ValueError('Invalid guard capacity limits')
        if self.scan_engine != "antios":
            raise ValueError("Unknown Guard scan engine")
        # Older startup policies may retain engine_service. It is ignored by
        # the native AntiOS Engine and never used for a network connection.
        roots = tuple(dict.fromkeys(checked_path(root) for root in self.roots))
        if any(not root.is_dir() for root in roots):
            raise ValueError('Guard roots must be directories')
        if os.name == 'nt' and any(str(root).startswith('\\\\') for root in roots):
            raise ValueError('Guard does not support network roots')
        return roots


def file_identity(info):
    return (*fingerprint(info), info.st_ctime_ns)


def inventory(roots, *, excluded=(), max_files=50000, cancelled=lambda: False):
    """Reconcile notifications against disk, with bounded traversal and no links."""
    files, issues, stack = {}, [], list(roots)
    entries = 0
    limited = False
    while stack and not cancelled():
        folder = stack.pop()
        if any(folder == root or root in folder.parents for root in excluded):
            continue
        try:
            checked_path(folder)
            with os.scandir(folder) as children:
                for child in children:
                    if cancelled():
                        return files, issues, True
                    entries += 1
                    if entries > max_files * 2 or len(files) >= max_files:
                        return files, issues, True
                    path = Path(child.path)
                    if any(path == root or root in path.parents for root in excluded):
                        continue
                    try:
                        # Windows DirEntry.stat may omit file IDs. Use the same stat
                        # source as post-scan validation so stable files can be cached.
                        info = path.stat(follow_symlinks=False) if os.name == 'nt' else child.stat(follow_symlinks=False)
                        if is_link(info):
                            raise ValueError('link-or-reparse-point')
                        if stat.S_ISDIR(info.st_mode):
                            stack.append(path)
                        elif stat.S_ISREG(info.st_mode):
                            files[path] = file_identity(info)
                        else:
                            raise ValueError('not-a-regular-file')
                    except (OSError, ValueError) as exc:
                        if len(issues) < 100:
                            issues.append({'path': str(path), 'reason': str(exc)[:500]})
        except (OSError, ValueError) as exc:
            if len(issues) < 100:
                issues.append({'path': str(folder), 'reason': str(exc)[:500]})
    return files, issues, limited


def probe_engine(service_name=None, *, scan_engine="antios"):
    """Probe our local engine, without connecting to external services."""
    from .antivirus import load_managed_signatures
    from .engine import AntiOSEngine

    if scan_engine != "antios":
        raise ValueError("Unknown Guard scan engine")
    rules, catalog = load_managed_signatures()
    engine = AntiOSEngine(signatures=rules)
    try:
        return dict(engine.metadata, available=True, **catalog)
    finally:
        engine.close()


class Guard:
    def __init__(self, policy, state_dir=None, *, scanner=None,
                 probe=None, quarantine_factory=Quarantine, watcher_factory=None,
                 status_observer=None, behavior_engine=None, process_sampler=None,
                 process_sampler_factory=None, native_probe=None, incident_graph=None,
                 security_registry=None, security_registry_factory=None):
        self.policy = policy
        self.roots = policy.validate()
        self.state_dir = Path(state_dir or default_guard_path()).absolute()
        self.excluded = (
            self.state_dir,
            default_quarantine_path().absolute(),
            *defender_protected_roots(),
            *companion_protected_roots(),
        )
        for excluded in self.excluded:
            if any(root == excluded or excluded in root.parents for root in self.roots):
                raise ValueError('A watched root cannot be inside protected Guard, quarantine or Defender storage')
        if scanner is None:
            self.scanner = lambda path, **kwargs: run_scan_process(
                path, **kwargs)
        else:
            self.scanner = scanner
        self.probe = (lambda: probe_engine(scan_engine=policy.scan_engine)) if probe is None else probe
        self.quarantine_factory = quarantine_factory
        self.watcher_factory = watcher_factory or (DirectoryNotifications if os.name == 'nt' else PollNotifications)
        self.status_observer = status_observer
        self.behavior = behavior_engine or BehaviorEngine()
        # Process sampling is read-only, but may temporarily fail when Windows
        # cannot supply a process snapshot. Never silently disable it forever.
        self._process_sampler_factory = process_sampler_factory
        self._process_collector_name = 'injected'
        self._process_visibility_required = os.name == 'nt' or process_sampler_factory is not None
        if process_sampler is None and self._process_sampler_factory is None and os.name == 'nt':
            from .windows_behavior import WindowsProcessSampler
            self._process_sampler_factory = WindowsProcessSampler
            self._process_collector_name = 'toolhelp-snapshot'
        self._collector_errors = 0
        self._collector_recoveries = 0
        self._collector_detail = ''
        self._process_retry_at = float('inf')
        if process_sampler is not None:
            self.process_sampler = process_sampler
        elif self._process_sampler_factory is not None:
            try:
                self.process_sampler = self._process_sampler_factory()
            except OSError as exc:
                self.process_sampler = None
                self._collector_errors += 1
                self._collector_detail = str(exc)[:500]
                self._process_retry_at = time.monotonic() + 30
        else:
            self.process_sampler = None
        self._behavior_events = []
        self._behavior_collector = (
            self._process_collector_name if self.process_sampler is not None
            else 'file-correlation-only'
        )
        self.incidents = incident_graph or IncidentGraph()
        self.evidence_bus = EvidenceBus(max_events=4096)
        self._security_registry_factory = security_registry_factory
        self._security_registry_error = ""
        if security_registry is not None:
            self.security_registry = security_registry
        elif os.name == "nt":
            try:
                if self._security_registry_factory is None:
                    self._security_registry_factory = (
                        lambda: runtime_registry(evidence_bus=self.evidence_bus)
                    )
                self.security_registry = self._security_registry_factory()
            except OSError as exc:
                self.security_registry = None
                self._security_registry_error = f"{type(exc).__name__}: {exc}"[:500]
        else:
            self.security_registry = None
        self._deep_results = queue.Queue(maxsize=2)
        self._deep_thread = None
        self._deep_runs = 0
        if native_probe is not None:
            self.native_probe = native_probe
        elif os.name == 'nt':
            # Old native service speaks to ClamAV, not AntiOS Engine.
            self.native_probe = lambda: None
        else:
            self.native_probe = lambda: None
        self._native_checked_at = float('-inf')
        self._native_pre_execution = None
        self._native_probe_errors = 0
        self._last_observed_state = None
        self.pending = OrderedDict()
        self.queue_cursor = None
        self.known, self.failures, self.threats = {}, {}, {}
        self.transient_retries = {}
        self.status = {'schema': 1, 'kind': 'antivirus-guard', 'run_id': uuid.uuid4().hex,
                       'state': 'starting', 'running': True, 'pid': os.getpid(),
                       'started_at': time.time(), 'heartbeat': time.time(),
                       'roots': [str(root) for root in self.roots],
                       'scan_engine': self.policy.scan_engine,
                       'mode': 'quarantine' if policy.auto_quarantine else 'notify',
                       'pre_execution_blocking': False, 'coverage': 'selected-directories-after-change',
                       'engine': {}, 'scanned': 0, 'detections': 0, 'quarantined': 0,
                       'errors': 0, 'pending': 0, 'unresolved': 0, 'inventory_issues': [],
                       'capacity_exceeded': False, 'notifications': 'starting',
                       'notification_resyncs': 0, 'fast_path_seconds': _FAST_SETTLE_SECONDS,
                       'transient_deferrals': 0, 'behavior_alerts_dropped': 0,
                       'behavior': dict(self.behavior.status(), collector=self._behavior_collector,
                                        collector_errors=self._collector_errors,
                                        collector_recoveries=0, alerts_dropped=0,
                                        collector_detail=self._collector_detail),
                       'risk': {'mode': 'fusion', 'evaluations': 0, 'highest_score': 0,
                                'last': None, 'native_pre_execution': 'unknown',
                                'native_probe_errors': 0},
                       'deep_security': {
                           'state': (
                               'idle' if self.security_registry is not None
                               else 'unavailable'
                           ),
                           'in_progress': False,
                           'runs': 0,
                           'last_completed_at': None,
                           'highest_score': 0,
                           'evidence_count': 0,
                           'signature_count': 0,
                           'reports': {},
                           'detail': self._security_registry_error,
                       },
                       'incidents': self.incidents.status()}

    def _refresh_behavior_status(self):
        self.status['behavior'] = dict(
            self.behavior.status(),
            collector=self._behavior_collector,
            collector_errors=self._collector_errors,
            collector_recoveries=self._collector_recoveries,
            collector_detail=self._collector_detail,
            alerts_dropped=self.status['behavior_alerts_dropped'],
        )

    def _queue_behavior_findings(self, findings):
        for finding in findings:
            self._behavior_events.append(finding.to_dict())
        overflow = max(0, len(self._behavior_events) - 100)
        if overflow:
            del self._behavior_events[:overflow]
            self.status['behavior_alerts_dropped'] += overflow
        self._refresh_behavior_status()

    def _publish_incidents(self, store: GuardState):
        self.status['incidents'] = self.incidents.status()
        for update in self.incidents.drain_updates():
            store.event('incident-update', update)

    def _start_deep_security(self, surfaces, budget):
        """Start one bounded background sensor pass without blocking Guard."""
        if self.security_registry is None:
            return False
        if self._deep_thread is not None and self._deep_thread.is_alive():
            return False
        selected = frozenset(surfaces)
        self.status['deep_security']['in_progress'] = True
        self.status['deep_security']['state'] = 'scanning'

        def worker():
            try:
                context = ScanContext(
                    budget=budget,
                    requested_surfaces=selected,
                )
                reports = self.security_registry.collect_all(context)
                raw = tuple(
                    item
                    for report in reports
                    for item in report.evidence
                )
                signatures = DEFAULT_DETECTION_SIGNATURES.evaluate(raw)
                for item in signatures:
                    self.evidence_bus.publish(item)
                result = (selected, reports, signatures, None)
            except Exception as exc:
                result = (
                    selected,
                    (),
                    (),
                    f"{type(exc).__name__}: {exc}"[:500],
                )
            try:
                self._deep_results.put_nowait(result)
            except queue.Full:
                pass

        self._deep_thread = threading.Thread(
            target=worker,
            name="AntiOS-DeepSecurity",
            daemon=True,
        )
        self._deep_thread.start()
        return True

    def _drain_deep_security(self, store: GuardState):
        """Fuse completed background sensor evidence on the Guard thread."""
        changed = False
        while True:
            try:
                surfaces, reports, signatures, error = self._deep_results.get_nowait()
            except queue.Empty:
                break
            changed = True
            state = self.status['deep_security']
            state['in_progress'] = False
            state['last_completed_at'] = time.time()
            self._deep_runs += 1
            state['runs'] = self._deep_runs

            if error:
                state.update(state='error', detail=error)
                store.event('deep-security-error', {
                    'surfaces': sorted(item.value for item in surfaces),
                    'error': error,
                })
                continue

            raw = tuple(
                item
                for report in reports
                for item in report.evidence
            )
            combined = (*raw, *signatures)
            if combined:
                self.incidents.observe_evidence(combined)
                self._publish_incidents(store)

            summary = CoverageSummary.from_reports(tuple(reports))
            highest = max((item.risk_score for item in combined), default=0)
            report_state = {
                report.descriptor.surface.value: {
                    'coverage': report.coverage.value,
                    'reason': report.reason,
                    'inspected_items': report.inspected_items,
                    'inspected_bytes': report.inspected_bytes,
                    'skipped_items': report.skipped_items,
                    'error_items': report.error_items,
                    'evidence': len(report.evidence),
                }
                for report in reports
            }
            merged_reports = dict(state.get('reports') or {})
            merged_reports.update(report_state)
            state.update(
                state=(
                    'attention' if highest >= 40 else
                    'normal' if summary.fully_covered else
                    'partial'
                ),
                highest_score=max(int(state.get('highest_score', 0)), highest),
                evidence_count=len(raw),
                signature_count=len(signatures),
                reports=merged_reports,
                detail='',
            )

            review = [item for item in combined if item.risk_score >= 40][:20]
            if review:
                store.event('deep-security-evidence', {
                    'surfaces': sorted(item.value for item in surfaces),
                    'evidence': [item.to_dict() for item in review],
                    'total_review_evidence': sum(
                        item.risk_score >= 40 for item in combined
                    ),
                })
        return changed

    def _native_state(self, now: float) -> bool | None:
        if now - self._native_checked_at < 15:
            return self._native_pre_execution
        self._native_checked_at = now
        try:
            value = self.native_probe()
            if value not in {True, False, None}:
                raise ValueError('native pre-execution probe returned invalid state')
            self._native_pre_execution = value
        except (OSError, RuntimeError, ValueError):
            self._native_probe_errors += 1
            self._native_pre_execution = None
        return self._native_pre_execution

    def _record_risk(self, path: Path, result: dict, store: GuardState):
        evidence = self.behavior.findings_for_subject(str(path), max_age=60)
        native = self._native_state(time.monotonic())
        context = evaluate_risk(
            str(path), result, behavior_findings=evidence,
            native_pre_execution=native,
        ).to_dict()
        risk = self.status.get('risk', {})
        risk.update(
            mode='fusion',
            evaluations=int(risk.get('evaluations', 0)) + 1,
            highest_score=max(int(risk.get('highest_score', 0)), context['score']),
            last=context,
            native_pre_execution=context['native_pre_execution'],
            native_probe_errors=self._native_probe_errors,
        )
        self.status['risk'] = risk
        self.incidents.observe_risk(context)
        self._publish_incidents(store)
        # Keep the bounded journal useful: clean/low contexts stay in status,
        # while decisions needing review or confirmed remediation are persisted.
        if context['score'] >= 40 or context['confirmed_threat'] or not context['scanner_complete']:
            store.event('risk-context', context)
        return context

    def _settle_delay(self, path: Path) -> float:
        """Prioritize executable/script-like writes without claiming execution blocking."""
        if path.suffix.lower() in _FAST_SCAN_SUFFIXES:
            return min(self.policy.settle, _FAST_SETTLE_SECONDS)
        return self.policy.settle

    def _notify_status(self):
        if self.status_observer is None:
            return
        state = str(self.status.get('state') or 'starting')
        if state == self._last_observed_state:
            return
        self._last_observed_state = state
        try:
            self.status_observer(dict(self.status))
        except Exception:
            # Tray/UI observers are cosmetic and must never weaken protection.
            pass

    def invalidate_changes(self, batch):
        # Events identify work; only inventory may admit files to the scan queue.
        # Prefix matching also covers directory moves and renames. The set bounds
        # this to O(cached paths * path depth), not O(paths * notification count).
        affected = {path for path in (*batch.paths, *batch.reset_roots)
                    if any(path == root or root in path.parents for root in self.roots)
                    and not any(path == root or root in path.parents for root in self.excluded)}
        if not affected:
            return False
        if batch.paths:
            behavior_findings = self.behavior.observe_many_file_changes(
                str(path) for path in batch.paths
            )
            self._queue_behavior_findings(behavior_findings)
            for path in batch.paths:
                self.incidents.observe_file_change(str(path))
            self.incidents.observe_behavior_findings(
                finding.to_dict() for finding in behavior_findings
            )
        def matches(path):
            return path in affected or not affected.isdisjoint(path.parents)
        for path in list(self.known):
            if matches(path):
                del self.known[path]
        changed_at = time.monotonic()
        for path, (identity, _) in list(self.pending.items()):
            if matches(path):
                self.pending[path] = (identity, changed_at + self._settle_delay(path))
        return True

    def run(self, stop=None):
        stop = stop or threading.Event()
        store = GuardState(self.state_dir)
        try:
            store.acquire()
        except BaseException:
            store.close()
            raise
        watcher = None
        last_heartbeat, last_probe, last_inventory = 0.0, float('-inf'), float('-inf')
        last_process_poll = float('-inf')
        last_stop_poll = float('-inf')
        next_deep_runtime = time.monotonic() + _DEEP_INITIAL_DELAY
        next_deep_persistence = time.monotonic() + _DEEP_INITIAL_DELAY
        next_deep_platform = time.monotonic() + _DEEP_INITIAL_DELAY + 5.0
        last_alert_loss_reported = 0
        version, changed, notification_error = None, True, False
        next_notification_retry = 0.0

        def cancelled():
            nonlocal last_heartbeat, last_process_poll, last_stop_poll
            # Stop requests take priority over process snapshots, journal writes
            # and inventory reconciliation. A failing/slow collector must not
            # be invoked again after the user explicitly stopped the Guard.
            if stop.is_set():
                return True
            now = time.monotonic()
            if now - last_stop_poll >= 0.2:
                last_stop_poll = now
                if store.stopped(self.status['run_id']):
                    stop.set()
                    return True

            # Restore a failed Windows process sampler, including one that
            # failed to initialize. The first snapshot is a safe baseline.
            if (self.process_sampler is None and self._process_sampler_factory is not None
                    and now >= self._process_retry_at):
                self._process_retry_at = now + 30
                try:
                    self.process_sampler = self._process_sampler_factory()
                    self._behavior_collector = self._process_collector_name
                    self._collector_detail = ''
                    self._collector_recoveries += 1
                    last_process_poll = float('-inf')
                    store.event('behavior-collector-recovered', {
                        'collector': self._behavior_collector,
                        'recoveries': self._collector_recoveries,
                    })
                except OSError as exc:
                    self._collector_errors += 1
                    self._collector_detail = str(exc)[:500]
                    store.event('behavior-collector-error', {
                        'error': self._collector_detail,
                        'retry_seconds': 30,
                    })
                self._refresh_behavior_status()

            # run_scan_process invokes this callback while its worker is busy,
            # so process correlation stays live even during a long file scan.
            if self.process_sampler is not None and now - last_process_poll >= 0.5:
                last_process_poll = now
                try:
                    for event in self.process_sampler.poll():
                        behavior_findings = self.behavior.observe_process(event)
                        self._queue_behavior_findings(behavior_findings)
                        self.incidents.observe_process(
                            event,
                            behavior_findings=(finding.to_dict() for finding in behavior_findings),
                        )
                except OSError as exc:
                    self._behavior_collector = 'file-correlation-only'
                    self.process_sampler = None
                    self._process_retry_at = now + 30
                    self._collector_errors += 1
                    self._collector_detail = str(exc)[:500]
                    self._refresh_behavior_status()
                    store.event('behavior-collector-error', {
                        'error': self._collector_detail,
                        'retry_seconds': 30 if self._process_sampler_factory is not None else None,
                    })

            if now - last_heartbeat >= 0.5:
                last_heartbeat = now
                self._refresh_behavior_status()
                self.status.update(heartbeat=time.time(), pending=len(self.pending),
                                   unresolved=len(self.failures), active_threats=len(self.threats))
                self._publish_incidents(store)
                store.publish(self.status)
            return stop.is_set()

        store.publish(self.status)
        self._notify_status()
        store.event('started', {'roots': self.status['roots'], 'mode': self.status['mode']})
        try:
            while not cancelled():
                now = time.monotonic()

                self._drain_deep_security(store)
                if self.security_registry is not None:
                    if now >= next_deep_runtime:
                        if self._start_deep_security(
                            (Surface.PROCESS, Surface.RAM),
                            ScanBudget(
                                max_items=20_000,
                                max_bytes=16 * 1024 * 1024,
                                max_seconds=5.0,
                                allow_privileged=True,
                            ),
                        ):
                            next_deep_runtime = now + _DEEP_RUNTIME_INTERVAL
                    if now >= next_deep_persistence:
                        if self._start_deep_security(
                            (Surface.PERSISTENCE,),
                            ScanBudget(
                                max_items=5_000,
                                max_bytes=0,
                                max_seconds=12.0,
                                allow_privileged=True,
                            ),
                        ):
                            next_deep_persistence = (
                                now + _DEEP_PERSISTENCE_INTERVAL
                            )
                    if now >= next_deep_platform:
                        if self._start_deep_security(
                            (
                                Surface.DRIVER,
                                Surface.BOOT,
                                Surface.UEFI,
                                Surface.DMA,
                                Surface.ATTESTATION,
                            ),
                            ScanBudget(
                                max_items=4_096,
                                max_bytes=256 * 1024 * 1024,
                                max_seconds=25.0,
                                allow_privileged=True,
                            ),
                        ):
                            next_deep_platform = (
                                now + _DEEP_PLATFORM_INTERVAL
                            )

                while self._behavior_events:
                    store.event('behavior-alert', self._behavior_events.pop(0))
                if self.status['behavior_alerts_dropped'] > last_alert_loss_reported:
                    last_alert_loss_reported = self.status['behavior_alerts_dropped']
                    store.event('behavior-alert-loss', {
                        'dropped_total': last_alert_loss_reported,
                        'reason': 'behavior-event-queue-overflow',
                    })

                if watcher is None and now >= next_notification_retry:
                    next_notification_retry = now + 30
                    try:
                        watcher = self.watcher_factory(self.roots)
                        notification_error = False
                        self.status['notifications'] = 'native' if watcher.native else 'periodic'
                        # Changes while the notification handle was unavailable
                        # may have preserved every cached metadata field.
                        self.invalidate_changes(ChangeBatch(reset_roots=self.roots))
                        last_inventory = float('-inf')
                    except OSError as exc:
                        notification_error = True
                        self.status['notifications'] = 'failed; periodic reconciliation continues'
                        store.event('notification-error', {'error': str(exc)[:500]})
                if now - last_probe >= 30:
                    last_probe = now
                    try:
                        metadata = self.probe()
                        probed_version = (metadata.get('version'), metadata.get('signature_catalog_version'))
                        if probed_version != version:
                            version = probed_version
                            self.known.clear()
                            self.queue_cursor = None
                            changed = True
                        if metadata != self.status['engine']:
                            store.event('engine', metadata)
                        self.status['engine'] = metadata
                    except (OSError, RuntimeError) as exc:
                        self.status['engine'] = {'available': False, 'detail': str(exc)[:500]}
                        store.event('engine-error', self.status['engine'])
                if now - last_inventory >= self.policy.interval:
                    last_inventory = now
                    files, issues, limited = inventory(self.roots, max_files=self.policy.max_files,
                        excluded=self.excluded, cancelled=cancelled)
                    self.status['inventory_issues'] = issues
                    self.status['capacity_exceeded'] = limited
                    for mapping in (self.pending, self.known, self.failures,
                                    self.threats, self.transient_retries):
                        for path in list(mapping):
                            if path not in files and not limited and not issues:
                                del mapping[path]
                    # Refresh every admitted file even if a full queue stops
                    # admission before that path's position in the inventory.
                    for path, (identity, _) in list(self.pending.items()):
                        current = files.get(path)
                        if current is not None and current != identity:
                            # A new file version gets its own transient retry budget.
                            self.transient_retries.pop(path, None)
                            self.pending[path] = (current, now + self._settle_delay(path))
                    # Continue after the last admission. Repeated writes/cache
                    # resets in the first entries must not starve the backlog.
                    entries = list(files.items())
                    start = next((index + 1 for index, (path, _) in enumerate(entries)
                                  if path == self.queue_cursor), 0)
                    for offset in range(len(entries)):
                        path, identity = entries[(start + offset) % len(entries)]
                        known = self.known.get(path)
                        if known and known[0] == identity and now - known[1] < known[2]:
                            continue
                        pending = self.pending.get(path)
                        if pending is not None:
                            continue
                        if len(self.pending) >= self.policy.max_queue:
                            self.status['capacity_exceeded'] = True
                            break
                        self.pending[path] = (identity, now + self._settle_delay(path))
                        self.queue_cursor = path
                    changed = False
                ready = next(((path, item) for path, item in self.pending.items()
                              if now >= item[1]), None)
                if ready and self.status['engine'].get('available') and not cancelled():
                    path, (identity, _) = ready
                    del self.pending[path]
                    # A degraded Guard must not look fully healthy merely because
                    # it entered a scanning phase.
                    scan_state = 'degraded' if self.status['state'] == 'degraded' else 'scanning'
                    self.status.update(state=scan_state, current_path=str(path))
                    store.publish(self.status)
                    self._notify_status()
                    try:
                        result = self.scanner(path, engine=self.policy.scan_engine, timeout=45, cancelled=cancelled)
                        if cancelled():
                            break
                        self.transient_retries.pop(path, None)
                        self.status['scanned'] += result['summary']['files_scanned']
                        if not result['engine'].get('available') or result['engine'].get('failed_during_scan'):
                            self.status['engine'] = dict(result['engine'], available=False)
                            last_probe = time.monotonic()
                        incomplete = result['coverage'] == 'limited'
                        if incomplete:
                            self.failures[path] = 'incomplete scan'
                        else:
                            self.failures.pop(path, None)
                        findings = result['findings']
                        risk_context = self._record_risk(path, result, store)
                        if findings or incomplete:
                            store.event('scan', {'path': str(path), 'verdict': result['verdict'],
                                'coverage': result['coverage'], 'findings': findings,
                                'issues': result['issues'], 'engine': result['engine'],
                                'risk': risk_context})
                        for finding in findings:
                            if finding['kind'] != 'threat':
                                continue
                            self.threats[path] = finding['name']
                            self.status['detections'] += 1
                            if self.policy.auto_quarantine and risk_context['automatic_enforcement_eligible']:
                                item = self.quarantine_factory().add(finding, dry_run=False)
                                store.event('quarantined', {'path': str(path), 'id': item['id'], 'name': finding['name']})
                                self.status['quarantined'] += 1
                                self.threats.pop(path, None)
                                self.failures.pop(path, None)
                        try:
                            current = file_identity(checked_path(path).stat())
                        except FileNotFoundError:
                            current = None
                        # A scan result never covers bytes written during detection.
                        if current == identity:
                            if not incomplete and not any(f['kind'] == 'threat' for f in findings):
                                self.threats.pop(path, None)
                            if len(self.known) >= self.policy.max_files and path not in self.known:
                                self.known.pop(next(iter(self.known)))
                            self.known[path] = (identity, time.monotonic(), 30 if incomplete else self.policy.rescan)
                    except (OSError, RuntimeError, ValueError) as exc:
                        if isinstance(exc, FileNotFoundError):
                            # Another protection/remediation layer may have removed or
                            # quarantined the file between discovery and our scan.
                            self.transient_retries.pop(path, None)
                            self.failures.pop(path, None)
                            self.known.pop(path, None)
                            store.event('scan-vanished', {'path': str(path)})
                        elif _transient_scan_conflict(exc):
                            retries = self.transient_retries.get(path, 0) + 1
                            if retries <= _MAX_TRANSIENT_SCAN_RETRIES:
                                self.transient_retries[path] = retries
                                self.status['transient_deferrals'] += 1
                                delay = min(2.0, max(0.25, self._settle_delay(path) * (retries + 1)))
                                self.pending[path] = (identity, time.monotonic() + delay)
                                store.event('scan-deferred', {
                                    'path': str(path), 'retry': retries,
                                    'reason': str(exc)[:500], 'delay_seconds': delay,
                                })
                            else:
                                self.transient_retries.pop(path, None)
                                self.status['errors'] += 1
                                self.failures[path] = str(exc)[:500]
                                if len(self.known) >= self.policy.max_files and path not in self.known:
                                    self.known.pop(next(iter(self.known)))
                                self.known[path] = (identity, time.monotonic(), 30)
                                store.event('scan-error', {'path': str(path), 'error': str(exc)[:500]})
                        else:
                            self.transient_retries.pop(path, None)
                            self.status['errors'] += 1
                            self.failures[path] = str(exc)[:500]
                            if len(self.known) >= self.policy.max_files and path not in self.known:
                                self.known.pop(next(iter(self.known)))
                            self.known[path] = (identity, time.monotonic(), 30)
                            store.event('scan-error', {'path': str(path), 'error': str(exc)[:500]})
                    self.status.pop('current_path', None)
                if len(self.failures) > self.policy.max_files or len(self.threats) > self.policy.max_files:
                    raise RuntimeError('Guard incident capacity exceeded; review history and reduce watched scope')
                degraded = (notification_error or self.failures or self.status['inventory_issues'] or
                            self.status['capacity_exceeded'] or not self.status['engine'].get('available') or
                            self.status['engine'].get('signature_catalog_status') == 'fallback' or
                            self.status['engine'].get('database_freshness') != (
                                'local' if self.policy.scan_engine == 'antios' else 'current') or
                            (self._process_visibility_required and self.process_sampler is None) or
                            self.status['behavior_alerts_dropped'] > 0)
                behavior_attention = self.status.get('behavior', {}).get('state') in {'attention', 'alert'}
                incident_attention = self.status.get('incidents', {}).get('state') in {'attention', 'alert'}
                self.status['state'] = (
                    'degraded' if degraded else
                    'attention' if self.threats or behavior_attention or incident_attention else
                    'monitoring'
                )
                self._notify_status()
                if watcher is not None:
                    try:
                        batch = watcher.wait(0.05 if ready else 0.25)
                        changed = self.invalidate_changes(batch) or changed
                        if batch.reset_roots:
                            self.status['notification_resyncs'] += 1
                            store.event('notification-resync', {'roots': [str(p) for p in batch.reset_roots]})
                        # A timed sweep remains even when no event was received.
                        if changed and time.monotonic() - last_inventory >= 0.5:
                            last_inventory = float('-inf')
                    except OSError as exc:
                        watcher.close()
                        watcher = None
                        notification_error = True
                        self.status['notifications'] = 'failed; periodic reconciliation continues'
                        self.invalidate_changes(ChangeBatch(reset_roots=self.roots))
                        last_inventory = float('-inf')
                        store.event('notification-error', {'error': str(exc)[:500]})
                else:
                    stop.wait(0.25)
        except KeyboardInterrupt:
            stop.set()
            raise
        except BaseException as exc:
            self.status.update(state='failed', last_error=str(exc)[:500])
            self._notify_status()
            raise
        finally:
            if watcher is not None:
                watcher.close()
            self._drain_deep_security(store)
            self.status.update(running=False, heartbeat=time.time(), pending=len(self.pending),
                               unresolved=len(self.failures), active_threats=len(self.threats))
            if self.status['state'] != 'failed':
                self.status['state'] = 'stopped'
            self._notify_status()
            try:
                store.publish(self.status)
                store.event('stopped', {'state': self.status['state']})
            finally:
                store.close()
        return self.status


def load_policy(path):
    from .antivirus import read_regular
    content, _ = read_regular(Path(path), 65536)
    data = json.loads(content)
    if not isinstance(data, dict) or data.get('schema') != 1:
        raise ValueError('Guard policy must use schema 1')
    unknown = set(data) - {'schema', 'roots', 'auto_quarantine', 'engine_service', 'scan_engine'}
    if unknown:
        # Show safe *field names* in diagnostics without leaking arbitrary JSON
        # keys. Never ignore unknown policy options or weaken Guard defaults.
        names = sorted(
            field if isinstance(field, str) and re.fullmatch(r'[a-z_][a-z0-9_]{0,40}', field)
            else '<invalid-name>' for field in unknown
        )
        raise ValueError(
            'Unknown guard policy field(s): ' + ', '.join(names[:8]) +
            '; reconfigure Resident Guard to regenerate startup-policy.json'
        )
    roots = data.get('roots')
    if not isinstance(roots, list) or not all(isinstance(p, str) for p in roots):
        raise ValueError('Guard roots must be a list of paths')
    if any(not Path(p).is_absolute() for p in roots):
        raise ValueError('Policy roots must be absolute paths')
    automatic = data.get('auto_quarantine', False)
    if not isinstance(automatic, bool):
        raise ValueError('auto_quarantine must be boolean')
    engine_service = data.get('engine_service')
    if engine_service is not None and (
            not isinstance(engine_service, str)
            or re.fullmatch(r'[A-Za-z0-9_-]{1,80}', engine_service) is None):
        raise ValueError('Invalid legacy engine_service field')
    # Ignore historical service bindings; all new scans are local.
    scan_engine = data.get('scan_engine', 'antios')
    if scan_engine == 'clamav':
        # A policy from an older installation is migrated to our engine.
        scan_engine = 'antios'
    if scan_engine != 'antios':
        raise ValueError('Unknown Guard scan engine')
    return GuardPolicy(tuple(Path(p) for p in roots), auto_quarantine=automatic,
                       engine_service=engine_service, scan_engine=scan_engine)


def _startup_error_file(state_dir=None):
    return Path(state_dir or default_guard_path()).absolute() / "startup-error.json"


def _write_startup_error(state_dir, exc):
    try:
        path = _startup_error_file(state_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": 1,
            "kind": "antios-guard-startup-error",
            "at": time.time(),
            "error_type": type(exc).__name__,
            "error": str(exc)[:2000],
            "pid": os.getpid(),
        }
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        temp.replace(path)
    except OSError:
        pass


def _clear_startup_error(state_dir):
    try:
        _startup_error_file(state_dir).unlink(missing_ok=True)
    except OSError:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(prog='antios guard', description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    run.add_argument('roots', nargs='*', type=Path)
    run.add_argument('--policy', type=Path)
    run.add_argument('--auto-quarantine', action='store_true', help='Explicitly permit automatic encrypted isolation of confirmed detections.')
    run.add_argument('--engine', choices=('antios',),
                     help='Native AntiOS Engine (default).')
    run.add_argument('--state-dir', type=Path)
    for name in ('status', 'stop', 'history'):
        commands.add_parser(name).add_argument('--state-dir', type=Path)
    args = parser.parse_args(argv)
    tray = None
    try:
        if args.command != 'run':
            status = read_guard_state(args.state_dir, history=args.command == 'history', stop=args.command == 'stop')
            print(json.dumps(status, indent=2, ensure_ascii=False))
            return 0
        if args.policy:
            if args.roots or args.auto_quarantine or args.engine is not None:
                raise ValueError('Use a policy file or inline roots/options, not both')
            policy = load_policy(args.policy)
        else:
            policy = GuardPolicy(tuple(args.roots), auto_quarantine=args.auto_quarantine,
                                 scan_engine=args.engine or 'antios')
        if policy.auto_quarantine and os.name != 'nt':
            raise ValueError('Automatic encrypted quarantine requires Windows DPAPI')
        print('AntiOS Guard: post-write detection for selected directories; pre-execution blocking is unavailable.', flush=True)
        observer = None
        if os.name == 'nt' and getattr(sys, 'frozen', False):
            try:
                from .tray import GuardTray
                tray = GuardTray()
                tray.start('starting')
                observer = tray.set_state
            except Exception:
                tray = None
        _clear_startup_error(args.state_dir)
        Guard(policy, args.state_dir, status_observer=observer).run()
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        state_dir = getattr(args, "state_dir", None) if "args" in locals() else None
        _write_startup_error(state_dir, exc)
        from .diagnostics import classify_error, record_event
        record_event("Guard", "ERROR", str(exc),
                     code=classify_error(str(exc), component="Guard"),
                     context={"operation": getattr(args, "command", "run")})
        print(f'AntiOS Guard: {exc}', file=sys.stderr)
        return 2
    finally:
        if tray is not None:
            tray.stop()


def launch_guard(root):
    """Explicit GUI action; the companion outlives the dashboard until stopped."""
    import subprocess
    import sys
    path = GuardPolicy((Path(root),)).validate()[0]
    if read_guard_state().get('running'):
        raise RuntimeError('AntiOS Guard is already running; stop it before changing roots')
    if getattr(sys, 'frozen', False):
        executable = Path(sys.executable).parent / 'AntiOS-Guard.exe'
        if not executable.is_file():
            raise FileNotFoundError('AntiOS-Guard.exe is missing from the portable installation')
        command = [str(executable), 'run', str(path)]
    else:
        command = [sys.executable, '-m', 'antios.guard', 'run', str(path)]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **hidden_process_kwargs(),
    )
    return {'pid': process.pid, 'root': str(path)}


if __name__ == '__main__':
    raise SystemExit(main())
