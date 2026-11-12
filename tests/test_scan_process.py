import json
from pathlib import Path
import sys
import time

import pytest

from antios import scan_process
from antios.scan_verdict import replay_scan_report


def test_real_worker_returns_report_and_can_restart(tmp_path):
    target = tmp_path / 'normal.txt'
    target.write_text('ordinary benign fixture')
    for profile, override, expected in [('light', None, 2), ('heavy', 16, 16)]:
        result = scan_process.run_scan_process(target, profile=profile, workers=override)
        assert result['summary']['files_scanned'] == 1
        assert result['limits']['profile'] == profile
        assert result['limits']['workers'] == expected
        assert not result['summary']['cancelled']
        assert not result['findings']
        assert replay_scan_report(result)['verdict'] == 'no-threats-found'
        assert target.read_text() == 'ordinary benign fixture'


def test_forced_stop_reaps_blocked_child_and_keeps_checkpoint(tmp_path, monkeypatch):
    script = tmp_path / 'blocked.py'
    started = tmp_path / 'started'
    pid_file = tmp_path / 'pid'
    checkpoint = {'schema': 1, 'kind': 'antivirus-scan',
                  'summary': {'files_scanned': 1, 'threats': 1, 'reviews': 0},
                  'findings': [{'kind': 'threat', 'name': 'fixture'}], 'issues': [],
                  'coverage': 'limited', 'verdict': 'incomplete'}
    script.write_text('import os,sys,time\nfrom pathlib import Path\n'
                      f'Path({str(pid_file)!r}).write_text(str(os.getpid()))\n'
                      'with open(sys.argv[1], "w") as f:\n'
                      f' f.write({json.dumps(["checkpoint", checkpoint]) + chr(10)!r}); f.flush()\n'
                      ' f.write("[\\\"checkpoint\\\", {"); f.flush()\n'
                      f' Path({str(started)!r}).touch()\n'
                      ' time.sleep(60)\n', encoding='utf-8')
    monkeypatch.setattr(scan_process, 'worker_command', lambda request, events:
                        [sys.executable, str(script), str(events)])
    processes = []
    popen = scan_process.subprocess.Popen
    def capture(*args, **kwargs):
        process = popen(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(scan_process.subprocess, 'Popen', capture)
    before = time.monotonic()
    result = scan_process.run_scan_process(tmp_path, cancelled=lambda:
        started.exists() or time.monotonic() - before > 10)
    assert time.monotonic() - before < 12
    assert processes[0].poll() is not None
    assert result['summary']['cancelled'] and result['summary']['forced_stop']
    assert result['findings'] == checkpoint['findings']
    assert result['coverage'] == 'limited'
    assert result['verdict'] == 'threats-found'
    assert 'scan-cancelled' in result['coverage_contract']['reasons']
    assert replay_scan_report(result)['dimensions']['coverage'] == 'limited'


def test_stop_before_first_checkpoint_is_incomplete(tmp_path):
    result = scan_process.run_scan_process(tmp_path, cancelled=lambda: True)
    assert result['summary']['cancelled']
    assert result['summary']['files_scanned'] == 0
    assert result['verdict'] == 'incomplete'


def test_worker_failure_is_not_reported_as_clean(tmp_path):
    with pytest.raises(RuntimeError):
        scan_process.run_scan_process(tmp_path / 'missing')


def test_worker_receives_engine_selection(tmp_path, monkeypatch):
    request, events = tmp_path / 'request', tmp_path / 'events'
    request.write_text(json.dumps({'path': str(tmp_path), 'engine': 'antios'}))
    options = []
    monkeypatch.setattr(scan_process, 'scan_files', lambda path, **kwargs: options.append(kwargs))
    assert scan_process.worker_main(str(request), str(events)) == 0
    assert options[0]['engine'] == 'antios'


def test_deadline_kills_a_blocked_worker_and_preserves_incomplete_state(tmp_path, monkeypatch):
    script = tmp_path / 'blocked.py'
    script.write_text('import time\ntime.sleep(60)\n')
    monkeypatch.setattr(scan_process, 'worker_command', lambda request, events: [sys.executable, str(script)])
    start = time.monotonic()
    result = scan_process.run_scan_process(tmp_path, timeout=0.2)
    assert time.monotonic() - start < 5
    assert result['summary']['timed_out']
    assert result['verdict'] == 'incomplete'
    assert 'scan-timed-out' in result['coverage_contract']['reasons']
