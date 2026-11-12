from antios.behavior import BehaviorEngine, ProcessEvent


class Clock:
    def __init__(self):
        self.now = 100.0
    def __call__(self):
        return self.now
    def advance(self, seconds):
        self.now += seconds


def engine(**kwargs):
    clock = Clock()
    return BehaviorEngine(clock=clock, mass_threshold=10, **kwargs), clock


def test_document_spawning_powershell_is_high_signal():
    behavior, _clock = engine()
    findings = behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="powershell.exe",
        path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        parent_image="WINWORD.EXE",
    ))
    assert [(item.rule, item.score) for item in findings] == [
        ("document-spawns-interpreter", 85)
    ]


def test_browser_spawning_script_host_is_high_signal():
    behavior, _clock = engine()
    findings = behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="wscript.exe",
        path=r"C:\Windows\System32\wscript.exe",
        parent_image="chrome.exe",
    ))
    assert findings[0].rule == "browser-spawns-interpreter"
    assert findings[0].severity == "high"


def test_execution_from_downloads_is_detected_without_calling_it_malware():
    behavior, _clock = engine()
    findings = behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="setup.exe",
        path=r"C:\Users\Alice\Downloads\setup.exe",
        parent_image="explorer.exe",
    ))
    assert findings[0].rule == "user-writable-execution"
    assert findings[0].severity == "low"
    assert findings[0].score == 45
    assert behavior.status()["state"] == "normal"


def test_recently_changed_file_then_execution_correlates():
    behavior, clock = engine()
    path = r"C:\Users\Alice\Downloads\payload.exe"
    behavior.observe_file_change(path)
    clock.advance(2)
    findings = behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="payload.exe", path=path, parent_image="explorer.exe",
    ))
    rules = {item.rule for item in findings}
    assert "changed-then-executed" in rules
    assert "user-writable-execution" in rules


def test_mass_file_changes_are_bounded_and_deduplicated():
    behavior, clock = engine()
    findings = []
    for index in range(10):
        findings += behavior.observe_file_change(fr"C:\Data\file-{index}.txt")
    assert [item.rule for item in findings] == ["mass-file-changes"]
    for index in range(10, 20):
        findings += behavior.observe_file_change(fr"C:\Data\file-{index}.txt")
    assert [item.rule for item in findings].count("mass-file-changes") == 1
    assert behavior.status()["state"] == "attention"
    clock.advance(61)
    behavior.observe_file_change(r"C:\Data\again.txt")
    assert behavior.status()["recent_findings"] == 1


def test_interpreter_plus_mass_changes_escalates_to_critical():
    behavior, _clock = engine()
    behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="powershell.exe",
        path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        parent_image="explorer.exe",
    ))
    findings = []
    for index in range(10):
        findings += behavior.observe_file_change(fr"C:\Victim\file-{index}.docx")
    assert findings[-1].rule == "interpreter-with-mass-file-changes"
    assert findings[-1].severity == "critical"
    assert behavior.status()["state"] == "alert"


def test_old_file_change_does_not_correlate_with_execution():
    behavior, clock = engine()
    path = r"C:\Users\Alice\Downloads\payload.exe"
    behavior.observe_file_change(path)
    clock.advance(31)
    findings = behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="payload.exe", path=path, parent_image="explorer.exe",
    ))
    assert "changed-then-executed" not in {item.rule for item in findings}


def test_engine_is_detection_only():
    behavior, _clock = engine()
    assert behavior.status()["mode"] == "detect-only"



def test_findings_for_subject_returns_only_fresh_exact_path():
    behavior, clock = engine()
    path = r"C:\Users\Alice\Downloads\payload.exe"
    behavior.observe_file_change(path)
    behavior.observe_process(ProcessEvent(
        pid=20, ppid=10, image="payload.exe", path=path, parent_image="explorer.exe",
    ))
    matching = behavior.findings_for_subject(path, max_age=30)
    assert {item["rule"] for item in matching} == {
        "user-writable-execution", "changed-then-executed"
    }
    assert behavior.findings_for_subject(r"C:\Other\payload.exe", max_age=30) == []
    clock.advance(31)
    assert behavior.findings_for_subject(path, max_age=30) == []



def test_windows_process_sampler_detects_observable_pid_reuse_without_windows():
    """Image/parent changes at the same PID are a new execution, not a cache hit."""
    from antios.windows_behavior import WindowsProcessSampler, _SnapshotProcess

    parent = _SnapshotProcess(100, 4, "WINWORD.EXE", "")
    views = [
        {100: parent, 55: _SnapshotProcess(55, 100, "calc.exe", "")},
        {100: parent, 55: _SnapshotProcess(55, 100, "powershell.exe", "")},
        {100: parent, 55: _SnapshotProcess(55, 100, "powershell.exe", "")},
        {100: parent, 55: _SnapshotProcess(55, 101, "powershell.exe", "")},
    ]
    sampler = WindowsProcessSampler.__new__(WindowsProcessSampler)
    sampler._known = None
    sampler.snapshot = lambda: views.pop(0)
    sampler._path = lambda _pid: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    assert sampler.poll() == []  # baseline
    replaced = sampler.poll()
    assert len(replaced) == 1
    assert replaced[0].image == "powershell.exe"
    assert replaced[0].parent_image == "WINWORD.EXE"
    assert replaced[0].path.endswith("powershell.exe")
    assert sampler.poll() == []  # unchanged, not a new process
    reparented = sampler.poll()
    assert len(reparented) == 1
    assert reparented[0].ppid == 101
