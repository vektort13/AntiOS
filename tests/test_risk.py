from antios.risk import classify_origin, evaluate_risk


def scan(*, verdict="no-threats-found", coverage="antios-local-inspection", findings=None, fresh=True):
    return {
        "verdict": verdict,
        "coverage": coverage,
        "findings": findings or [],
        "engine": {
            "available": True,
            "database_freshness": "local" if fresh else "stale",
        },
    }


def test_confirmed_threat_is_the_only_automatic_enforcement_case():
    context = evaluate_risk(
        r"C:\Users\Alice\Downloads\bad.exe",
        scan(verdict="threats-found", findings=[{"kind": "threat", "name": "Inert.Test"}]),
        behavior_findings=[{"rule": "changed-then-executed", "score": 75}],
        native_pre_execution=True,
        now=1,
    )
    assert context.score == 100
    assert context.classification == "confirmed-threat"
    assert context.automatic_enforcement_eligible is True
    assert context.native_pre_execution == "active"


def test_critical_behavior_never_becomes_automatic_block():
    context = evaluate_risk(
        r"C:\Users\Alice\AppData\Local\Temp\script.ps1",
        scan(),
        behavior_findings=[{"rule": "interpreter-with-mass-file-changes", "score": 95}],
        native_pre_execution=False,
        now=1,
    )
    assert context.score == 95
    assert context.classification == "critical-behavior"
    assert context.automatic_enforcement_eligible is False
    assert context.recommended_action == "review-immediately"


def test_clean_download_without_behavior_stays_low():
    context = evaluate_risk(
        r"C:\Users\Alice\Downloads\setup.exe",
        scan(),
        now=1,
    )
    assert context.origin == "downloads"
    assert context.score == 5
    assert context.classification == "low"


def test_review_plus_startup_origin_is_elevated_but_review_only():
    context = evaluate_risk(
        r"C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\item.cmd",
        scan(verdict="review", findings=[{"kind": "review", "name": "Heuristic"}]),
        now=1,
    )
    assert context.origin == "startup"
    assert context.score == 80
    assert context.classification == "high"
    assert context.automatic_enforcement_eligible is False


def test_incomplete_scan_and_temp_origin_needs_review():
    context = evaluate_risk(
        r"C:\Users\Alice\AppData\Local\Temp\payload.exe",
        scan(verdict="incomplete", coverage="limited"),
        now=1,
    )
    assert context.score == 60
    assert context.classification == "elevated"
    assert context.scanner_complete is False


def test_native_state_never_changes_maliciousness_score():
    active = evaluate_risk(r"C:\Data\a.exe", scan(), native_pre_execution=True, now=1)
    inactive = evaluate_risk(r"C:\Data\a.exe", scan(), native_pre_execution=False, now=1)
    unknown = evaluate_risk(r"C:\Data\a.exe", scan(), native_pre_execution=None, now=1)
    assert active.score == inactive.score == unknown.score == 0
    assert active.native_execution_boundary_protected is True
    assert inactive.native_execution_boundary_protected is False
    assert unknown.native_execution_boundary_protected is None


def test_origin_classifier_is_conservative():
    assert classify_origin(r"C:\Windows\System32\cmd.exe") == ("windows", 0)
    assert classify_origin(r"C:\Program Files\Vendor\tool.exe") == ("program-files", 0)
    assert classify_origin(r"C:\Users\A\Downloads\tool.exe") == ("downloads", 5)
    assert classify_origin(r"C:\Users\A\AppData\Local\Temp\x.exe") == ("user-temp", 10)



def test_real_antios_coverage_values_define_complete_scan():
    native = evaluate_risk(r"C:\Data\a.exe", scan(), now=1)
    clamav = evaluate_risk(r"C:\Data\a.exe", scan(coverage="clamav-and-signatures"), now=1)
    amsi = evaluate_risk(r"C:\Data\a.exe", scan(coverage="provider-and-signatures"), now=1)
    limited = evaluate_risk(r"C:\Data\a.exe", scan(coverage="limited", verdict="incomplete"), now=1)
    assert native.scanner_complete is True
    assert clamav.scanner_complete is False
    assert amsi.scanner_complete is False
    assert limited.scanner_complete is False
