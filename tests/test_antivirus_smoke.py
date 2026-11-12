import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("antivirus_smoke", Path("scripts/smoke-antivirus.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def report(*, available=True, errors=0, scanned=1):
    complete = scanned == 1 and errors == 0
    return {"summary": {"files_scanned": 1, "threats": 0, "reviews": 0,
                        "skipped": 0, "cancelled": False, "limit_reached": False,
                        "provider_scanned": scanned, "errors": errors},
            "engine": {"available": available}, "findings": [],
            "coverage": "antios-local-inspection" if complete else "limited",
            "verdict": "no-threats-found" if complete else "incomplete"}


def test_working_provider_passes_strict_validation():
    assert "passed" in smoke.validate_benign(0, report(), require_amsi=True)


@pytest.mark.parametrize("available,errors", [(False, 0), (True, 1)])
def test_unavailable_provider_is_explicit_and_fails_strict_mode(available, errors):
    result = report(available=available, errors=errors, scanned=0)
    with pytest.raises(ValueError):
        smoke.validate_benign(3, result)
    with pytest.raises(ValueError):
        smoke.validate_benign(3, result, require_amsi=True)


@pytest.mark.parametrize("code", [1, 2, 3, -1])
def test_unexpected_exit_code_cannot_pass_complete_scan(code):
    with pytest.raises(ValueError):
        smoke.validate_benign(code, report())


def test_incomplete_scan_cannot_claim_success():
    with pytest.raises(ValueError):
        smoke.validate_benign(0, report(errors=1, scanned=0))
