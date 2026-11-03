from pathlib import Path
import runpy
import xml.etree.ElementTree as ET

import pytest

verify = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/run-platform-tests.py"))["verify_report"]


def write_report(tmp_path, names, result=None):
    root = ET.Element("testsuite")
    for name in names:
        case = ET.SubElement(root, "testcase", classname="tests.test_example", name=name)
        if result:
            ET.SubElement(case, result)
    path = tmp_path / "results.xml"
    ET.ElementTree(root).write(path)
    return path


def test_exact_completed_test_set_is_accepted(tmp_path):
    report = write_report(tmp_path, ["first", "second"])
    assert verify(report, ["tests/test_example.py::first", "tests/test_example.py::second"]) == 2


@pytest.mark.parametrize("result", ["skipped", "failure", "error"])
def test_nonpassing_test_cannot_satisfy_platform_gate(tmp_path, result):
    report = write_report(tmp_path, ["first"], result)
    with pytest.raises(ValueError, match="skipped or failed"):
        verify(report, ["tests/test_example.py::first"])


@pytest.mark.parametrize("names", [[], ["other"], ["first", "first"]])
def test_missing_wrong_or_duplicate_cases_cannot_satisfy_gate(tmp_path, names):
    report = write_report(tmp_path, names)
    with pytest.raises(ValueError, match="exactly"):
        verify(report, ["tests/test_example.py::first"])
