"""Run the 59 previously skipped cases on their real target platforms.

No production service/driver is installed. Every selected case must pass;
missing, skipped or duplicated cases make this verification fail.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def verify_report(path: Path, expected: list[str]) -> int:
    tree = ET.parse(path)
    cases = list(tree.iter("testcase"))
    actual = [case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"]
              for case in cases]
    if len(actual) != len(expected) or set(actual) != set(expected):
        raise ValueError("Platform test report does not contain exactly the requested cases")
    if any(case.find(tag) is not None for case in cases for tag in ("skipped", "failure", "error")):
        raise ValueError("Platform test report contains skipped or failed cases")
    return len(cases)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("linux", "windows"))
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--report-directory", type=Path, default=ROOT / "build/platform-test-results")
    args = parser.parse_args()
    groups = json.loads((ROOT / "release/platform-test-cases.json").read_text(encoding="utf-8"))
    cases = groups[args.platform]
    if not cases or len(cases) != len(set(cases)):
        raise ValueError("Expected a nonempty, unique test selection")
    if not args.collect_only:
        supported = os.name == "nt" if args.platform == "windows" else sys.platform.startswith("linux")
        if not supported:
            raise RuntimeError(f"These cases require a real {args.platform} environment")
    report = args.report_directory.resolve() / (args.platform + ".xml")
    if not args.collect_only:
        report.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "pytest", "-ra", "-W", "error"]
    command += ["--collect-only"] if args.collect_only else ["--junitxml", str(report)]
    result = subprocess.run(command + cases, cwd=ROOT)
    if result.returncode:
        return result.returncode
    if not args.collect_only:
        count = verify_report(report, cases)
        print(f"Verified {count} {args.platform} cases; zero skipped, zero failed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
