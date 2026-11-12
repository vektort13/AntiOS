#!/usr/bin/env python3
"""Inventory and parse every tracked file, line-by-line, with a reproducible report.

Heuristic findings are manual-review leads, not proven vulnerabilities.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BINARY = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".ai",
          ".pdf", ".zip", ".exe", ".dll", ".pyd", ".woff", ".woff2",
          ".ttf", ".mp3", ".mp4", ".bin", ".pdb", ".msix"}
SOURCE = {".py", ".ps1", ".psm1", ".psd1", ".c", ".h", ".cpp", ".hpp",
          ".nsi", ".nsh", ".sh", ".js", ".ts", ".jsx", ".tsx", ".html",
          ".css", ".yml", ".yaml", ".toml", ".json", ".xml", ".svg"}
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
CONFLICT = re.compile(r"^(?:<<<<<<< |=======\s*$|>>>>>>> )")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
RISKS = (
    ("exec-eval", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("shell-execution", re.compile(r"\bshell\s*=\s*True\b|\bos\.system\s*\(")),
    ("pickle-load", re.compile(r"\bpickle\.(?:load|loads)\s*\(")),
    ("unsafe-temp", re.compile(r"\btempfile\.mktemp\s*\(")),
    ("powershell-eval", re.compile(r"\b(?:Invoke-Expression|iex)\s+", re.I)),
    ("tls-disabled", re.compile(r"\bverify\s*=\s*False\b|SkipCertificateCheck", re.I)),
    ("unsafe-c-api", re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf|gets)\s*\(")),
    ("recursive-delete", re.compile(r"\brm\s+-rf\b|\brmtree\s*\(|\bRemove-Item\b.*-Recurse", re.I)),
)


def tracked_paths() -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [Path(os.fsdecode(part)) for part in raw.split(b"\0") if part]


def parse_file(path: Path, data: str) -> str:
    suffix = path.suffix.lower()
    if suffix == ".py":
        compile(data, path.as_posix(), "exec", dont_inherit=True)
        return "python-compile"
    if suffix == ".json":
        json.loads(data)
        return "json"
    if suffix == ".toml":
        tomllib.loads(data)
        return "toml"
    if suffix in {".xml", ".svg"}:
        ET.fromstring(data)
        return "xml"
    if suffix in {".yml", ".yaml"}:
        import yaml
        yaml.safe_load(data)
        return "yaml"
    if suffix == ".sh":
        subprocess.run(["bash", "-n", str(ROOT / path)], check=True,
                       capture_output=True, text=True, timeout=15)
        return "bash-grammar"
    if suffix in {".ps1", ".psm1", ".psd1"}:
        return "powershell-grammar-in-Windows-job"
    if suffix in {".c", ".h", ".cpp", ".hpp"}:
        return "native-WDK-compiler-in-Windows-job"
    if suffix in {".nsi", ".nsh"}:
        return "NSIS-compiler-in-portable-job"
    return "text-inspected"


def audit_path(path: Path) -> dict:
    raw = (ROOT / path).read_bytes()
    suffix = path.suffix.lower()
    item = {"path": path.as_posix(), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "kind": "binary" if suffix in BINARY else "text", "lines": 0,
            "validation": [], "findings": [], "errors": []}
    if suffix in BINARY:
        if not raw:
            item["errors"].append("Empty binary resource")
        return item
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        item["errors"].append(f"Non-UTF8 text: {exc}")
        return item
    lines = content.splitlines(keepends=True)
    item["lines"] = len(lines)
    for number, line in enumerate(lines, 1):
        if CONTROL.search(line):
            item["findings"].append({"line": number, "kind": "control-character"})
        if BIDI.search(line):
            item["findings"].append({"line": number, "kind": "bidi-character"})
        if CONFLICT.match(line):
            item["errors"].append(f"Git conflict marker at line {number}")
        if suffix in SOURCE:
            for category, pattern in RISKS:
                if pattern.search(line):
                    item["findings"].append(
                        {"line": number, "kind": category, "sample": line.strip()[:120]})
    try:
        item["validation"].append(parse_file(path, content))
    except (SyntaxError, ValueError, TypeError, ET.ParseError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        item["errors"].append(f"Syntax/format error: {exc}")
    return item


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--output", default=".audit/full-source.json")
    cli.add_argument("--summary", default=".audit/full-source.md")
    args = cli.parse_args()
    paths = tracked_paths()
    if not paths:
        print("No tracked files", file=sys.stderr)
        return 1
    rows = []
    for path in paths:
        try:
            rows.append(audit_path(path))
        except (OSError, PermissionError, ImportError) as exc:
            rows.append({"path": path.as_posix(), "bytes": 0, "sha256": "",
                         "kind": "unreadable", "lines": 0, "validation": [],
                         "findings": [], "errors": [str(exc)]})
    rows.sort(key=lambda item: item["path"])
    errors = [(r["path"], e) for r in rows for e in r["errors"]]
    leads = [(r["path"], f) for r in rows for f in r["findings"]]
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    data = {"schema": 1, "commit": commit, "tracked_files": len(rows),
            "text_files": sum(r["kind"] == "text" for r in rows),
            "total_text_lines": sum(r["lines"] for r in rows),
            "records": rows}
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = [
        "# AntiOS tracked-source audit", "",
        "Commit: " + commit,
        f"Files: {len(rows)}, textual lines: {data['total_text_lines']}",
        f"Errors: {len(errors)}; heuristic manual-review leads: {len(leads)}",
        "",
        "This is whole-line inventory and syntax validation, not proof of semantic correctness.",
        "PowerShell/NSIS checks run in separate Windows jobs.", "",
        "## Errors",
    ]
    report += [f"- {path}: {err}" for path, err in errors] or ["None."]
    report += ["", "## Manual-review leads"]
    report += [f"- {path}:{lead['line']} {lead['kind']}"
               for path, lead in leads] or ["None."]
    report += ["", "## Per-file audit evidence", "",
               "| File | Lines | Validation | Leads | Errors |",
               "|---|---:|---|---:|---:|"]
    for row in rows:
        report.append(
            f"| {row['path']} | {row['lines']} | "
            f"{', '.join(row['validation']) or row['kind']} | "
            f"{len(row['findings'])} | {len(row['errors'])} |")
    summary = ROOT / args.summary
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"Scanned all {len(rows)} tracked files, {data['total_text_lines']} lines; "
          f"{len(errors)} errors, {len(leads)} leads.")
    for path, error in errors[:40]:
        print(f"ERROR {path}: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
