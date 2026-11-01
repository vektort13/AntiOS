"""Stage and verify the resources shipped in AntiOS distributions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def runtime_files() -> list[Path]:
    manifest = json.loads((ROOT / "release/windows-runtime-files.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), list):
        raise ValueError("Invalid Windows runtime resource manifest")
    paths, names = [], set()
    for value in manifest["files"]:
        relative = PurePosixPath(value)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("Invalid runtime resource path")
        path = ROOT.joinpath(*relative.parts)
        if not path.is_file() or path.name.casefold() in names:
            raise ValueError(f"Missing or duplicate runtime resource: {value}")
        names.add(path.name.casefold())
        paths.append(path)
    if not paths:
        raise ValueError("Runtime resource manifest is empty")
    return paths


def stage_runtime(destination: Path) -> None:
    sources = runtime_files()
    destination.mkdir(parents=True, exist_ok=True)
    for source in sources:
        shutil.copy2(source, destination / source.name)


def verify_package(path: Path, *, wheel: bool = False) -> None:
    prefix = "antios/assets/windows/" if wheel else ""
    expected = {prefix + source.name: source.read_bytes() for source in runtime_files()}
    required = set(expected)
    if not wheel:
        required.update({"AntiOS.exe", "AntiOS-GUI.exe", "AntiOS-Guard.exe", "AntiOS-AmsiProvider.dll"})
    if path.is_dir():
        names = {p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file()}
        read = lambda name: path.joinpath(*PurePosixPath(name).parts).read_bytes()
        _verify(names, read, required, expected)
    else:
        with zipfile.ZipFile(path) as bundle:
            if bundle.testzip() is not None:
                raise ValueError("Distribution archive has an invalid checksum")
            _verify(set(bundle.namelist()), bundle.read, required, expected)


def _verify(names, read, required, expected) -> None:
    missing = required - names
    if missing:
        raise ValueError("Distribution resources missing: " + ", ".join(sorted(missing)))
    changed = [name for name, content in expected.items() if read(name) != content]
    if changed:
        raise ValueError("Distribution resources differ: " + ", ".join(sorted(changed)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["stage-runtime", "verify-portable", "verify-wheel"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.operation == "stage-runtime":
        stage_runtime(args.path)
    else:
        verify_package(args.path, wheel=args.operation == "verify-wheel")
    print("Distribution resources: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
