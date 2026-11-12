from __future__ import annotations

import subprocess
import sys

FORBIDDEN_PREFIXES = (
    "proprietary/",
    "private/",
    "antios/proprietary/",
    "antios/private/",
    "private-core/",
    "core-private/",
    "vendor/private-core/",
)


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    tracked = [line.strip().replace("\\", "/") for line in result.stdout.splitlines()]
    leaked = [
        path
        for path in tracked
        if any(path.casefold().startswith(prefix.casefold()) for prefix in FORBIDDEN_PREFIXES)
    ]

    if leaked:
        print("Refusing public build: private/proprietary paths are tracked:", file=sys.stderr)
        for path in leaked:
            print(f"  - {path}", file=sys.stderr)
        return 2

    print("Public/private source boundary: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
