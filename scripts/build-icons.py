from __future__ import annotations

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "antios" / "assets" / "icons"
OUTPUT = ROOT / "build" / "icons"
SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)


def build_icon(name: str) -> Path:
    source = SOURCE / f"{name}.png"
    if not source.is_file():
        raise FileNotFoundError(source)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    target = OUTPUT / f"{name}.ico"
    with Image.open(source) as image:
        image.convert("RGBA").save(
            target,
            format="ICO",
            sizes=[(size, size) for size in SIZES],
        )
    return target


def main() -> int:
    for name in ("app_main", "app_taskbar", "tray_alert", "tray_ok"):
        target = build_icon(name)
        print(target.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
