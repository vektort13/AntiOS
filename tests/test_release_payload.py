import json
from pathlib import Path
import runpy
import zipfile

import pytest

from antios import protection_repair

payload = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/release-payload.py"))


def test_packaged_resources_resolve_without_the_source_tree(monkeypatch, tmp_path):
    module = tmp_path / "site-packages/antios/protection_repair.py"
    resources = module.parent / "assets/windows"
    payload["stage_runtime"](resources)
    monkeypatch.setattr(protection_repair, "__file__", str(module))
    for locate in (protection_repair._script_path, protection_repair._bootstrap_script_path,
                   protection_repair._bootstrap_manifest_path):
        path = locate()
        assert path.parent == resources
        assert path.is_file()
    assert json.loads(protection_repair._bootstrap_manifest_path().read_text())["schema"] == 1


def test_portable_verification_checks_extracted_archive_contents(tmp_path):
    package = tmp_path / "portable"
    payload["stage_runtime"](package)
    for name in ("AntiOS.exe", "AntiOS-GUI.exe", "AntiOS-Guard.exe", "AntiOS-AmsiProvider.dll"):
        (package / name).write_bytes(b"inert package fixture")
    archive = tmp_path / "portable.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path in package.iterdir():
            bundle.write(path, path.name)
    payload["verify_package"](archive)
    (package / "clamav-trust.ps1").unlink()
    with pytest.raises(ValueError, match="clamav-trust.ps1"):
        payload["verify_package"](package)


def test_wheel_verification_rejects_modified_resources(tmp_path):
    wheel = tmp_path / "wheel"
    resources = wheel / "antios/assets/windows"
    payload["stage_runtime"](resources)
    payload["verify_package"](wheel, wheel=True)
    (resources / "protection-repair.ps1").write_text("inert incorrect resource")
    with pytest.raises(ValueError, match="resources differ"):
        payload["verify_package"](wheel, wheel=True)
