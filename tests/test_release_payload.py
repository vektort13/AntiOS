"""Windows packaging must include only the AntiOS-owned runtime resources."""
import runpy
from pathlib import Path
import zipfile

import pytest

payload = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/release-payload.py"))


def test_native_resources_are_complete_and_exclude_old_engine_bootstrap(tmp_path):
    sources = payload["runtime_files"]()
    names = {path.name for path in sources}
    assert {
        "guard-startup.ps1", "guard-trust.ps1", "guard-state-access.cs",
        "protection-first-run.ps1", "dashboard-startup.ps1",
    } <= names
    assert not any("clamav" in name.lower() or "amsi" in name.lower()
                   or "bootstrap" in name.lower() for name in names)
    installed = tmp_path / "site-packages/antios/assets/windows"
    payload["stage_runtime"](installed)
    assert {file.name for file in installed.iterdir()} == names
    assert (installed / "guard-trust.ps1").read_bytes() == next(
        path for path in sources if path.name == "guard-trust.ps1").read_bytes()


def test_portable_verification_checks_native_resources(tmp_path):
    package = tmp_path / "portable"
    payload["stage_runtime"](package)
    for name in ("AntiOS.exe", "AntiOS-GUI.exe", "AntiOS-Guard.exe"):
        (package / name).write_bytes(b"inert packaged executable")
    archive = tmp_path / "portable.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path in package.iterdir():
            bundle.write(path, path.name)
    payload["verify_package"](archive)
    (package / "guard-trust.ps1").unlink()
    with pytest.raises(ValueError, match="guard-trust.ps1"):
        payload["verify_package"](package)


def test_wheel_verification_rejects_modified_native_files(tmp_path):
    wheel = tmp_path / "wheel"
    resources = wheel / "antios/assets/windows"
    payload["stage_runtime"](resources)
    payload["verify_package"](wheel, wheel=True)
    (resources / "guard-startup.ps1").write_text("inert corrupted resource")
    with pytest.raises(ValueError, match="resources differ"):
        payload["verify_package"](wheel, wheel=True)


def test_installer_source_does_not_bootstrap_third_party_engine():
    installer = (Path(__file__).resolve().parents[1] / "installer/AntiOS.nsi").read_text("utf-8")
    section = installer.split('Section "AntiOS" SecMain', 1)[1].split('Section "Uninstall"', 1)[0]
    active = section.split("antios_legacy_upgrade_safe:", 1)[1]
    assert "protection-bootstrap.ps1" not in active
    assert "Install-AmsiProvider.ps1" not in active
    assert "clamav-windows.json" not in section
    assert "protection-first-run.ps1" in section
