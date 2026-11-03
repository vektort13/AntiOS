import ast
from pathlib import Path
import tomllib

from antios import __version__


def test_release_version_matches_package_version():
    release_version = Path("release/VERSION").read_text(encoding="utf-8").strip()
    assert release_version == __version__


def test_release_tag_matches_package_version():
    tag = Path("release/TAG").read_text(encoding="utf-8").strip()
    base, alpha = __version__.split("a")
    assert tag == f"v{base}-alpha.{alpha}"


def test_package_declares_apache_2_license():
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["license"] == "Apache-2.0"
    assert "LICENSE" in metadata["project"]["license-files"]
    assert "NOTICE" in metadata["project"]["license-files"]


def test_package_exposes_gui_script():
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["gui-scripts"]["antios-gui"] == "antios.dashboard:main"


def test_trust_docs_are_present():
    assert Path("PRIVACY.md").is_file()
    assert Path("SUPPORT.md").is_file()


def test_license_and_notice_are_present():
    license_text = Path("LICENSE").read_text(encoding="utf-8")
    notice = Path("NOTICE").read_text(encoding="utf-8")

    assert "Apache License" in license_text
    assert "Version 2.0" in license_text
    assert "Copyright 2026 Dargon777" in notice
    assert "does not retroactively relicense" in notice


def test_windows_and_store_versions_track_package_alpha():
    _base, alpha = __version__.split("a")
    expected_numeric = f"2.0.{int(alpha)}.0"
    expected_tuple = (2, 0, int(alpha), 0)

    for path in (
        "release/windows-cli-version.txt",
        "release/windows-gui-version.txt",
        "release/windows-guard-version.txt",
    ):
        tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        fixed_info = [node for node in calls if node.func.id == "FixedFileInfo"]
        assert len(fixed_info) == 1, path
        fixed_fields = {keyword.arg: keyword.value for keyword in fixed_info[0].keywords}
        for name in ("filevers", "prodvers"):
            assert ast.literal_eval(fixed_fields[name]) == expected_tuple, (path, name)

        string_fields = {
            ast.literal_eval(node.args[0]): ast.literal_eval(node.args[1])
            for node in calls if node.func.id == "StringStruct"
        }
        for name in ("FileVersion", "ProductVersion"):
            assert string_fields[name] == __version__, (path, name)

    installer = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert f'!define APP_VERSION "{__version__}"' in installer
    assert f'!define NUMERIC_VERSION "{expected_numeric}"' in installer

    store_script = Path("scripts/build-store-msix.ps1").read_text(encoding="utf-8")
    store_workflow = Path(".github/workflows/store-msix.yml").read_text(encoding="utf-8")
    assert expected_numeric in store_script
    assert expected_numeric in store_workflow
