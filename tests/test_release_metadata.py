from pathlib import Path
import tomllib
import re

from antios import __version__


def test_release_version_matches_package_version():
    release_version = Path("release/VERSION").read_text(encoding="utf-8").strip()
    assert release_version == __version__


def test_release_tag_matches_package_version():
    tag = Path("release/TAG").read_text(encoding="utf-8").strip()
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)a(\d+)", __version__)
    assert match is not None
    major, minor, patch, alpha = map(int, match.groups())
    expected = f"V.{major}.{minor}.{patch:02d}-Alpha"
    if alpha > 1:
        expected += f".{alpha}"
    assert tag == expected


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
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)a(\d+)", __version__)
    assert match is not None
    major, minor, patch, _alpha = map(int, match.groups())
    expected_numeric = f"{major}.{minor}.{patch}.0"
    expected_tuple = f"({major}, {minor}, {patch}, 0)"

    for path in (
        "release/windows-cli-version.txt",
        "release/windows-gui-version.txt",
        "release/windows-guard-version.txt",
    ):
        text = Path(path).read_text(encoding="utf-8")
        assert expected_tuple in text
        assert __version__ in text

    installer = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert f'!define APP_VERSION "{__version__}"' in installer
    assert f'!define NUMERIC_VERSION "{expected_numeric}"' in installer

    store_script = Path("scripts/build-store-msix.ps1").read_text(encoding="utf-8")
    store_workflow = Path(".github/workflows/store.yml").read_text(encoding="utf-8")
    assert expected_numeric in store_script
    assert expected_numeric in store_workflow

    release_workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "Expected exactly one empty draft for the requested tag" in release_workflow
    assert "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets?name=$name" in release_workflow
    assert 'gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$release_id"' in release_workflow
    assert "gh release create" not in release_workflow
    assert "gh release upload" not in release_workflow
    assert "signed_release:" in release_workflow
    assert "inputs.signed_release == true" in release_workflow
    assert "Refuse unconfigured signed release" in release_workflow
    assert 'cat release/RELEASE_NOTES.md' in release_workflow
    assert "draft:true,prerelease:true" in release_workflow
    # Upload preflight must verify both artifact types and every checksum
    # before changing or uploading assets to the release draft.
    assert "Only the eight reviewed deliverables" in release_workflow
    assert "Expected one wheel and one source distribution." in release_workflow
    assert "Unexpected additional release payload files" in release_workflow
    assert "sha256sum --check AntiOS-Setup.exe.sha256" in release_workflow
    assert "sha256sum --check AntiOS-windows-x64.zip.sha256" in release_workflow
    assert "sha256sum --check AntiOS-linux-x64.tar.gz.sha256" in release_workflow
    assert release_workflow.index("sha256sum --check AntiOS-Setup.exe.sha256") < release_workflow.index(
        'gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$release_id"'
    )

