"""Regression contracts for exhaustive static audit and native Windows cleanup."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_full_source_audit_requires_every_tracked_file_and_line():
    script = (ROOT / "scripts/audit-all-sources.py").read_text("utf-8")
    assert '"git", "ls-files", "-z"' in script
    assert "for path in paths:" in script
    assert "for number, line in enumerate(lines, 1):" in script
    assert '"sha256": hashlib.sha256(raw).hexdigest()' in script
    assert '"errors": []' in script
    assert "return 1 if errors else 0" in script


def test_per_user_uninstaller_never_recursively_erases_unknown_files():
    source = (ROOT / "scripts/uninstall.ps1").read_text("utf-8")
    assert "Remove-Item -Recurse -Force $InstallDir" not in source
    assert "Remove-Item -Recurse -Force $StartMenuDir" not in source
    assert "install-manifest.json" in source
    assert "Assert-NoReparsePoint" in source
    assert "GetFullPath" in source
    assert "Remove-EmptyDirectory" in source
    assert "Refusing a reparse point" in source
    assert source.index("foreach ($entry in @($manifest.files))") < source.index("& $Guard stop")


def test_per_user_installer_manifest_lists_only_source_files():
    source = (ROOT / "scripts/install.ps1").read_text("utf-8")
    assert "Get-ChildItem -LiteralPath $folder -Recurse -Force" in source
    assert "install-manifest.json" in source
    assert "$owned.Add" in source
    assert "($manifest | ConvertTo-Json" in source
    assert "ReparsePoint" in source
    assert source.index("$owned.Add") < source.index("Copy-Item -Force $CliSource")


def test_release_publication_requires_enabled_authenticode_signing():
    workflow = (ROOT / ".github/workflows/release.yml").read_text("utf-8")
    assert "Refuse unconfigured signed release" in workflow
    assert "vars.ENABLE_ARTIFACT_SIGNING != 'true'" in workflow
    assert "signed_release:" in workflow
    assert "type: boolean" in workflow
    assert "github.event_name == 'workflow_dispatch'" in workflow
    assert "inputs.signed_release == true" in workflow
    assert "github.ref != 'refs/heads/master'" in workflow
    publish = workflow.split("  publish-release:", 1)[1]
    assert "vars.ENABLE_ARTIFACT_SIGNING == 'true'" in publish
    assert "inputs.signed_release == true" in publish
    assert "gh api --paginate --slurp" in publish
    assert "select(.tag_name == $tag)" in publish
    assert ".[0].draft == true" in publish
    assert "(.[0].assets | length) == 0" in publish
    assert 'gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$release_id"' in publish
    assert "draft:true,prerelease:true" in publish
    assert "tag_name:$tag" in publish
    assert ".tag_name == $tag and .target_commitish == $target" in publish
    after_patch = publish.split("--method PATCH", 1)[1]
    before_upload, upload = after_patch.split('for file in "${assets[@]}"; do', 1)
    assert "verify_release_draft" in before_upload
    assert "verify_release_draft" in upload.rsplit("done", 1)[1]
    assert "--data-binary \"@$file\"" in publish
    assert "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets?name=$name" in publish
    assert ".digest == $digest" in publish
    assert 'git ls-remote origin "refs/tags/$tag"' in publish
    assert '"$tag_commit" != "$GITHUB_SHA"' in publish
    assert "gh release create" not in publish
    assert "gh release upload" not in publish
    assert "gh release edit" not in publish
    assert "--draft=false" not in publish


def test_current_install_scripts_never_bootstrap_clamav():
    installer = (ROOT / "installer/AntiOS.nsi").read_text("utf-8")
    install = installer.split('Section "AntiOS" SecMain', 1)[1].split('Section "Uninstall"', 1)[0]
    active = install.split("antios_legacy_upgrade_safe:", 1)[1]
    assert "protection-bootstrap.ps1" not in active
    assert "clamav-windows.json" not in active
    assert "Install-AmsiProvider.ps1" not in active


def test_build_scripts_deny_arbitrary_recursive_cleanup_locations():
    for filename, approved in (
        ("scripts/stage-installer.ps1", "installer-stage"),
        ("scripts/build-hardened-windows.ps1", "hardened-dist"),
    ):
        source = (ROOT / filename).read_text("utf-8")
        assert "cnotmatch" in source
        assert approved in source
        assert "ReparsePoint" in source
        assert "refusing recursive cleanup" in source
        assert source.count("param(") >= 1
