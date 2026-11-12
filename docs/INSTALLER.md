# Windows installation

The normal Windows distribution is AntiOS-Setup.exe from the latest GitHub release. A portable ZIP is also available for use without a normal installation.

## Before installing

- Check the release notes for signing status.
- Verify the matching SHA-256 file when using a direct-download prerelease.
- Keep an existing trusted antivirus enabled unless you are testing in an isolated environment.

## Upgrade

Current 3.x builds use the AntiOS Engine directly.

Some older 2.x installations used retired third-party engine components. If the installer cannot safely prove that a legacy service or registration belongs to AntiOS, it can refuse the in-place upgrade rather than deleting it blindly. Remove the old version with its own uninstaller and then install the current release cleanly.

## Uninstall

Use the installed AntiOS uninstaller for normal removal. The uninstaller is expected to remove AntiOS-owned files and configuration without recursively deleting unrelated content that happens to be in the same directory.

## Portable use

The portable package contains the Windows executables and runtime resources without normal installer registration. Features that depend on installed startup configuration may require separate setup or may not be available in portable use.
