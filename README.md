# AntiOS

**Languages:** English · [Русский](README.ru.md) · [Español](README.es.md) · [简体中文](README.zh-CN.md) · [Suomi](README.fi.md) · [Polski](README.pl.md) · [Монгол](README.mn.md)

AntiOS is a pre-release endpoint-security and system-maintenance project for Windows, with a smaller Linux companion build.

**Development version:** 3.0.2a1  
**Releases:** https://github.com/Dargon777/AntiOS/releases

## Current scope

AntiOS currently includes:

- on-demand file and folder scanning with the local AntiOS Engine;
- optional Resident Guard monitoring;
- quarantine and explicit restore;
- scan reports with coverage, findings and replay support;
- Windows security and system diagnostics;
- process, persistence, memory, loaded-driver and boot/security-posture sensors;
- incident, risk and behavior context for review;
- storage cleanup, storage analysis and bounded file-recovery tools;
- coexistence reporting for Microsoft Defender and selected Kaspersky / Dr.Web installations;
- Windows installer and portable builds, plus a supplemental Linux x86_64 package.

The project is still under active development. It does **not** claim Windows primary-antivirus certification, ELAM/PPL protection, complete boot-time coverage or perfect pre-execution blocking.

## Platforms

| Platform | Status |
| --- | --- |
| Windows 10 22H2 x64 | Supported target |
| Windows 11 x64 | Supported target |
| Linux x86_64 | Supplemental companion build |
| Python 3.11+ | Development/package use |

Linux support is intentionally narrower than Windows support.

## Download

Use the latest GitHub release. Depending on the release, assets can include Windows Setup and portable packages, a Linux x86_64 package, and Python distributions.

Some prerelease Windows builds are unsigned. Check the release notes and SHA-256 files before installing them.

## Documentation

Start with the pages relevant to what you are doing:

- [Antivirus](docs/ANTIVIRUS.md)
- [Resident Guard](docs/GUARD.md)
- [Security sensors](docs/DEEP_SECURITY_FOUNDATION.md)
- [Coexistence with other security products](docs/COEXISTENCE.md)
- [Windows installation](docs/INSTALLER.md)
- [Linux companion](docs/LINUX.md)
- [Recovery](docs/RECOVERY.md)
- [Signing and release trust](docs/SIGNING.md)
- [Privacy](PRIVACY.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Development

AntiOS is developed in public, but security-sensitive exploit details should be reported privately rather than posted in issues or pull requests.

The normal repository workflow is intentionally simple: one focused change per branch/PR, a small number of meaningful commits, CI, then squash merge.

The public source tree is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
