# AntiOS

**Languages:** English · [Русский](README.ru.md) · [Español](README.es.md) · [简体中文](README.zh-CN.md) · [Suomi](README.fi.md) · [Polski](README.pl.md) · [Монгол](README.mn.md)

AntiOS is an endpoint-security companion and system-maintenance toolkit for Windows, with supplemental Linux support.

> **Development tree:** `3.0.2a1`<br>
> **Latest published release:** [GitHub Releases](https://github.com/Dargon777/AntiOS/releases)<br>
> **Status:** pre-release software

## What AntiOS provides

- on-demand file and folder scanning;
- optional resident protection;
- quarantine and explicit restore workflows;
- coexistence with Microsoft Defender and supported Kaspersky / Dr.Web products;
- Windows security, health and system diagnostics;
- Storage Cleanup and Storage Intelligence;
- bounded file-recovery and integrity checks;
- local incident and protection-status views;
- Windows installer, portable and Python-package distributions;
- a supplemental Linux x86_64 companion build.

AntiOS is designed to complement existing protection rather than silently disable or reconfigure another antivirus product.

## Platform support

| Platform | Status | Notes |
| --- | --- | --- |
| Windows 10 22H2 x64 | Supported desktop target | Installer and portable builds |
| Windows 11 x64 | Supported desktop target | Installer and portable builds |
| Linux x86_64 | Supplemental companion | Portable build targets glibc 2.39+; desktop UI requires X11 or XWayland |
| Python 3.11+ | Source/package use | CLI and development scenarios |

Linux support is intentionally narrower than Windows support and does not claim distro-native package or service integration.

## Download

Use the latest published release:

[GitHub Releases](https://github.com/Dargon777/AntiOS/releases)

Current release assets can include:

- `AntiOS-Setup.exe` — normal Windows installation;
- `AntiOS-windows-x64.zip` — portable Windows build;
- `AntiOS-linux-x64.tar.gz` — supplemental Linux x86_64 build;
- Python wheel and source package for development/package use.

The repository may contain development changes newer than the latest published release.

## Antivirus and coexistence

AntiOS provides independent scanning and optional resident protection while preserving the settings and ownership of supported existing antivirus products.

On Windows, coexistence is supported with Microsoft Defender and selected Kaspersky / Dr.Web products. Linux companion mode can also report supported third-party protection where available.

AntiOS does **not** claim certified Windows primary-antivirus registration, ELAM/PPL protection, complete boot-time protection or perfect pre-execution interception.

See:

- [Antivirus](docs/ANTIVIRUS.md)
- [Windows third-party antivirus companion mode](docs/WINDOWS_COMPANION.md)
- [Linux companion](docs/LINUX.md)

## Protection assistant

Choose **Assistant** in the antivirus center to run harmless functional checks, compare file snapshots or review plain-language activity explanations. Earlier changed files are recovered into a new folder. The command line also supports `antios self-check --json`.

Explanations use local evidence. A passing self-check describes current operation; it does not guarantee detection of every threat.

## Storage and recovery

Storage Cleanup and Storage Intelligence help identify cleanup candidates and understand storage usage while keeping destructive actions explicit.

Recovery features are bounded backup/integrity tools. They are not full-system rollback and do not prove that restored content is malware-free.

See:

- [Storage Intelligence](docs/STORAGE_INTELLIGENCE.md)
- [Recovery](docs/RECOVERY.md)

## Security and privacy

AntiOS processes security and diagnostic data locally by default and does not enable automatic telemetry.

Public documentation intentionally focuses on capabilities, limitations and user-visible behavior. Security-sensitive implementation details are not published in public-facing materials when they would add unnecessary reconnaissance or bypass value.

Some security-sensitive or commercial implementation components may be developed or distributed outside the public source tree. Public interfaces and user-visible behavior should remain documented without exposing internal enforcement design.

This documentation policy is not a substitute for secure design, code review, signed updates, least privilege or fail-safe behavior.

See:

- [Security policy](SECURITY.md)
- [Privacy policy](PRIVACY.md)
- [Contributing](CONTRIBUTING.md)

## Installation

For normal Windows use, install the latest `AntiOS-Setup.exe` from Releases.

Use the portable Windows archive when installation is not desired. Linux users can use the published x86_64 archive on compatible systems. Python packages are primarily intended for development and package-based use.

## Development

The current AntiOS public tree is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Contributors should keep public README files, release notes, pull requests and issues focused on user-visible behavior and reproducible public interfaces. Detailed security architecture, bypass research and other sensitive implementation discussion belongs in a private engineering or vulnerability-reporting channel.
