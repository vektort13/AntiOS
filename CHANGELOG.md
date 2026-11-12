# Changelog

This file summarizes user-visible changes. Detailed commit history remains available in Git.

## Unreleased

- Added Windows process, persistence and bounded process-memory security sensors.
- Added loaded-driver trust/BYOVD intelligence and boot, Secure Boot, TPM, VBS and DMA posture checks.
- Connected deep-security evidence to the existing risk and incident pipeline without giving weak heuristics independent quarantine authority.
- Simplified GitHub Actions into five purpose-driven workflows.
- Refreshed public documentation and removed stale references to the legacy third-party scan-engine path.

## 3.0.2a1 — 2026-11-12

- Redesigned the Windows dashboard around protection status, scanning, quarantine and tools.
- Added light, balanced and heavy scan profiles with a separate worker setting.
- Expanded the local SHA-256 signature set and improved scanning of folders with many small files.
- Added clearer coverage reporting and offline decision replay from saved scan reports.
- Added an inert benchmark with known expected outcomes.
- Published Windows Setup/portable, Linux x86_64 and Python prerelease packages.

## 3.0.1a1 — 2026-11-10

- Moved the app, CLI and Resident Guard to the independent AntiOS Engine.
- Removed the third-party antivirus-engine runtime requirement from new packages.
- Kept coexistence reporting for existing security products.
- Added safer handling for legacy installations that still contain retired engine components.

## 2.0 alpha line — 2026-09 to 2026-11

The 2.0 alpha series established the current dashboard, Guard, quarantine, recovery, diagnostics, coexistence, Linux companion, installer and packaging foundations. It also included the older managed third-party scan-engine path that was retired in the 3.0 line.

Per-release historical notes remain available on the GitHub Releases page.

Security vulnerabilities should be reported through [SECURITY.md](SECURITY.md).
