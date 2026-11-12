# AntiOS public changelog

This public changelog intentionally contains only user-facing capability summaries.

Detailed security architecture, trust-boundary sequencing, service/task identities, IPC/state layouts, detection thresholds, cache/queue settings, update handoff mechanics, repair/rollback sequencing and native protocol details are not published here.

## 3.0.2a1 - 2026-11-11 (prerelease)

- Redesigns the Windows dashboard around protection status, scanning, quarantine and tools.
- Adds light, balanced and heavy scan profiles with an independent worker setting.
- Adds curated signatures and improves performance in folders with many small files.
- Explains scan coverage and supports replaying decisions from saved reports.
- Adds an inert detection benchmark with known expected outcomes.

## 3.0.1a1 - 2026-11-10 (release candidate)

- introduces AntiOS's independent local scan engine across the app, CLI and optional resident monitor;
- removes external antivirus-engine runtime requirements from new packages;
- retains read-only coexistence with existing protection;
- blocks potentially unsafe upgrades from legacy installations rather than silently deleting components;
- updates release packaging and version metadata.

This early alpha does not match the detection breadth of mature antivirus products. Broad release acceptance, Windows upgrade validation and code signing remain outstanding.

## 2.0.0a37 - 2026-11-05

- adds a protection assistant with harmless engine checks, a temporary backup recovery test and actionable results;
- compares saved file snapshots and recovers earlier copies of changed or missing files;
- explains recorded activity in plain language while distinguishing confirmed detections from behavioral suspicion;
- connects the three features in one local workspace and adds Windows acceptance for the user-facing self-check.
- keeps protection diagnostics available in a normal Windows session when administrator-only configuration cannot be inspected.

## 2.0.0a36 - 2026-11-05

- repairs missing database-verification settings in older Windows protection-engine installations;
- reloads repaired engine configuration and preserves existing configuration if recovery fails;
- expands Windows acceptance checks to cover upgrades, large-file scanning, a standard harmless antivirus test and resident Guard scanning.

## 2.0.0a35 - 2026-11-04

- restores missing settings for existing Windows protection engines while preserving settings owned by other applications;
- repairs current-user Guard file access during upgrades and administrator-assisted recovery while preserving history;
- improves installer compatibility on 64-bit Windows.

## 2.0.0a34 - 2026-11-04

- fixes a first-time ClamAV setup error when an optional engine registration value is not yet present;
- improves recovery of permissions on existing per-user Guard state files without deleting their history;
- preserves unrelated local files and third-party protection settings;
- extends Windows regression tests for installation and Guard state recovery.

This prerelease remains a companion to existing endpoint protection. If older Guard state files are inaccessible, explicit administrator-assisted reconfiguration may still be required.

## 2.0.0a33 - 2026-11-04

- opens the Windows dashboard on a redesigned protection center with the current access level and a system-drive selector;
- adds an interactive administrator scan window for installed copies;
- scans the full file selection by default and streams large files through ClamAV;
- reports inaccessible files and incomplete engine analysis in scan results.
- fixes false-positive permission checks that could prevent the ClamAV engine from installing on otherwise standard Windows folders;

## 2.0.0a32 - 2026-11-03

- improves Windows Guard startup and recovery after running AntiOS as administrator;
- keeps independent protection status available when a component cannot be read;
- reduces repeated diagnostic messages when navigating the interface;
- fixes interface cleanup when changing themes during a scan;
- clarifies incompatible Guard settings and Windows access errors;
- adds isolated regression checks for startup, status reporting and Windows compatibility.

Existing inaccessible user data may require a one-time administrator-assisted Guard reconfiguration. AntiOS remains prerelease companion software.

## 2.0.0a31 - 2026-11-03

Alpha 31 improves protection diagnostics and reliability:

- keeps protection status reporting available when a companion component cannot be read;
- improves Windows permission-error messages and gives clearer guidance for incompatible Guard settings;
- reduces repeated diagnostic notices without concealing the underlying failure;
- distinguishes incomplete scan coverage from successful process completion;
- improves privacy-conscious support reports and adds regression coverage.

This prerelease does not replace Windows Defender or other antivirus products. An inaccessible Windows resource may still require a local repair.

## 2.0.0a30 - 2026-10-31

Alpha 30 expands AntiOS companion support across Windows and Linux:

- adds a Linux x86_64 release archive alongside the Windows installer and portable package;
- adds supplemental Kaspersky and Dr.Web coexistence support on Windows and Linux;
- keeps third-party antivirus products in control of their own real-time protection and policy;
- exposes companion status in AntiOS diagnostics and protection views;
- carries forward Storage Intelligence, cleanup safety and recovery verification improvements from the previous alpha.

## Current alpha line

Recent AntiOS v2 alpha work includes:

- Windows and Linux companion support;
- on-demand antivirus scanning and optional resident protection;
- encrypted quarantine and restore workflows;
- coexistence with Microsoft Defender and selected third-party antivirus products;
- diagnostics, incident views and privacy-conscious support export;
- Storage Cleanup and Storage Intelligence;
- bounded file recovery and integrity checking;
- installer, updater, repair and upgrade reliability work;
- hardened build and signing work;
- Windows 10 22H2 x64 compatibility target and Windows 11 support;
- UI, localization and Microsoft Store packaging improvements.

For security reasons, historical engineering-level changelog entries have been removed from the current public tree. Older commits and previously published GitHub metadata may still exist in repository history.

Security issues should be reported through [SECURITY.md](SECURITY.md).
