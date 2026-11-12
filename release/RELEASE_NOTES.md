# AntiOS 3.0.02 Alpha

This prerelease moves the current Windows app onto the independent AntiOS Engine and refreshes the main scan workflow.

## Changes

- Redesigned Windows overview, scan workspace, quarantine view and tools section.
- Added light, balanced and heavy scan profiles with a separate worker setting.
- Expanded the local SHA-256 signature set and improved folders with many small files.
- Added clearer scan-coverage reporting and decision replay from saved JSON reports.
- Added an inert benchmark with known expected outcomes.

## Downloads

The release contains Windows x64 Setup and portable packages, a Linux x86_64 archive and Python distributions.

The Windows binaries in this prerelease are **unsigned**. SHA-256 files verify download integrity but not publisher identity.

## Upgrading from 2.x

Current 3.x builds no longer use the retired managed third-party scan engine. If Setup reports a legacy-installation conflict, follow [docs/INSTALLER.md](../docs/INSTALLER.md) and perform a clean migration instead of deleting services or registrations manually.

## Русский

В этом предварительном релизе Windows-приложение переведено на собственный AntiOS Engine и обновлён основной сценарий проверки.

- переработаны обзор, экран проверки, карантин и раздел инструментов;
- добавлены профили Light / Balanced / Heavy и отдельный выбор числа потоков;
- расширен локальный набор SHA-256 сигнатур;
- отчёты лучше показывают неполное покрытие и поддерживают replay решения;
- добавлен безопасный контрольный benchmark.

Windows-сборки этого релиза **не подписаны**. SHA-256 подтверждает целостность файла, но не личность издателя.
