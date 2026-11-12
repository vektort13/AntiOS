# Antivirus

AntiOS provides on-demand scanning, findings, quarantine/restore and optional resident protection.

## Public behavior

- Users choose files or folders to scan.
- Results distinguish detections, skipped items, errors and incomplete coverage.
- JSON reports include a coverage contract with counts and reason codes for incomplete inspection. A file can have a review finding even when the engine completed its checks.
- Advisory rule findings include a rule family and rule ID for filtering across reports.
- Quarantine and restore are explicit operations.
- AntiOS can coexist with supported primary antivirus products without disabling them.
- **AntiOS Engine is the default file detection engine.** It checks local SHA-256 signatures, advisory PE, ELF and script indicators, and supported ZIP, GZIP, TAR, BZIP2 and XZ contents. Supported OpenXML VBA projects are reported for review. The engine runs offline.
- CLI, dashboard and Guard use a shared signed SHA-256 catalog for the current user. The bundled starter set is curated from public malware reports and includes a separate EICAR self-test rule. The existing local SHA-256 file option overrides the shared catalog for an individual on-demand scan. Findings based on structural indicators are for manual review.
- Large files can still match a full-file hash. Limits, damaged entries and recognized unsupported archives are surfaced as incomplete coverage.
- An explicit on-demand file limit can be set up to 2 GiB. Full content inspection has a smaller memory budget, and larger files use streaming SHA-256 with bounded structural inspection.
- Protection status surfaces degraded or incomplete states instead of silently reporting success.
- Experimental native protection is not treated as production-certified primary antivirus protection.

## Scan profiles

| Profile | Default workers | Full file inspection limit | Archive nesting limit |
| --- | ---: | ---: | ---: |
| Light | 2 | 16 MiB | 2 |
| Balanced (default) | 4 | 64 MiB | 4 |
| Heavy | 8 | 96 MiB | 6 |

Each profile checks the full SHA-256 of files it can read. Above the profile's inspection limit, AntiOS streams the file and inspects a bounded preview. The report flags partial coverage. Heavy mode also allows more archive entries and decompressed content per file.

Use the scan-depth and worker controls in the dashboard, or pass `--profile light`, `--profile balanced`, or `--profile heavy` to `antios virus-scan`. For example, `antios virus-scan PATH --profile heavy --workers 12 --json` requests deep inspection with more parallelism. The worker override accepts 1–16 and is capped by the available logical CPUs. A single selected file uses one worker.

## Scan decisions and replay

New JSON reports include `decision` and `proof_receipt`. The decision records the detection status, certainty, inspection coverage, review priority and confidence in remediation. An unreadable archive can require review with an undetermined detection status. A signature hit can remain confirmed even when other files received partial inspection.

Run `antios virus-scan-replay REPORT.json --json` to check that the saved evidence reproduces the verdict. Replay reads the report and uses its versioned decision policy. The receipt checksum covers the recorded decision, counts, scope, signature set and finding and issue evidence. It checks internal consistency. Reports are unsigned. Post-scan quarantine annotations and timestamps are outside the receipt. Reports exported before this feature lack a supported receipt.

Run `antios virus-scan-benchmark --json` to generate and test a labeled corpus of ten inert controls under each profile. The corpus covers clean inputs, exact and nested hash matches, an advisory, unreadable and unsupported archives, and bounded streaming. The command checks the expected answers, replays each verdict and reports median folder-scan time. Its results measure these controls. Estimating real-world detection and false-positive rates requires an independently labeled evaluation set.

## Important limitations

AntiOS v2 alpha is pre-release software. It does not claim ELAM/PPL, Windows primary-antivirus certification, complete boot-time protection or perfect pre-execution interception.

A clean result is limited to the content and providers that were actually checked.

## Catalog updates

Run `antios signatures status --json` to see the active catalog version and any fallback warning.
Run `antios signatures install PACKAGE` to install a newer publisher-signed catalog for your account.
A rejected update leaves the existing catalog available. An unreadable installed catalog is surfaced as degraded while scanning continues with a verified fallback.

The starter catalog contains public sector information from the UK National Cyber Security Centre
licensed under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).
See the [NCSC malware analysis reports](https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports)
for the original indicators and publication dates. The catalog is a limited exact-match set.

The application includes 13 additional exact SHA-256 matches from the Windows and ELF sample tables in the [CISA/FBI Akira advisory](https://www.cisa.gov/sites/default/files/2024-04/aa24-109a-stopransomware-akira-ransomware_2.pdf). The report counts these separately from the signed catalog. Signed catalog versions above 3 supersede this supplement.

## Internal design

Security-sensitive implementation detail is intentionally omitted from public documentation. This includes internal provider sequencing, process/service identities, state and IPC formats, retry/timeout values, verdict caches, native protocol details, repair/update handoffs and enforcement thresholds.

For vulnerabilities, use [../SECURITY.md](../SECURITY.md).
