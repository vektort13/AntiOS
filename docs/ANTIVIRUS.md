# Antivirus

AntiOS has its own local file-inspection engine. Current 3.x builds do not require ClamAV or another external antivirus engine to perform AntiOS scans.

## What a scan does

The engine can:

- calculate full-file SHA-256 hashes for readable files;
- match the bundled and installed AntiOS signature catalog;
- inspect supported PE, ELF and script structures;
- inspect supported ZIP, GZIP, TAR, BZIP2 and XZ contents within configured limits;
- flag selected structural indicators for review;
- report unreadable, truncated or unsupported content as incomplete coverage rather than clean.

Quarantine and restore are explicit operations. Structural or behavioral review findings are not treated as confirmed malware by themselves.

## Scan profiles

| Profile | Default workers | Full-content inspection limit | Archive nesting |
| --- | ---: | ---: | ---: |
| Light | 2 | 16 MiB | 2 |
| Balanced | 4 | 64 MiB | 4 |
| Heavy | 8 | 96 MiB | 6 |

Large readable files can still receive a full SHA-256 hash while deeper structural inspection stays bounded. Reports show when coverage is partial.

Example command:

    antios virus-scan PATH --profile heavy --workers 12 --json

## Reports and replay

JSON scan reports include findings, issues, coverage and the decision made from that evidence.

The command below checks whether a saved report reproduces the recorded decision under the supported decision policy:

    antios virus-scan-replay REPORT.json --json

The built-in benchmark runs inert controls with known expected outcomes:

    antios virus-scan-benchmark --json

It is a functional regression check, not a measurement of real-world malware detection rate.

## Signature updates

Use:

    antios signatures status --json
    antios signatures install PACKAGE

A rejected or unreadable update must not silently replace a verified catalog. AntiOS can fall back to a verified bundled catalog and report the degraded state.

The starter exact-hash set includes indicators derived from public NCSC and CISA/FBI malware reporting. It is intentionally limited; exact-hash coverage should not be confused with broad malware-family detection.

## Limitations

AntiOS is pre-release software. It does not currently provide certified Windows primary-antivirus registration, ELAM/PPL protection, a kernel minifilter for complete pre-execution blocking or complete boot-time malware coverage.

A clean result means only that the content successfully inspected by the active AntiOS checks did not produce a finding.
