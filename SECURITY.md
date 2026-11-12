# Security Policy

## Supported versions

AntiOS v2 is pre-release software. Security fixes are made on the latest v2 release line.

| Version | Supported |
| --- | --- |
| 2.0.0 alpha | Yes |
| Legacy v1 | No |

## Reporting a vulnerability

Please do **not** post exploit details, bypass steps, internal trust-boundary weaknesses or sensitive logs in a public issue.

Preferred route:

1. Use GitHub private vulnerability reporting / Security Advisory for this repository when available.
2. Include the affected version, OS version/build, reproduction conditions, expected behavior and actual behavior.
3. State whether administrator access, local code execution or special configuration is required.
4. Remove personal data, secrets, malware samples and unrelated machine identifiers before attaching diagnostics.

## Public security boundary

AntiOS aims to fail visibly when a scan, provider, update, recovery or protection operation cannot be verified. A failed or incomplete check must not silently become a clean verdict.

Public documentation intentionally does not describe exact internal trust sequences, service/task identities, IPC/state formats, quarantine transaction ordering, validation allowlists, update handoff internals, retry timing, native protocol fields or enforcement thresholds.

Those details belong in private engineering and security-review material.

## Disclosure

If a report demonstrates a security issue, remediation should be prepared before publishing technical details that would materially reduce the effort required to exploit affected users.
