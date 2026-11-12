# Contributing to AntiOS v2

Thanks for helping improve AntiOS.

## Development setup

Requirements:

- Python 3.11 or newer
- Windows for live Registry/system integration tests
- Linux or Windows for the unit test suite

Setup:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip pytest
python -m pip install -e .
python -m pytest
```

## Design rules

Changes to v2 should preserve these boundaries:

1. Dry-run remains the default for system changes.
2. Every real write must be reversible where practical.
3. Registry writes require an explicit allowlist entry.
4. Backup input is untrusted and must never become an arbitrary Registry-write primitive.
5. Read-only inventory and write-capable operations stay clearly separated.
6. Logs must not contain scanned fingerprint values, generated identities, secrets, or backup contents.
7. Do not add anti-cheat, ban, licensing, hardware-serial, storage-serial, network-adapter identity bypasses, or similar evasion functionality.

## Tests

Every behavior change should include tests. The CI matrix currently covers:

- Windows latest: Python 3.11, 3.12, 3.13
- Ubuntu latest: Python 3.11, 3.12, 3.13
- Windows PyInstaller portable build and executable smoke tests

## Pull requests

Keep pull requests focused. Describe:

- what changed;
- why;
- safety/reversibility implications;
- test coverage;
- whether a Windows restart or Administrator privileges are involved.


## Licensing contributions

The current AntiOS v2 source tree is licensed under the Apache License 2.0.

Unless you explicitly state otherwise when submitting a contribution, contributions intentionally submitted for inclusion in AntiOS v2 are made under the Apache License 2.0, consistent with Section 5 of the license.

Do not submit code you do not have the right to license. If a contribution incorporates third-party material, clearly identify its origin and license.


## Public security documentation

Keep public GitHub text focused on user-visible behavior, compatibility, limitations and test outcomes.

Do **not** publish security-sensitive operational architecture in public pull requests, issues, release notes, READMEs or discussions. This includes exact:

- trust-boundary or privilege-handoff sequencing;
- internal service, task, process, state-file or IPC identities;
- watchdog, heartbeat, lock and recovery mechanics;
- provider-validation and peer-verification order;
- retry, timeout, queue, cache, correlation or detection thresholds;
- native protocol fields and enforcement decision flow;
- updater activation, repair, rollback or postcondition sequencing;
- unfinished bypasses, exploit proofs or attacker-oriented architecture diagrams.

If a change requires discussion of those details, use a private engineering channel. Security vulnerabilities, bypasses and exploit details must be reported through the private route described in [SECURITY.md](SECURITY.md), not a public issue or pull request.

Public descriptions should explain **what changed for users and what safety guarantee is preserved**, not provide a step-by-step map of the protection implementation.
