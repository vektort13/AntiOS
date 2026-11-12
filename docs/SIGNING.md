# Signing and release trust

AntiOS supports signed distribution paths and integrity verification for release artifacts.

## Public guarantees

- release artifacts are expected to carry integrity metadata;
- production signing is preferred for executable distribution;
- the updater must not treat an unverifiable package as trusted merely because it came from a familiar location;
- Microsoft Store distribution follows the Store signing model.

## Internal design

Certificate pinning strategy, trust-store layout, exact verification order, CI identities, handoff mechanics, fallback rules and release-activation sequencing are intentionally omitted from public documentation.

Security reports about signing or update verification should be submitted privately through [../SECURITY.md](../SECURITY.md).
