# File recovery

AntiOS includes bounded file backup and integrity-recovery features.

## Public behavior

- users explicitly select content to protect;
- integrity is verified before saved content is trusted;
- recovery writes into a safe destination rather than silently overwriting unrelated files;
- malformed or unsafe recovery data is rejected;
- recovery is not a full Windows rollback and not a malware-clean guarantee.

## Internal design

Archive structure, manifest fields, trust ordering, temporary-file strategy, path-validation implementation and repair/rollback internals are intentionally omitted from public documentation.
