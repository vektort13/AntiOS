# File recovery

AntiOS includes bounded file backup and recovery tools for selected files.

Saved content is checked for integrity before it is trusted, and recovery should write to an explicit safe destination rather than silently replacing unrelated files.

Recovery archives are treated as untrusted input: malformed paths, inconsistent metadata and integrity failures are rejected.

This feature is not a full Windows rollback system and does not guarantee that restored content is malware-free. Scan restored files when appropriate.
