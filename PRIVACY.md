# AntiOS Privacy

AntiOS is designed to process security and diagnostic information locally by default.

## Data AntiOS may read

Depending on the feature, AntiOS may inspect system-health information, selected files and folders, antivirus/provider status, local configuration, quarantine metadata, storage-cleanup candidates and recovery data.

## Network activity

AntiOS does not include automatic analytics or project telemetry. Network access may occur when the user explicitly opens external links, requests updates, or uses a security provider whose own product may contact its vendor services.

AntiOS does not silently change the privacy policy of Microsoft Defender, Kaspersky, Dr.Web, ClamAV infrastructure or other third-party providers.

## Reports and support data

Exports are created only when requested by the user. Review them before sharing because they may contain local paths, hashes, system information or other diagnostic context.

## Local security data

Quarantine, diagnostics, storage history and recovery features keep local state necessary for their operation. Public documentation intentionally does not publish exact storage paths, schemas, temporary-job layouts, retention counters, account-boundary handoffs or repair-process communication details.

The product should expose user-facing controls for viewing, clearing or disabling optional history where applicable.

## Security-sensitive privacy details

Implementation-specific redaction rules, local state layouts and privileged handoff mechanics are maintained in private engineering documentation. This keeps the public privacy policy focused on **what data is processed and where it may leave the machine**, without publishing an operational map of the protection stack.

For security reports, see [SECURITY.md](SECURITY.md).
