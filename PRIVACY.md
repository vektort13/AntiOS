# Privacy

AntiOS is designed to process security and diagnostic information locally by default.

## Data processed locally

Depending on the feature, AntiOS may read selected files and folders, file hashes, process and system metadata, protection-provider status, quarantine metadata, storage information, recovery archives and local diagnostic events.

Resident and security-sensor features may also inspect bounded process, driver, persistence and platform-security metadata.

## Network activity

AntiOS does not enable project analytics or automatic telemetry.

Network access can occur when you explicitly check/download updates, open project links or use a third-party security product that contacts its own vendor services.

## Reports

Reports and support exports are created locally. Review them before sharing: they can contain file paths, hashes, operating-system information and other machine-specific diagnostic context.

## Local state

Some features keep local state for quarantine, diagnostics, recovery, configuration and optional history. Removing that state can reduce or reset the related feature history.

AntiOS does not intentionally upload quarantined files, browsing history, passwords or raw process memory as part of normal operation.

For security reports, see [SECURITY.md](SECURITY.md).
