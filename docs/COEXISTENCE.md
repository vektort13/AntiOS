# Security-product coexistence

AntiOS supports a layered companion model with supported security products.

## Public contract

- AntiOS does not disable, stop or reconfigure Microsoft Defender.
- AntiOS does not add Defender exclusions.
- AntiOS does not write fake Windows Security Center antivirus registration.
- AntiOS does not disable, stop or reconfigure Kaspersky or Dr.Web, and does not add vendor exclusions.
- AntiOS does not rely on process hiding or rootkit techniques.
- A failure in another provider does not automatically become a clean AntiOS verdict.
- Temporary conflicts and unavailable resources are surfaced as degraded or incomplete coverage.

AntiOS can also provide supplemental scanning alongside selected Kaspersky and Dr.Web products where supported.

## AntiOS Engine protection boundary

AntiOS Engine is an independent local file-inspection engine with SHA-256 rules,
bounded archive inspection and advisory executable/script indicators.
Resident Guard monitors files after writes and is **not** a Windows pre-execution
minifilter. No ClamAV daemon, third-party detection API or AMSI provider is
required for AntiOS scans. It may miss unknown threats.

AntiOS does not claim primary antivirus certification or replace the installed
real-time protection product. Upgrading from an older managed ClamAV/AMSI build
does not authorize deleting any old service or provider without verifying its
ownership and installer history. The coexistence goal is to add an independent
layer without weakening existing protection.

## Upgrading legacy AntiOS installations

The native-only setup refuses an in-place upgrade (exit code **30**) when
older AntiOS engine scripts, binaries, or a recorded managed ClamAV service
binding remain in the installation. The preflight runs **before** extracting,
replacing files or stopping Guard.

To migrate, preserve any needed user configuration and quarantine data, use the
**original installed version's own uninstaller**, and confirm that its managed
services and AMSI registration have been retired. Then perform a clean AntiOS
Engine installation. If leftovers remain, stop and investigate their ownership;
never delete a service, driver, registry entry or another antivirus product
merely because it has a familiar name. Current AntiOS neither runs retired
engine uninstall scripts nor claims a legacy service provides protection.

This cautious upgrade gate does not yet substitute for signed installer upgrade
and rollback tests in a disposable Windows virtual machine.

For unattended installations, `/NOGUARD=1` skips only Resident Guard
task configuration; the local AntiOS Engine remains part of the application.
The old `/NOENGINE` option is intentionally rejected rather than silently
changing its meaning.
