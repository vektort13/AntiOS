# Coexistence with other security products

AntiOS is designed to run alongside an existing security product instead of silently taking control of it.

## Windows

AntiOS does not intentionally disable Microsoft Defender, Kaspersky or Dr.Web, stop their services, add hidden exclusions or create fake Windows Security Center registration.

Where supported, AntiOS reads provider status and shows it as companion context. AntiOS scans still use the independent AntiOS Engine.

Resident Guard is optional. Running multiple resident scanners can increase disk I/O and CPU use, so users should enable overlapping resident protection deliberately.

## Legacy AntiOS installations

Older 2.x builds could contain a managed third-party scan-engine path. Current 3.x builds do not use it.

If the installer detects legacy components whose ownership cannot be safely established, it can refuse an in-place migration instead of deleting services or registrations by name. In that case, remove the old version with its own uninstaller and then install the current build cleanly.

AntiOS does not claim primary-antivirus certification and should not be used as a reason to disable an existing trusted real-time antivirus.
