# Windows third-party antivirus companion mode

AntiOS can run as a supplemental layer next to Kaspersky or Dr.Web on Windows.
It does not try to become the primary registered antivirus and it does not
modify the vendor product.

## Discovery

AntiOS reads the antivirus product list exposed by Windows Security Center
(root/SecurityCenter2) to detect registered Kaspersky/Dr.Web products.

For Kaspersky Endpoint Security for Windows, AntiOS may also use the documented
read-only command:

    avp.com STATUS File_Monitoring

File_Monitoring is Kaspersky's File Threat Protection profile. If the command is
unavailable, blocked by product policy, or emits an unrecognized localized
state, AntiOS reports real-time state as unconfirmed instead of guessing.

Dr.Web is detected through Windows Security Center registration. AntiOS does
not invoke a Dr.Web scanner or configuration tool automatically.

## Companion policy

AntiOS never disables Kaspersky or Dr.Web, changes their exclusions, starts or
stops their services, changes their policies, launches vendor scans
automatically, controls vendor quarantine, or claims primary-antivirus
registration.

AntiOS continues to provide its own ClamAV second-opinion scanning, Storage
Intelligence, diagnostics and explicitly enabled Guard.

When a supported vendor's real-time state is confirmed active, the UI treats
AntiOS as a companion layer. Guard remains explicit opt-in because stacking
resident scanners can increase disk IO and CPU load.

## Commands

    antios coexistence-status
    antios protection-status

Both JSON outputs include detected vendor companion information.
