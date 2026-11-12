# AntiOS Linux companion

Linux support is a supplemental companion mode.

The portable x86_64 build targets glibc 2.39 or newer (Ubuntu 24.04 LTS
or a compatible distribution). The desktop interface requires an X11 display
or XWayland. Older glibc versions and musl-based distributions are not supported
by the portable binaries; the CLI can also be installed from the Python package.

## Public scope

- read-only system/security diagnostics;
- on-demand AntiOS scanning where supported;
- Storage Cleanup and Storage Intelligence;
- coexistence awareness for supported Kaspersky and Dr.Web products;
- optional desktop UI;
- optional AntiOS resident protection when explicitly enabled.

AntiOS does not take ownership of third-party antivirus policy, disable vendor protection, add exclusions or automatically launch vendor remediation.

## Coexistence

AntiOS uses supported, read-only vendor interfaces to determine whether compatible products are present and healthy enough for coexistence reporting.

Exact executable locations, command invocations, provider-discovery rules, local daemon endpoints and service-management assumptions are intentionally omitted from public documentation.

Distribution-specific installation and service configuration should follow the vendor or distribution documentation.

## Security boundary

Linux companion support is additive: the existing vendor product keeps its real-time policy and AntiOS supplies independent local analysis around it.
