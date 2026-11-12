# Windows security-product companion mode

AntiOS can run alongside Microsoft Defender and selected Kaspersky or Dr.Web installations.

## Discovery

AntiOS uses read-only Windows and provider information where supported to identify installed security products and report their visible status.

Kaspersky Endpoint Security can expose additional read-only status through its documented command-line interface when available. Dr.Web companion status is based on the supported Windows registration and status information available to AntiOS.

If a provider cannot be queried reliably, AntiOS reports the state as unconfirmed instead of guessing.

## Policy

AntiOS does not disable supported third-party products, change their exclusions, start or stop their services, control their quarantine or impersonate Windows primary-antivirus registration.

AntiOS scanning uses the independent AntiOS Engine. Current builds do not use ClamAV as a second-opinion backend.

Resident Guard remains opt-in because stacking resident scanners can increase system load.

Useful commands:

    antios coexistence-status
    antios protection-status
