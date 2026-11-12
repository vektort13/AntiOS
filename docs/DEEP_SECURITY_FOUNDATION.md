# Security sensors

AntiOS uses read-only or bounded sensors to add system context to ordinary file scanning. Sensor results enter the same evidence, risk and incident pipeline; they do not form a separate hidden verdict engine.

## Current Windows coverage

| Surface | Current status | Examples |
| --- | --- | --- |
| Process | Partial baseline | process identity, parent, path, token integrity, loader module inventory and on-disk image Authenticode |
| Persistence | Partial baseline | common autoruns, services, tasks, WMI and COM persistence |
| Process memory | Partial baseline | executable private regions and bounded header probes |
| Loaded drivers | Partial baseline | loaded-driver inventory, Authenticode, exact blocklist and hash checks |
| Boot / UEFI | Partial baseline | firmware type and Secure Boot posture |
| TPM / VBS / Code Integrity | Partial baseline | TPM state, VBS, HVCI and Secure Launch posture |
| DMA | Partial baseline | Device Guard DMA capability and requirement posture |
| Network | Partial baseline | IPv4/IPv6 TCP snapshots attributed to stable process instances |
| Browser | Partial baseline | Chrome and Edge extension manifests, force-install policies and native messaging registrations |
| GPU | Partial baseline | display adapters and reported driver versions |
| Device firmware | Partial baseline | firmware revisions reported for physical disks |
| Kernel integrity | Planned | documented integrity evidence where available |
| Platform firmware | Planned | documented platform attestation where available |
| Virtualization | Planned | hypervisor and security posture beyond current VBS signals |

Partial is intentional. For example, the current memory sensor does not dump arbitrary process memory, the driver sensor does not detect every manually mapped kernel image, and the UEFI sensor does not authenticate SPI flash or every firmware database.

## Evidence rules

Sensors report explicit coverage states: complete, partial, unavailable, unsupported, permission denied, error or not implemented.

A sensor failure is not converted into a clean result.

Security-sensor evidence is review and correlation input. Current policy reserves automatic quarantine for sufficiently trusted scanner evidence; a weak heuristic or posture gap cannot quarantine a file by itself.

## Resident operation

Resident Guard runs supported sensors in a bounded background worker so security collection does not block ordinary file monitoring and scanning.

Raw process memory is not persisted as normal evidence. Persistence command arguments are used only as needed for local classification and are not stored as ordinary evidence records.

Process reports distinguish a full loader module list from a bounded sample. Image signing status describes the on-disk file. Mapped-image verification, loaded-module integrity, machine-wide COM registration and complete WMI filter/binding coverage remain open.

## Inspect local sensor coverage

Run `antios sensors` for coverage and observation counts, or `antios sensors --surface network --json` and `antios sensors --surface browser --json` for details. The command runs on demand without changing browser, firewall or Guard settings.

- Network observations contain per-process TCP counts. Endpoint addresses, ports and traffic content are omitted. Short-lived connections, UDP, connection direction and unmatched process owners are outside this snapshot's coverage.
- Browser observations include extension IDs and selected manifest permissions from standard Chrome and Edge profiles, plus force-install entries and native messaging registrations. Browser history, cookies, profile names, policy URLs and registered manifest paths are omitted. Activation, custom profiles and other browsers remain outside coverage.
- Use `--surface gpu` or `--surface device_firmware` for display and disk metadata. These reports omit hardware serial numbers and cannot establish firmware integrity, GPU load or VRAM contents.
- Guard can correlate an established public TCP peer with executable private memory containing a PE header in the same process instance. The correlation adds review evidence.

## Scope

AntiOS does not claim arbitrary SMM, management-engine or security-processor, firmware-flash or VRAM inspection. Those surfaces should only be documented as supported after a specific, testable acquisition path exists.
