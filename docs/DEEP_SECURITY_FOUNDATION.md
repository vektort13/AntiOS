# Security sensors

AntiOS uses read-only or bounded sensors to add system context to ordinary file scanning. Sensor results enter the same evidence, risk and incident pipeline; they do not form a separate hidden verdict engine.

## Current Windows coverage

| Surface | Current status | Examples |
| --- | --- | --- |
| Process | Partial baseline | process identity, parent, image path |
| Persistence | Partial baseline | common autoruns, services, tasks, WMI and COM persistence |
| Process memory | Partial baseline | executable private regions and bounded header probes |
| Loaded drivers | Partial baseline | loaded-driver inventory, Authenticode, exact blocklist and hash checks |
| Boot / UEFI | Partial baseline | firmware type and Secure Boot posture |
| TPM / VBS / Code Integrity | Partial baseline | TPM state, VBS, HVCI and Secure Launch posture |
| DMA | Partial baseline | Device Guard DMA capability and requirement posture |
| Network | Planned | connection and process correlation |
| Browser | Planned | extension, policy and native-messaging inventory |
| GPU | Planned | adapter and driver telemetry exposed by documented APIs |
| Device firmware | Planned | firmware revisions exposed by supported device APIs |
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

## Scope

AntiOS does not claim arbitrary SMM, management-engine or security-processor, firmware-flash or VRAM inspection. Those surfaces should only be documented as supported after a specific, testable acquisition path exists.
