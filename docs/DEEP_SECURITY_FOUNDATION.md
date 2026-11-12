# Deep-security sensor foundation

AntiOS treats deep inspection as a set of independent collectors feeding the
same shared `Evidence` / `EvidenceBus` pipeline used by detection, risk and
incident correlation. The sensor layer does not create a second verdict engine.

## Planned surfaces

| Surface | Examples | Default acquisition | Minimum privilege |
| --- | --- | --- | --- |
| Process | module/image integrity, process ancestry | snapshot | user |
| RAM | executable private memory, image mismatch | snapshot | admin |
| Persistence | services, scheduled tasks, WMI, COM, autoruns | query | user |
| Driver | loaded drivers, signatures, vulnerable-driver intelligence | query | admin |
| Kernel | kernel integrity evidence | snapshot | system |
| Boot | boot configuration and measured-boot evidence | attestation | admin |
| UEFI | Secure Boot and available UEFI integrity evidence | attestation | admin |
| Platform firmware | firmware/security-processor posture exposed by platform APIs | attestation | admin |
| Device firmware | storage/NIC/GPU/USB firmware inventory and change evidence | query | admin |
| GPU | process/device telemetry and exposed integrity evidence | query | user |
| Network | connection/process correlation | event stream | user |
| Browser | extensions, enterprise policies and risky persistence | query | user |
| DMA | platform DMA protection posture | attestation | admin |
| Virtualization | hypervisor/VBS/security posture | query | admin |
| Attestation | TPM/measured boot and platform claims | attestation | admin |

This table describes the target surface map. On Windows, process/persistence,
bounded process-memory inspection, loaded-driver trust and core boot/platform
posture are now connected to this architecture. The remaining rows are still
planned coverage.

## Contracts

Every collector has a versioned `SensorDescriptor` and returns a
`SensorReport`. Reports distinguish complete, partial, unavailable,
unsupported, permission-denied, error and not-implemented states. Any state
other than complete requires an explicit reason.

`ScanBudget` provides hard item, byte, time and depth limits. Privileged
collection is disabled unless the caller explicitly enables it. Collector
failures are isolated and surfaced as sanitized coverage errors.

Collectors emit the project's shared `Evidence` objects. The helper
`sensor_evidence()` stamps surface, sensor version, rule ID and scan run ID so
later signature/risk/incident stages can correlate observations without losing
provenance. A `SensorRegistry` can publish successful reports directly into
the existing bounded `EvidenceBus`.

Generic sensor evidence never becomes an independent enforcement path. Current
AntiOS policy continues to reserve automatic enforcement for confirmed scanner
threats; behavioral, firmware, GPU, memory and other sensor signals remain
review/correlation input unless a future policy is explicitly designed and
validated.

## Implementation status and order

1. **Implemented baseline:** Process inventory + persistence inventory.
   - running process PID/PPID, stable creation identity and image path;
   - Run/RunOnce and Explorer policy Run keys;
   - Winlogon Shell/Userinit, AppInit_DLLs and BootExecute;
   - targeted IFEO Debugger and SilentProcessExit MonitorProcess hooks;
   - auto/boot/system services and drivers, plus Startup folders;
   - scheduled-task action inventory;
   - WMI command/script consumers through a bounded read-only CIM query;
   - per-user COM server overrides;
   - user-writable/interpreter-based entries are review evidence, never an
     automatic remediation decision;
   - persistence command arguments are used only transiently for classification
     and are not persisted in Evidence or Guard journal records.
2. **Implemented baseline:** Process-memory inspection.
   - bounded VirtualQueryEx enumeration;
   - private executable region detection;
   - writable+executable metadata;
   - small read-only header probes only for private executable regions;
   - embedded PE-header classification;
   - inaccessible/protected processes remain explicit partial coverage;
   - raw memory bytes are never persisted in evidence or logs.
3. **Implemented baseline:** Driver trust and vulnerable-driver intelligence.
   - loaded kernel images from EnumDeviceDrivers with a running-driver CIM
     supplement/fallback;
   - stable flat SHA-256 for the authenticated AntiOS malware catalog;
   - Authenticode trust status and signer metadata;
   - Microsoft-documented Authenticode PE-image SHA-256 for exact full-hash
     comparison against the local Microsoft Recommended Driver Blocklist XML;
   - Windows CI cross-checks the AntiOS PE-image hash directly against
     SignTool's `Hash of file (sha256)` output;
   - VulnerableDriverBlocklistEnable is recorded as posture only because its
     absence does not prove the effective blocklist is disabled;
   - exact Microsoft full-hash matches, known-malware hashes and untrusted
     user-writable drivers are review evidence only;
   - Microsoft page-hash/certificate/publisher deny rules and manually mapped
     kernel code remain explicit coverage gaps.
4. **Implemented baseline:** Boot / Secure Boot / TPM / DMA posture.
   - BIOS-versus-UEFI firmware type and Secure Boot state;
   - TPM present/ready/enabled/activated state and vendor/version metadata;
   - VBS status, HVCI/Memory Integrity, Secure Launch and SMM firmware
     measurement service state through Win32_DeviceGuard;
   - Code Integrity/App Control policy presence and enforcement status;
   - Device Guard DMA capability/requirement posture;
   - PCR values and measured-boot event-log validation are not yet performed;
   - UEFI PK/KEK/DB/DBX contents and SPI flash are not read or authenticated.
5. Browser and network correlation.
6. GPU/device-firmware inventory and telemetry.
7. Platform-firmware and virtualization attestation where supported.

Deep firmware, SMM, management-engine/security-processor and arbitrary VRAM
inspection must not be advertised as supported unless AntiOS has a documented,
testable acquisition path for the specific platform.


## Resident Guard integration

On Windows the Guard schedules process+RAM inspection, persistence inventory,
and a slower driver/platform posture cycle through one background deep-security
worker. The worker is bounded and does not block the Guard heartbeat, directory
notifications or ordinary file scanning.
Raw sensor evidence is published to the shared EvidenceBus, evaluated by the
multi-sensor signature engine and then attached to IncidentGraph on the Guard
thread.

The implementation remains detect/review-only. Memory metadata, persistence
heuristics, driver trust/BYOVD evidence, platform-posture findings and
multi-sensor signatures cannot authorize quarantine, driver unloading, process
termination or firmware/security-setting changes.
