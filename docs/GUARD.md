# Resident Guard

Resident Guard is AntiOS's optional background file-monitoring layer.

It watches configured locations, submits relevant file activity to the AntiOS Engine and reports detections, errors and incomplete coverage.

Guard uses the AntiOS Engine directly; current builds do not install or depend on ClamAV or an AntiOS AMSI provider.

## Limits

Guard is post-write monitoring, not a Windows kernel minifilter. It does not claim complete pre-execution blocking.

Confirmed scanner evidence can be handled according to the configured quarantine policy. Behavior-only, sensor-only or posture-only findings remain review evidence.

If Guard cannot maintain normal monitoring, it should expose a degraded or attention state instead of silently presenting full protection.
