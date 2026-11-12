# Behavior monitoring

AntiOS may correlate local security events to provide additional context around suspicious activity.

## Public behavior

- behavioral context is advisory unless a separate trusted scanner confirms a threat;
- behavior-only signals do not silently delete files or terminate processes;
- the feature is bounded and designed to avoid unlimited event retention;
- incomplete collection is surfaced as reduced coverage;
- behavior context can be shown in local incident views.

## Limitations

Behavior correlation is not a complete EDR event stream and does not prove malicious intent by itself.

## Internal design

Public documentation intentionally omits collector APIs, polling intervals, rule names, scores, thresholds, correlation windows, ring sizes, suppression intervals and internal state mappings. Those parameters are security-sensitive implementation detail and may change without public notice.
