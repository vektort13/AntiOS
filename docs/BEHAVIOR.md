# Behavior context

AntiOS can use local activity as additional context around a suspicious file or process.

Behavior signals are advisory. They can raise review priority or help connect related evidence, but they do not independently authorize file deletion, process termination or quarantine.

Collection is bounded, and missing events reduce coverage instead of being treated as proof that nothing happened.

This feature is not a complete EDR event stream and should not be used as one.
