# Code protection

AntiOS uses normal software-hardening practices to raise the cost of tampering and accidental disclosure.

## Public scope

- hardened build options may be used for Windows distribution;
- release artifacts may include integrity/signing metadata;
- sensitive commercial or defensive logic should not depend on public documentation for secrecy;
- code hardening is not described as encryption or an absolute anti-reversing guarantee.

Exact compiler flags, packaging layout, protected-module boundaries, anti-tamper checks and proprietary interface design are intentionally omitted from public documentation.
