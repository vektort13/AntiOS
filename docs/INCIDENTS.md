# Incident correlation

AntiOS can group related local security evidence into an incident view.

## Public behavior

- incident views connect relevant evidence already collected by AntiOS;
- they do not invent malware verdicts;
- unrelated background activity should not automatically become an incident;
- incident data is bounded and local;
- incomplete evidence remains distinguishable from confirmed findings.

Graph-building rules, node/edge schemas, correlation windows, retention limits and evidence-selection thresholds are intentionally omitted from public documentation.
