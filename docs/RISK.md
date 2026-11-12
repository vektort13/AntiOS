# Risk context

AntiOS can combine several local security signals to improve the context shown to the user.

## Public behavior

- scanner verdicts remain the primary basis for malware enforcement;
- contextual signals may raise attention without automatically deleting content;
- unrelated global events are not blindly assigned to every file;
- incomplete evidence remains visible as uncertainty;
- the UI may present a combined explanation for why an item deserves review.

## Internal design

Scoring formulas, weights, freshness windows, rule names, thresholds, feature ordering and enforcement cutoffs are intentionally not documented publicly. They are implementation details that could materially simplify tuning attacks against the product.
