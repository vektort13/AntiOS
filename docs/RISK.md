# Risk context

AntiOS combines scanner results and local context to decide what deserves attention.

Scanner detections carry more authority than weak contextual signals. Process behavior, persistence, memory metadata, driver posture and other sensor evidence can raise review priority or connect an incident, but do not independently prove malware.

The UI should preserve uncertainty when evidence is incomplete instead of presenting a precise-looking score as certainty.
