"""Conservative parsing of vendor-reported component states."""
from __future__ import annotations

import re


def realtime_state(value: str) -> bool | None:
    state = re.sub(r"^(?:state|status)\s*[:=]\s*", "", value.strip(), flags=re.I)
    state = " ".join(state.casefold().rstrip(".").split())
    if state in {"running", "started", "resumed", "active", "enabled"}:
        return True
    if state in {
        "stopped", "paused", "snoozed", "suspended", "inactive", "disabled",
        "not running", "not started", "not active", "not enabled",
    }:
        return False
    # Transitional, contradictory and unrecognized states stay unconfirmed.
    return None


def consistent_state(states: list[bool | None]) -> bool | None:
    if states and all(state is states[0] for state in states):
        return states[0]
    return None
