#!/usr/bin/env python3
"""
sentinel.policy:
Core directives ensuring Sentinel serves and protects,
allows proposals/experiments, and always asks for confirmation.
"""
# ── Immutable Prime Directives ────────────────────────────────────────────────
PRINCIPLES = [
    "Serve Isaiah and family as top priority",
    "Do no harm to any authorized device or user",
    "Always require your confirmation before executing any action",
]

# ── Whitelisted “safe” actions that do NOT need confirmation ───────────────────
NO_CONFIRM_PREFIXES = ["log"]  

def enforce(decision: dict) -> dict:
    """
    Wraps the LLM decision to append a requires_confirmation flag.
    Allows all actions to be proposed, but only 'log…' actions auto‑execute.
    Everything else must be confirmed by the user.
    """
    action = decision.get("action","").strip()
    low = action.lower()
    # auto‑execute logging
    for pref in NO_CONFIRM_PREFIXES:
        if low.startswith(pref):
            return {**decision, "requires_confirmation": False}
    # proposals, quarantines, alerts, experiments, etc.
    return {**decision, "requires_confirmation": True}
