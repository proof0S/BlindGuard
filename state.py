"""
BlindGuard — State Manager
Persisted state inside the TEE. Tracks audit history, version info,
and provides queryable history without exposing code.
"""

import json
import os
import time
from typing import Optional


STATE_DIR = os.environ.get("BLINDGUARD_STATE_DIR", "/tmp/blindguard-state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")


def _ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)


def load_state() -> dict:
    """Load persisted state from TEE-encrypted storage."""
    _ensure_state_dir()
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {
        "version": "0.1.0",
        "created_at": time.time(),
        "audit_count": 0,
        "audits": [],
    }


def save_state(state: dict):
    """Persist state to TEE-encrypted storage."""
    _ensure_state_dir()
    state["updated_at"] = time.time()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def record_audit(
    run_id: str,
    input_commitment: str,
    output_hash: str,
    findings_count: int,
    severity_counts: dict,
    attestation_signature: str,
):
    """
    Record an audit run in persisted state.
    Note: only commitments and hashes are stored, NEVER the actual code.
    """
    state = load_state()
    state["audit_count"] += 1
    state["audits"].append({
        "run_id": run_id,
        "timestamp": time.time(),
        "input_commitment": input_commitment,
        "output_hash": output_hash,
        "findings_count": findings_count,
        "severity_counts": severity_counts,
        "attestation_signature": attestation_signature,
    })
    # Keep last 100 audits in state
    if len(state["audits"]) > 100:
        state["audits"] = state["audits"][-100:]
    save_state(state)


def get_audit_history(limit: int = 10) -> list[dict]:
    """Get recent audit history (public metadata only)."""
    state = load_state()
    return state["audits"][-limit:]


def get_stats() -> dict:
    """Get aggregate agent stats."""
    state = load_state()
    return {
        "version": state["version"],
        "total_audits": state["audit_count"],
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
    }
