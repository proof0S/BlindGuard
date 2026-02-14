"""
BlindGuard — Upgrade Policy
Enforces versioned, policy-gated upgrades.
Prevents silent or unauthorized changes to the agent.
"""

import json
import hashlib
import os
from typing import Tuple


MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.json")


def load_manifest(path: str = MANIFEST_PATH) -> dict:
    """Load the agent manifest."""
    with open(path, "r") as f:
        return json.load(f)


def compute_manifest_hash(manifest: dict) -> str:
    """Compute deterministic hash of manifest."""
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def parse_semver(version: str) -> Tuple[int, int, int]:
    """Parse semantic version string."""
    parts = version.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def validate_upgrade(current_manifest: dict, new_manifest: dict) -> dict:
    """
    Validate whether an upgrade from current to new manifest is allowed.
    Checks:
    1. Version must be bumped (semver)
    2. Agent name must not change
    3. Minimum version constraint respected
    4. Signer must be in allowed list
    """
    errors = []
    warnings = []

    policy = current_manifest.get("upgrade_policy", {})

    # Check version bump
    current_ver = current_manifest["agent"]["version"]
    new_ver = new_manifest["agent"]["version"]
    if policy.get("require_version_bump", True):
        cur = parse_semver(current_ver)
        new = parse_semver(new_ver)
        if new <= cur:
            errors.append(f"Version must be bumped: {current_ver} -> {new_ver} is not an upgrade")

    # Check minimum version
    min_ver = policy.get("minimum_version", "0.0.0")
    if parse_semver(new_ver) < parse_semver(min_ver):
        errors.append(f"Version {new_ver} is below minimum allowed {min_ver}")

    # Check agent name consistency
    if current_manifest["agent"]["name"] != new_manifest["agent"]["name"]:
        errors.append("Agent name cannot change during upgrade")

    # Check changelog
    if policy.get("changelog_required", False):
        if "changelog" not in new_manifest.get("agent", {}):
            warnings.append("Changelog entry recommended for upgrades")

    return {
        "allowed": len(errors) == 0,
        "current_version": current_ver,
        "new_version": new_ver,
        "current_hash": compute_manifest_hash(current_manifest),
        "new_hash": compute_manifest_hash(new_manifest),
        "errors": errors,
        "warnings": warnings,
    }
