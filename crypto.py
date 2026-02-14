"""
BlindGuard — Cryptographic utilities
Handles code hashing, data commitments, attestation generation, and verification.
"""

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class DataCommitment:
    """Commitment to input data without revealing it."""
    input_hash: str
    algorithm: str
    timestamp: float
    nonce: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Attestation:
    """TEE attestation for a single audit run."""
    agent_code_hash: str
    manifest_version: str
    input_commitment: str
    output_hash: str
    eigenai_model: str
    deterministic_seed: Optional[int]
    timestamp: float
    tee_signature: str  # In real TEE, this comes from hardware
    run_id: str

    def to_dict(self):
        return asdict(self)


def compute_file_hash(content: str, algorithm: str = "sha256") -> str:
    """Compute hash of file content."""
    h = hashlib.new(algorithm)
    h.update(content.encode("utf-8"))
    return h.hexdigest()


def compute_code_hash(code_files: dict[str, str], algorithm: str = "sha256") -> str:
    """
    Compute a deterministic hash over multiple code files.
    Files are sorted by path to ensure determinism.
    """
    h = hashlib.new(algorithm)
    for path in sorted(code_files.keys()):
        h.update(f"FILE:{path}\n".encode("utf-8"))
        h.update(code_files[path].encode("utf-8"))
        h.update(b"\n---END---\n")
    return h.hexdigest()


def create_data_commitment(code_files: dict[str, str]) -> DataCommitment:
    """
    Create a commitment to the input code.
    This proves WHAT was analyzed without revealing the code itself.
    """
    nonce = os.urandom(16).hex()
    content_hash = compute_code_hash(code_files)
    # Commitment = H(content_hash || nonce)
    commitment_input = f"{content_hash}:{nonce}"
    commitment = hashlib.sha256(commitment_input.encode()).hexdigest()
    return DataCommitment(
        input_hash=commitment,
        algorithm="sha256",
        timestamp=time.time(),
        nonce=nonce,
    )


def compute_docker_image_hash(dockerfile_path: str = "Dockerfile") -> str:
    """
    Compute hash of the agent's Docker build context.
    In production, EigenCompute TEE provides this via attestation.
    """
    agent_dir = os.path.dirname(os.path.abspath(__file__))
    relevant_files = {}
    for root, _dirs, files in os.walk(agent_dir):
        # Skip non-essential dirs
        skip = any(s in root for s in ["__pycache__", ".git", "node_modules", "tests"])
        if skip:
            continue
        for f in files:
            if f.endswith((".py", ".json", ".txt", ".toml", "Dockerfile")):
                fpath = os.path.join(root, f)
                relpath = os.path.relpath(fpath, agent_dir)
                try:
                    with open(fpath, "r") as fh:
                        relevant_files[relpath] = fh.read()
                except (UnicodeDecodeError, PermissionError):
                    pass
    return compute_code_hash(relevant_files)


def generate_tee_signature(payload: str) -> str:
    """
    Simulate TEE hardware signature.
    In production on EigenCompute, this is replaced by real TEE attestation
    using the enclave's derived signing key.
    """
    # Simulated TEE key — in production, this is hardware-derived and never extractable
    tee_key = os.environ.get("TEE_SIGNING_KEY", "blindguard-dev-tee-key-DO-NOT-USE-IN-PROD")
    sig = hmac.new(tee_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return sig


def create_attestation(
    manifest_version: str,
    input_commitment: str,
    output_content: str,
    eigenai_model: str,
    deterministic_seed: Optional[int] = None,
) -> Attestation:
    """
    Create a full attestation for an audit run.
    Binds: agent code + input commitment + output hash + model used.
    """
    run_id = os.urandom(8).hex()
    agent_hash = compute_docker_image_hash()
    output_hash = hashlib.sha256(output_content.encode()).hexdigest()
    timestamp = time.time()

    # Payload that gets signed
    payload = json.dumps({
        "agent_code_hash": agent_hash,
        "manifest_version": manifest_version,
        "input_commitment": input_commitment,
        "output_hash": output_hash,
        "eigenai_model": eigenai_model,
        "deterministic_seed": deterministic_seed,
        "timestamp": timestamp,
        "run_id": run_id,
    }, sort_keys=True)

    tee_sig = generate_tee_signature(payload)

    return Attestation(
        agent_code_hash=agent_hash,
        manifest_version=manifest_version,
        input_commitment=input_commitment,
        output_hash=output_hash,
        eigenai_model=eigenai_model,
        deterministic_seed=deterministic_seed,
        timestamp=timestamp,
        tee_signature=tee_sig,
        run_id=run_id,
    )


def verify_attestation(attestation: Attestation) -> dict:
    """
    Verify an attestation's integrity.
    Returns verification results for each check.
    """
    # Reconstruct payload
    payload = json.dumps({
        "agent_code_hash": attestation.agent_code_hash,
        "manifest_version": attestation.manifest_version,
        "input_commitment": attestation.input_commitment,
        "output_hash": attestation.output_hash,
        "eigenai_model": attestation.eigenai_model,
        "deterministic_seed": attestation.deterministic_seed,
        "timestamp": attestation.timestamp,
        "run_id": attestation.run_id,
    }, sort_keys=True)

    expected_sig = generate_tee_signature(payload)

    return {
        "signature_valid": expected_sig == attestation.tee_signature,
        "agent_code_hash": attestation.agent_code_hash,
        "timestamp": attestation.timestamp,
        "run_id": attestation.run_id,
    }
