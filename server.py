"""
BlindGuard — HTTP Server
Runs inside the TEE container. Exposes endpoints for:
- Submitting code for audit
- Retrieving audit reports
- Verifying attestations
- Checking agent identity/status
"""

import json
import hashlib
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

# Add parent dir to path

from analyzer import analyze
from crypto import (
    create_data_commitment,
    create_attestation,
    verify_attestation,
    compute_docker_image_hash,
    Attestation,
)
from state import record_audit, get_audit_history, get_stats
from upgrade import load_manifest, compute_manifest_hash


class BlindGuardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the BlindGuard agent."""

    def _send_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def do_OPTIONS(self):
        self._send_json({})

    def do_GET(self):
        if self.path == "/" or self.path == "/health":
            self._send_json({
                "agent": "blindguard",
                "status": "running",
                "description": "Private Security Agent — audits code without seeing or stealing it",
            })

        elif self.path == "/identity":
            manifest = load_manifest()
            self._send_json({
                "name": manifest["agent"]["name"],
                "version": manifest["agent"]["version"],
                "code_hash": compute_docker_image_hash(),
                "manifest_hash": compute_manifest_hash(manifest),
                "capabilities": manifest["capabilities"],
                "upgrade_policy": manifest["upgrade_policy"],
                "eigenai_model": manifest["eigencompute"]["eigenai_model"],
                "deterministic": manifest["eigencompute"]["deterministic"],
            })

        elif self.path == "/history":
            history = get_audit_history(limit=10)
            self._send_json({"audits": history})

        elif self.path == "/stats":
            self._send_json(get_stats())

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()

        if self.path == "/audit":
            self._handle_audit(body)
        elif self.path == "/verify":
            self._handle_verify(body)
        else:
            self._send_json({"error": "Not found"}, 404)

    def _handle_audit(self, body: str):
        """
        Handle code audit request.
        Input: JSON with "files" dict mapping filepath -> content
        Output: Report + attestation (code NEVER leaves this handler)
        """
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        code_files = data.get("files", {})
        if not code_files:
            self._send_json({"error": "No files provided. Send {\"files\": {\"path\": \"content\"}}"}, 400)
            return

        use_eigenai = data.get("use_eigenai", True)

        # Step 1: Create commitment to input (proves what was analyzed)
        commitment = create_data_commitment(code_files)

        # Step 2: Analyze (all inside TEE)
        report = analyze(code_files, use_eigenai=use_eigenai)

        # Step 3: Create attestation
        manifest = load_manifest()
        report_json = report.to_json()
        attestation = create_attestation(
            manifest_version=manifest["agent"]["version"],
            input_commitment=commitment.input_hash,
            output_content=report_json,
            eigenai_model=report.eigenai_model,
            deterministic_seed=report.deterministic_seed,
        )

        # Step 4: Record in state (only hashes, never code)
        record_audit(
            run_id=attestation.run_id,
            input_commitment=commitment.input_hash,
            output_hash=attestation.output_hash,
            findings_count=report.stats["total_findings"],
            severity_counts=report.stats["by_severity"],
            attestation_signature=attestation.tee_signature,
        )

        # Step 5: Return report + attestation (code stays inside TEE)
        self._send_json({
            "report": report.to_dict(),
            "attestation": attestation.to_dict(),
            "data_commitment": commitment.to_dict(),
            "verification_note": (
                "The 'data_commitment' proves which code was analyzed. "
                "The 'attestation' proves this exact agent produced this exact report. "
                "The source code NEVER leaves the TEE container."
            ),
        })

    def _handle_verify(self, body: str):
        """Verify a previously generated attestation."""
        try:
            data = json.loads(body)
            att = Attestation(**data["attestation"])
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            self._send_json({"error": f"Invalid attestation format: {e}"}, 400)
            return

        result = verify_attestation(att)
        result["verification"] = "PASS" if result["signature_valid"] else "FAIL"
        self._send_json(result)

    def log_message(self, format, *args):
        """Suppress default logging for cleaner output."""
        pass


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = HTTPServer(("0.0.0.0", port), BlindGuardHandler)
    print(f"╔══════════════════════════════════════════════════╗")
    print(f"║          BlindGuard — Private Security Agent     ║")
    print(f"║  Running inside TEE on port {port:<20} ║")
    print(f"║                                                  ║")
    print(f"║  Endpoints:                                      ║")
    print(f"║    GET  /            Health check                ║")
    print(f"║    GET  /identity    Agent identity & code hash  ║")
    print(f"║    GET  /history     Audit history               ║")
    print(f"║    GET  /stats       Agent statistics            ║")
    print(f"║    POST /audit       Submit code for analysis    ║")
    print(f"║    POST /verify      Verify an attestation       ║")
    print(f"╚══════════════════════════════════════════════════╝")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
