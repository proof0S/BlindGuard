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
from github_app import (
    handle_push_event,
    handle_release_event,
    handle_installation_event,
    verify_webhook_signature,
    get_installation_token,
)


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

    def _send_html(self, html: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_OPTIONS(self):
        self._send_json({})

    def do_GET(self):
        if self.path == "/app" or self.path == "/app/":
            # Serve the landing page from TEE
            html_path = os.path.join(os.path.dirname(__file__), "index.html")
            if os.path.exists(html_path):
                with open(html_path, "r") as f:
                    self._send_html(f.read())
            else:
                self._send_html("<h1>BlindGuard</h1><p>index.html not found in TEE</p>", 404)

        elif self.path == "/" or self.path == "/health":
            self._send_json({
                "agent": "blindguard",
                "status": "running",
                "description": "Private Security Agent, audits code without seeing or stealing it",
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
        body = self.rfile.read(content_length)

        if self.path == "/audit":
            self._handle_audit(body.decode())
        elif self.path == "/audit-repo":
            self._handle_audit_repo(body.decode())
        elif self.path == "/verify":
            self._handle_verify(body.decode())
        elif self.path == "/webhook":
            self._handle_webhook(body)
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

        result = self._run_audit(code_files)
        self._send_json(result)

    def _handle_audit_repo(self, body: str):
        """
        Audit a public GitHub repo by URL.
        Input: JSON with "repo_url" (e.g. "https://github.com/user/repo")
        """
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        repo_url = data.get("repo_url", "").strip().rstrip("/")
        if not repo_url:
            self._send_json({"error": "No repo_url provided"}, 400)
            return

        # Parse owner/repo from URL
        # Supports: https://github.com/owner/repo or owner/repo
        import re
        match = re.match(r"(?:https?://github\.com/)?([^/]+)/([^/]+)", repo_url)
        if not match:
            self._send_json({"error": "Invalid GitHub repo URL"}, 400)
            return

        owner, repo = match.group(1), match.group(2)
        branch = data.get("branch", "main")

        print(f"[Audit Repo] Fetching {owner}/{repo} @ {branch}")

        import urllib.request
        import urllib.error
        import base64

        github_token = os.environ.get("GITHUB_TOKEN", "")

        try:
            # Get tree
            tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
            req = urllib.request.Request(tree_url)
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("User-Agent", "BlindGuard-TEE")
            if github_token:
                req.add_header("Authorization", f"token {github_token}")
            with urllib.request.urlopen(req, timeout=15) as resp:
                tree_data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self._send_json({"error": f"Repository {owner}/{repo} not found or is private"}, 404)
            else:
                self._send_json({"error": f"GitHub API error: {e.code}"}, 500)
            return
        except Exception as e:
            self._send_json({"error": f"Could not reach GitHub: {str(e)}"}, 500)
            return

        if "tree" not in tree_data:
            self._send_json({"error": "Could not read repo tree"}, 500)
            return

        # Collect source code files
        SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".jsx", ".tsx", ".sol", ".rs", ".go", ".rb", ".php", ".java", ".cs", ".c", ".cpp", ".h")
        files = {}
        for item in tree_data["tree"]:
            if item["type"] != "blob":
                continue
            path = item["path"]
            if not any(path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                continue
            if any(skip in path for skip in ["venv/", "node_modules/", ".git/", "__pycache__/", "test_", "tests/", "setup.py", "dist/", "build/", ".min.", "vendor/", "migrations/"]):
                continue

            try:
                blob_url = f"https://api.github.com/repos/{owner}/{repo}/git/blobs/{item['sha']}"
                req = urllib.request.Request(blob_url)
                req.add_header("Accept", "application/vnd.github+json")
                req.add_header("User-Agent", "BlindGuard-TEE")
                if github_token:
                    req.add_header("Authorization", f"token {github_token}")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    blob_data = json.loads(resp.read().decode())
                if "content" in blob_data:
                    content = base64.b64decode(blob_data["content"]).decode("utf-8", errors="replace")
                    files[path] = content
            except Exception:
                pass

            # Limit to 20 files max
            if len(files) >= 20:
                break

        if not files:
            self._send_json({"error": f"No source code files found in {owner}/{repo}"}, 404)
            return

        print(f"[Audit Repo] Analyzing {len(files)} file(s) from {owner}/{repo}")

        result = self._run_audit(files)
        result["repo"] = f"{owner}/{repo}"
        result["branch"] = branch
        result["files_fetched"] = len(files)
        self._send_json(result)

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

    def _handle_webhook(self, body: bytes):
        """Handle GitHub App webhook events."""
        # Verify signature if webhook secret is set
        webhook_secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
        if webhook_secret:
            signature = self.headers.get("X-Hub-Signature-256", "")
            if not verify_webhook_signature(body, signature, webhook_secret):
                self._send_json({"error": "Invalid signature"}, 401)
                return

        event_type = self.headers.get("X-GitHub-Event", "")
        try:
            payload = json.loads(body.decode())
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        print(f"[Webhook] Received event: {event_type}")

        if event_type == "push":
            # Get installation token
            app_id = os.environ.get("GITHUB_APP_ID", "")
            private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")
            installation_id = str(payload.get("installation", {}).get("id", ""))

            if not installation_id:
                self._send_json({"error": "No installation ID in payload"}, 400)
                return

            token = get_installation_token(app_id, private_key, installation_id)
            if not token:
                # Fallback: try using a personal access token
                token = os.environ.get("GITHUB_TOKEN", "")

            if not token:
                self._send_json({"error": "Could not authenticate with GitHub"}, 500)
                return

            result = handle_push_event(payload, token, self._run_audit)
            self._send_json(result)

        elif event_type == "release":
            token = os.environ.get("GITHUB_TOKEN", "")
            if not token:
                self._send_json({"error": "Could not authenticate with GitHub"}, 500)
                return

            result = handle_release_event(payload, token, self._run_audit)
            self._send_json(result)

        elif event_type in ("installation", "installation_repositories"):
            result = handle_installation_event(payload)
            self._send_json(result)

        elif event_type == "ping":
            self._send_json({"status": "pong", "agent": "blindguard"})

        else:
            self._send_json({"status": "ignored", "event": event_type})

    @staticmethod
    def _run_audit(code_files: dict) -> dict:
        """Run audit pipeline (used by both /audit endpoint and webhook handler)."""
        commitment = create_data_commitment(code_files)
        report = analyze(code_files, use_eigenai=True)
        manifest = load_manifest()
        report_json = report.to_json()
        attestation = create_attestation(
            manifest_version=manifest["agent"]["version"],
            input_commitment=commitment.input_hash,
            output_content=report_json,
            eigenai_model=report.eigenai_model,
            deterministic_seed=report.deterministic_seed,
        )
        record_audit(
            run_id=attestation.run_id,
            input_commitment=commitment.input_hash,
            output_hash=attestation.output_hash,
            findings_count=report.stats["total_findings"],
            severity_counts=report.stats["by_severity"],
            attestation_signature=attestation.tee_signature,
        )
        return {
            "report": report.to_dict(),
            "attestation": attestation.to_dict(),
            "data_commitment": commitment.to_dict(),
            "verification_note": (
                "The 'data_commitment' proves which code was analyzed. "
                "The 'attestation' proves this exact agent produced this exact report. "
                "The source code NEVER leaves the TEE container."
            ),
        }

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
    print(f"║    POST /webhook     GitHub App webhook          ║")
    print(f"╚══════════════════════════════════════════════════╝")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
