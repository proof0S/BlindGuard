"""
BlindGuard — GitHub App Integration
Handles GitHub webhooks for automatic code auditing.
When installed on a repo, runs security audit on every push
inside the TEE and posts results back as a check run.
"""

import json
import hashlib
import hmac
import time
import os
import urllib.request
import urllib.error
import base64
from typing import Optional

# JWT for GitHub App authentication (PyJWT not needed, we do it manually)


def create_jwt(app_id: str, private_key: str) -> str:
    """Create a JWT for GitHub App authentication using manual encoding."""
    import struct

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = b64url(json.dumps({
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id
    }).encode())

    # For RS256 signing we need the private key
    # In TEE deployment, we use a simpler HMAC approach with the webhook secret
    # or rely on the installation token directly
    message = f"{header}.{payload}"

    # Simplified: use HMAC-SHA256 with private key as secret
    # In production, this would use proper RSA signing
    sig = hmac.new(private_key.encode(), message.encode(), hashlib.sha256).digest()
    signature = b64url(sig)

    return f"{message}.{signature}"


def get_installation_token(app_id: str, private_key: str, installation_id: str) -> Optional[str]:
    """Get an installation access token from GitHub."""
    jwt_token = create_jwt(app_id, private_key)
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"

    req = urllib.request.Request(url, method="POST")
    req.add_header("Authorization", f"Bearer {jwt_token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            return data.get("token")
    except urllib.error.HTTPError as e:
        print(f"[GitHub App] Failed to get installation token: {e.code} {e.read().decode()}")
        return None


def github_api(method: str, url: str, token: str, data: dict = None) -> dict:
    """Make an authenticated GitHub API request."""
    if not url.startswith("http"):
        url = f"https://api.github.com{url}"

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if body:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[GitHub App] API error: {e.code} {error_body}")
        return {"error": error_body, "status": e.code}


def get_repo_files(owner: str, repo: str, ref: str, token: str) -> dict:
    """Fetch Python files from a repo at a specific commit."""
    files = {}

    # Get the tree recursively
    tree_data = github_api("GET", f"/repos/{owner}/{repo}/git/trees/{ref}?recursive=1", token)

    if "tree" not in tree_data:
        return files

    for item in tree_data["tree"]:
        if item["type"] != "blob":
            continue
        path = item["path"]
        # Only analyze Python files
        if not path.endswith(".py"):
            continue
        # Skip test files, venvs, etc.
        if any(skip in path for skip in ["venv/", "node_modules/", ".git/", "__pycache__/", "test_", "tests/"]):
            continue
        # Fetch file content
        blob_data = github_api("GET", f"/repos/{owner}/{repo}/git/blobs/{item['sha']}", token)
        if "content" in blob_data:
            try:
                content = base64.b64decode(blob_data["content"]).decode("utf-8", errors="replace")
                files[path] = content
            except Exception:
                pass

    return files


def get_changed_files(owner: str, repo: str, before: str, after: str, token: str) -> dict:
    """Fetch only the Python files that changed in a push."""
    files = {}

    compare_data = github_api("GET", f"/repos/{owner}/{repo}/compare/{before}...{after}", token)

    if "files" not in compare_data:
        # Fallback: get all Python files at the commit
        return get_repo_files(owner, repo, after, token)

    for f in compare_data["files"]:
        path = f["filename"]
        if not path.endswith(".py"):
            continue
        if f["status"] == "removed":
            continue
        # Fetch full file content at the new commit
        file_data = github_api("GET", f"/repos/{owner}/{repo}/contents/{path}?ref={after}", token)
        if "content" in file_data:
            try:
                content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
                files[path] = content
            except Exception:
                pass

    return files


def create_commit_status(owner: str, repo: str, sha: str, token: str, state: str, description: str, target_url: str = ""):
    """Create a commit status (works with PAT, shows icon on commit)."""
    data = {
        "state": state,
        "description": description[:140],
        "context": "BlindGuard Security Audit"
    }
    if target_url:
        data["target_url"] = target_url
    return github_api("POST", f"/repos/{owner}/{repo}/statuses/{sha}", token, data)


def create_commit_comment(owner: str, repo: str, sha: str, token: str, body: str):
    """Create a comment on a commit."""
    return github_api("POST", f"/repos/{owner}/{repo}/commits/{sha}/comments", token, {"body": body})


def format_audit_comment(report: dict, attestation: dict, commitment: dict) -> tuple:
    """Format audit results for GitHub commit comment."""
    stats = report["stats"]
    findings = report["findings"]
    by_sev = stats.get("by_severity", {})

    critical = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    medium = by_sev.get("MEDIUM", 0)
    total = stats["total_findings"]

    if critical > 0:
        state = "failure"
    elif high > 0:
        state = "failure"
    else:
        state = "success"

    if total == 0:
        description = "No security issues found"
    else:
        description = f"Found {total} issue(s): {critical} critical, {high} high, {medium} medium"

    body = "## 🛡️ BlindGuard Security Audit\n\n"
    body += f"Analyzed **{stats['files_analyzed']} file(s)** ({stats['total_lines']} lines) inside the TEE enclave in {report['analysis_duration_ms']}ms.\n\n"

    if total == 0:
        body += "✅ **No security vulnerabilities detected.**\n\n"
    else:
        body += f"**{total} security issue(s) found.**\n\n"
        for f in findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
            body += f"{icon} **[{f['severity']}] {f['title']}** — `{f['file_path']}` {f['line_hint']} ({f['cwe_id']})\n"
            body += f"> 💡 {f['recommendation']}\n\n"

    body += "---\n\n"
    body += "### 🔐 TEE Attestation\n\n"
    body += "This audit ran inside a Trusted Execution Environment on EigenCompute. The source code never left the enclave.\n\n"
    body += f"| Field | Value |\n|---|---|\n"
    body += f"| Run ID | `{attestation['run_id'][:16]}...` |\n"
    body += f"| Agent Code Hash | `{attestation['agent_code_hash'][:24]}...` |\n"
    body += f"| Input Commitment | `{attestation['input_commitment'][:24]}...` |\n"
    body += f"| TEE Signature | `{attestation['tee_signature'][:24]}...` |\n"
    body += f"| Model | `{attestation['eigenai_model']}` |\n"
    body += f"| Version | `{attestation['manifest_version']}` |\n\n"
    body += "*Verified by [BlindGuard](https://proof0s.github.io/BlindGuard) on [EigenCompute TEE](https://verify-sepolia.eigencloud.xyz/app/0x9d70dBAb76b6D97Cba8221Bd897d079DFC3f390E)*"

    return state, description, body


def handle_push_event(payload: dict, token: str, audit_fn):
    """Handle a GitHub push webhook event."""
    repo = payload["repository"]
    owner = repo["owner"]["login"] if isinstance(repo["owner"], dict) else repo["owner"]
    repo_name = repo["name"]
    head_sha = payload["after"]
    before = payload.get("before", "0" * 40)

    print(f"[GitHub App] Push event: {owner}/{repo_name} @ {head_sha[:8]}")

    # Set pending status
    create_commit_status(
        owner, repo_name, head_sha, token,
        state="pending",
        description="BlindGuard is analyzing your code..."
    )

    # Get changed Python files
    if before and before != "0" * 40:
        files = get_changed_files(owner, repo_name, before, head_sha, token)
    else:
        files = get_repo_files(owner, repo_name, head_sha, token)

    if not files:
        create_commit_status(
            owner, repo_name, head_sha, token,
            state="success",
            description="No Python files to analyze"
        )
        return {"status": "skipped", "reason": "no python files"}

    print(f"[GitHub App] Analyzing {len(files)} file(s)...")

    # Run audit through the same TEE pipeline
    result = audit_fn(files)

    report = result["report"]
    attestation = result["attestation"]
    commitment = result["data_commitment"]

    # Format results
    state, description, comment_body = format_audit_comment(report, attestation, commitment)

    # Post commit status (shows icon on commit)
    create_commit_status(
        owner, repo_name, head_sha, token,
        state=state,
        description=description,
        target_url="https://proof0s.github.io/BlindGuard"
    )

    # Post commit comment (shows detailed report)
    create_commit_comment(owner, repo_name, head_sha, token, comment_body)

    print(f"[GitHub App] Audit complete: {description}")
    return {"status": "completed", "state": state, "description": description}


def handle_installation_event(payload: dict):
    """Handle GitHub App installation events."""
    action = payload.get("action")
    installation = payload.get("installation", {})
    account = installation.get("account", {})

    if action == "created":
        print(f"[GitHub App] Installed on {account.get('login')}")
    elif action == "deleted":
        print(f"[GitHub App] Uninstalled from {account.get('login')}")

    return {"status": "ok", "action": action}


def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify the webhook signature from GitHub."""
    if not signature or not signature.startswith("sha256="):
        return False

    expected = hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
