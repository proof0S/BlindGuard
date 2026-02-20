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
import subprocess
import urllib.request
import urllib.error
import base64
import tempfile
from typing import Optional

# JWT for GitHub App authentication (PyJWT not needed, we do it manually)


def _normalize_private_key(private_key: str) -> str:
    """Normalize private key loaded from env (supports escaped newlines)."""
    if "\\n" in private_key and "\n" not in private_key:
        return private_key.replace("\\n", "\n")
    return private_key


def create_jwt(app_id: str, private_key: str) -> str:
    """Create a proper RS256 JWT for GitHub App authentication."""

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = b64url(json.dumps({
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id
    }).encode())

    message = f"{header}.{payload}".encode()
    key_material = _normalize_private_key(private_key)

    # Use OpenSSL for RS256 signing to avoid external Python deps.
    # GitHub App JWT requires RS256, HMAC signatures are rejected.
    with tempfile.NamedTemporaryFile("w", delete=False) as key_file:
        key_file.write(key_material)
        key_path = key_file.name
    try:
        os.chmod(key_path, 0o600)
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=message,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            err = proc.stderr.decode(errors="replace").strip()
            print(f"[GitHub App] JWT signing failed: {err}")
            return ""
        signature = b64url(proc.stdout)
    finally:
        try:
            os.remove(key_path)
        except OSError:
            pass

    return f"{header}.{payload}.{signature}"


def get_installation_token(app_id: str, private_key: str, installation_id: str) -> Optional[str]:
    """Get an installation access token from GitHub."""
    jwt_token = create_jwt(app_id, private_key)
    if not jwt_token:
        return None
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
        print(f"[GitHub App] Failed to get installation token: {e.code} {e.read().decode(errors='replace')}")
        return None
    except Exception as e:
        print(f"[GitHub App] Failed to get installation token: {e}")
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

    SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".jsx", ".tsx", ".sol", ".vy", ".rs", ".cairo", ".move", ".go", ".rb", ".php", ".java", ".cs", ".c", ".cpp", ".h")

    for item in tree_data["tree"]:
        if item["type"] != "blob":
            continue
        path = item["path"]
        if not any(path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
            continue
        if any(skip in path for skip in ["venv/", "node_modules/", ".git/", "__pycache__/", "test_", "tests/", "dist/", "build/", ".min.", "vendor/", "migrations/"]):
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
        SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".jsx", ".tsx", ".sol", ".vy", ".rs", ".cairo", ".move", ".go", ".rb", ".php", ".java", ".cs", ".c", ".cpp", ".h")
        if not any(path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
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


def handle_installation_event(payload: dict, token: str = None, audit_fn=None):
    """Handle GitHub App installation and repo change events. Triggers full audit on new repos."""
    action = payload.get("action")
    installation = payload.get("installation", {})
    account = installation.get("account", {})
    sender = payload.get("sender", {}).get("login", "unknown")

    if action == "created":
        print(f"[GitHub App] Installed on {account.get('login')} by {sender}")
        repos = payload.get("repositories", [])
    elif action == "deleted":
        print(f"[GitHub App] Uninstalled from {account.get('login')}")
        return {"status": "ok", "action": action}
    elif action == "added":
        repos = payload.get("repositories_added", [])
        print(f"[GitHub App] {len(repos)} repo(s) added by {sender}")
    elif action == "removed":
        return {"status": "ok", "action": "removed"}
    else:
        return {"status": "ok", "action": action}

    if not token or not audit_fn or not repos:
        return {"status": "ok", "action": action, "repos": len(repos) if repos else 0}

    results = []
    for repo_info in repos:
        repo_full = repo_info.get("full_name", "")
        if not repo_full:
            continue
        owner, repo_name = repo_full.split("/", 1)
        print(f"[GitHub App] Auditing newly added repo: {repo_full}")

        # Get default branch HEAD
        repo_data = github_api("GET", f"/repos/{owner}/{repo_name}", token)
        default_branch = repo_data.get("default_branch", "main")
        ref_data = github_api("GET", f"/repos/{owner}/{repo_name}/git/ref/heads/{default_branch}", token)
        head_sha = ref_data.get("object", {}).get("sha", "")

        if not head_sha:
            results.append({"repo": repo_full, "status": "error", "reason": "no HEAD found"})
            continue

        create_commit_status(owner, repo_name, head_sha, token, "pending", "BlindGuard is auditing this repo...")

        files = get_repo_files(owner, repo_name, head_sha, token)
        if not files:
            create_commit_status(owner, repo_name, head_sha, token, "success", "No supported files to analyze")
            results.append({"repo": repo_full, "status": "no_files"})
            continue

        report = audit_fn(files)
        total = report.get("report", {}).get("stats", {}).get("total_findings", 0)
        state = "failure" if total > 0 else "success"
        desc = f"{total} security issue(s) found" if total > 0 else "No security issues found"
        create_commit_status(owner, repo_name, head_sha, token, state, desc)

        audit_report = report.get("report", {})
        attestation = report.get("attestation", {})
        commitment = report.get("data_commitment", {})
        state, desc, comment_body = format_audit_comment(audit_report, attestation, commitment)
        create_commit_comment(owner, repo_name, head_sha, token, comment_body)
        results.append({"repo": repo_full, "status": "audited", "findings": total})

    return {"status": "ok", "action": action, "results": results}


def handle_release_event(payload: dict, token: str, audit_fn):
    """Handle a GitHub release event. Audits the full repo at the release tag."""
    action = payload.get("action")
    if action not in ("published", "created"):
        return {"status": "ignored", "reason": f"release action '{action}' skipped"}

    repo = payload["repository"]
    owner = repo["owner"]["login"] if isinstance(repo["owner"], dict) else repo["owner"]
    repo_name = repo["name"]
    release = payload["release"]
    tag = release["tag_name"]
    release_name = release.get("name", tag)
    target = release.get("target_commitish", "main")

    print(f"[GitHub App] Release event: {owner}/{repo_name} @ {tag}")

    # Get the commit SHA for this release
    ref_data = github_api("GET", f"/repos/{owner}/{repo_name}/git/ref/tags/{tag}", token)
    if "object" in ref_data:
        head_sha = ref_data["object"]["sha"]
        # If it's an annotated tag, resolve to the commit
        if ref_data["object"]["type"] == "tag":
            tag_data = github_api("GET", f"/repos/{owner}/{repo_name}/git/tags/{head_sha}", token)
            head_sha = tag_data.get("object", {}).get("sha", head_sha)
    else:
        # Fallback to branch
        branch_data = github_api("GET", f"/repos/{owner}/{repo_name}/git/ref/heads/{target}", token)
        head_sha = branch_data.get("object", {}).get("sha", "")

    if not head_sha:
        return {"status": "error", "reason": "could not resolve release commit"}

    # Set pending status
    create_commit_status(
        owner, repo_name, head_sha, token,
        state="pending",
        description=f"BlindGuard is auditing release {tag}..."
    )

    # Get ALL Python files at this release (full audit for releases)
    files = get_repo_files(owner, repo_name, head_sha, token)

    if not files:
        create_commit_status(
            owner, repo_name, head_sha, token,
            state="success",
            description="No Python files to analyze"
        )
        return {"status": "skipped", "reason": "no python files"}

    print(f"[GitHub App] Full release audit: {len(files)} file(s) @ {tag}")

    # Run audit
    result = audit_fn(files)

    report = result["report"]
    attestation = result["attestation"]
    commitment = result["data_commitment"]

    # Format results
    state, description, comment_body = format_audit_comment(report, attestation, commitment)

    # Add release info to the comment
    release_header = f"## 🚀 Release Audit: `{tag}`\n\n"
    release_header += f"Full security audit triggered by release **{release_name}**. "
    release_header += f"All Python files in the repository were analyzed.\n\n---\n\n"
    comment_body = release_header + comment_body

    # Post commit status
    create_commit_status(
        owner, repo_name, head_sha, token,
        state=state,
        description=f"Release {tag}: {description}",
        target_url="https://proof0s.github.io/BlindGuard"
    )

    # Post commit comment
    create_commit_comment(owner, repo_name, head_sha, token, comment_body)

    print(f"[GitHub App] Release audit complete: {tag} — {description}")
    return {"status": "completed", "release": tag, "state": state, "description": description}


def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify the webhook signature from GitHub."""
    if not signature or not signature.startswith("sha256="):
        return False

    expected = hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
