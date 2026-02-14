#!/usr/bin/env python3
"""
BlindGuard CLI — Interact with the Private Security Agent.
Supports both local mode (direct analysis) and remote mode (via TEE server).
"""

import argparse
import json
import os
import sys
import hashlib
import glob

# Add parent dir to path

from analyzer import analyze
from crypto import create_data_commitment, create_attestation, verify_attestation, Attestation
from upgrade import load_manifest, compute_manifest_hash, validate_upgrade
from state import record_audit, get_audit_history, get_stats


BANNER = """
╔══════════════════════════════════════╗
║   BlindGuard — Private Security CLI  ║
║   Code audits without code exposure  ║
╚══════════════════════════════════════╝
"""


def load_code_files(path: str) -> dict[str, str]:
    """Load code files from a file or directory."""
    code_files = {}
    if os.path.isfile(path):
        with open(path, "r") as f:
            code_files[os.path.basename(path)] = f.read()
    elif os.path.isdir(path):
        patterns = ["**/*.py", "**/*.js", "**/*.ts", "**/*.sol", "**/*.go", "**/*.rs", "**/*.java"]
        for pattern in patterns:
            for filepath in glob.glob(os.path.join(path, pattern), recursive=True):
                if any(skip in filepath for skip in ["node_modules", "__pycache__", ".git", "venv"]):
                    continue
                relpath = os.path.relpath(filepath, path)
                try:
                    with open(filepath, "r") as f:
                        code_files[relpath] = f.read()
                except (UnicodeDecodeError, PermissionError):
                    pass
    else:
        print(f"Error: {path} not found")
        sys.exit(1)

    if not code_files:
        print(f"Error: No code files found in {path}")
        sys.exit(1)

    return code_files


def cmd_audit(args):
    """Run a security audit on code."""
    print(BANNER)
    print(f"🔍 Loading code from: {args.path}")

    code_files = load_code_files(args.path)
    print(f"📁 Found {len(code_files)} file(s) to analyze")
    for name in sorted(code_files.keys()):
        lines = len(code_files[name].split("\n"))
        print(f"   • {name} ({lines} lines)")

    # Create data commitment
    commitment = create_data_commitment(code_files)
    print(f"\n🔐 Data Commitment: {commitment.input_hash[:16]}...")
    print(f"   (This proves WHAT was analyzed without revealing the code)")

    # Run analysis
    print(f"\n⚙️  Analyzing...")
    report = analyze(code_files, use_eigenai=not args.no_ai)
    print(f"   Analysis completed in {report.analysis_duration_ms:.0f}ms")

    # Create attestation
    manifest = load_manifest()
    report_json = report.to_json()
    attestation = create_attestation(
        manifest_version=manifest["agent"]["version"],
        input_commitment=commitment.input_hash,
        output_content=report_json,
        eigenai_model=report.eigenai_model,
        deterministic_seed=report.deterministic_seed,
    )

    # Record in state
    record_audit(
        run_id=attestation.run_id,
        input_commitment=commitment.input_hash,
        output_hash=attestation.output_hash,
        findings_count=report.stats["total_findings"],
        severity_counts=report.stats["by_severity"],
        attestation_signature=attestation.tee_signature,
    )

    # Print report
    print(f"\n{'='*60}")
    print(f"  SECURITY AUDIT REPORT")
    print(f"{'='*60}")
    print(f"\n📊 Summary: {report.summary}")
    print(f"   Files analyzed: {report.stats['files_analyzed']}")
    print(f"   Total lines: {report.stats['total_lines']}")

    if report.findings:
        print(f"\n{'─'*60}")
        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}
        for f in report.findings:
            icon = severity_icons.get(f.severity.value, "•")
            print(f"\n{icon} [{f.severity.value}] {f.title}")
            print(f"   ID: {f.id} | File: {f.file_path} | {f.line_hint or ''}")
            if f.cwe_id:
                print(f"   CWE: {f.cwe_id}")
            print(f"   {f.description}")
            print(f"   💡 {f.recommendation}")
    else:
        print(f"\n✅ No issues found!")

    # Attestation
    print(f"\n{'='*60}")
    print(f"  ATTESTATION")
    print(f"{'='*60}")
    print(f"  Run ID:            {attestation.run_id}")
    print(f"  Agent Code Hash:   {attestation.agent_code_hash[:32]}...")
    print(f"  Manifest Version:  {attestation.manifest_version}")
    print(f"  Input Commitment:  {attestation.input_commitment[:32]}...")
    print(f"  Output Hash:       {attestation.output_hash[:32]}...")
    print(f"  EigenAI Model:     {attestation.eigenai_model}")
    print(f"  TEE Signature:     {attestation.tee_signature[:32]}...")

    # Save outputs
    if args.output:
        output = {
            "report": report.to_dict(),
            "attestation": attestation.to_dict(),
            "data_commitment": commitment.to_dict(),
        }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\n💾 Full report saved to: {args.output}")

    print(f"\n🔒 Source code was analyzed locally and NEVER transmitted.")
    print(f"   In TEE mode, code never leaves the secure enclave.")


def cmd_verify(args):
    """Verify an attestation from a previous audit."""
    print(BANNER)
    print(f"🔍 Verifying attestation from: {args.file}")

    with open(args.file, "r") as f:
        data = json.load(f)

    att_data = data.get("attestation", data)
    att = Attestation(**att_data)

    result = verify_attestation(att)

    print(f"\n{'='*60}")
    print(f"  VERIFICATION RESULT")
    print(f"{'='*60}")
    if result["signature_valid"]:
        print(f"\n  ✅ PASS — Attestation is VALID")
    else:
        print(f"\n  ❌ FAIL — Attestation is INVALID")
    print(f"\n  Agent Code Hash: {result['agent_code_hash'][:32]}...")
    print(f"  Run ID:          {result['run_id']}")
    print(f"  Timestamp:       {result['timestamp']}")


def cmd_identity(args):
    """Show agent identity."""
    print(BANNER)
    manifest = load_manifest()
    from crypto import compute_docker_image_hash

    print(f"  Agent:           {manifest['agent']['name']}")
    print(f"  Version:         {manifest['agent']['version']}")
    print(f"  Code Hash:       {compute_docker_image_hash()[:32]}...")
    print(f"  Manifest Hash:   {compute_manifest_hash(manifest)[:32]}...")
    print(f"  Capabilities:    {', '.join(manifest['capabilities'])}")
    print(f"  EigenAI Model:   {manifest['eigencompute']['eigenai_model']}")
    print(f"  Deterministic:   {manifest['eigencompute']['deterministic']}")
    print(f"\n  Upgrade Policy:")
    policy = manifest["upgrade_policy"]
    print(f"    Require version bump: {policy['require_version_bump']}")
    print(f"    Require signed manifest: {policy['require_signed_manifest']}")
    print(f"    Minimum version: {policy['minimum_version']}")


def cmd_history(args):
    """Show audit history."""
    print(BANNER)
    history = get_audit_history(limit=args.limit)
    stats = get_stats()

    print(f"  Total audits: {stats['total_audits']}")
    print(f"  Agent version: {stats['version']}")
    print()

    if not history:
        print("  No audits recorded yet.")
        return

    for audit in reversed(history):
        print(f"  ┌─ Run {audit['run_id']}")
        print(f"  │  Findings: {audit['findings_count']} | Severity: {json.dumps(audit['severity_counts'])}")
        print(f"  │  Commitment: {audit['input_commitment'][:24]}...")
        print(f"  └─ Signature: {audit['attestation_signature'][:24]}...")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="BlindGuard — Private Security Agent CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # audit
    p_audit = sub.add_parser("audit", help="Run security audit on code")
    p_audit.add_argument("path", help="File or directory to audit")
    p_audit.add_argument("-o", "--output", help="Save full report + attestation to JSON file")
    p_audit.add_argument("--no-ai", action="store_true", help="Skip EigenAI analysis (static only)")
    p_audit.set_defaults(func=cmd_audit)

    # verify
    p_verify = sub.add_parser("verify", help="Verify an audit attestation")
    p_verify.add_argument("file", help="JSON file containing attestation")
    p_verify.set_defaults(func=cmd_verify)

    # identity
    p_id = sub.add_parser("identity", help="Show agent identity")
    p_id.set_defaults(func=cmd_identity)

    # history
    p_hist = sub.add_parser("history", help="Show audit history")
    p_hist.add_argument("-n", "--limit", type=int, default=10, help="Number of audits to show")
    p_hist.set_defaults(func=cmd_history)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
