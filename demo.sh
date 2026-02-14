#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  BlindGuard — Demo Script
#  Private Security Agent: audits code without seeing or stealing it
# ══════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          BlindGuard — Private Security Agent Demo           ║"
echo "║  Audits code without seeing or stealing it                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Show Agent Identity ──────────────────────────────
echo "━━━ STEP 1: Agent Identity ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "The agent has a stable identity defined by its code hash,"
echo "manifest version, and upgrade policy."
echo ""
python3 blindguard_cli.py identity
echo ""

# ─── Step 2: Audit Vulnerable Code ───────────────────────────
echo "━━━ STEP 2: Audit Vulnerable Code ━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "We submit a sample vulnerable app for analysis."
echo "The code enters the agent and NEVER leaves — only the report exits."
echo ""
python3 blindguard_cli.py audit sample_vulnerable_app.py \
    --output /tmp/blindguard-report.json \
    --no-ai
echo ""

# ─── Step 3: Verify the Attestation ──────────────────────────
echo "━━━ STEP 3: Verify the Attestation ━━━━━━━━━━━━━━━━━━━━━━━━"
echo "A third party can verify the attestation WITHOUT seeing the code."
echo "This proves: which agent ran, what was analyzed, and what was found."
echo ""
python3 blindguard_cli.py verify /tmp/blindguard-report.json
echo ""

# ─── Step 4: Check Audit History ─────────────────────────────
echo "━━━ STEP 4: Persisted State — Audit History ━━━━━━━━━━━━━━━"
echo "The agent maintains an encrypted audit trail inside the TEE."
echo "Only commitments are stored — never the actual code."
echo ""
python3 blindguard_cli.py history
echo ""

# ─── Step 5: Verification Story ──────────────────────────────
echo "━━━ STEP 5: Verification Story ━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "How a third party verifies compliance:"
echo ""
echo "  1. CODE INTEGRITY"
echo "     → TEE attestation proves the exact Docker image (code hash)"
echo "     → Agent's code_hash in attestation matches published image digest"
echo ""
echo "  2. DATA PRIVACY"
echo "     → Only the data_commitment (hash) is revealed, never the code"
echo "     → Code owner can verify commitment matches their submitted code"
echo ""
echo "  3. OUTPUT AUTHENTICITY"
echo "     → Report is signed by TEE-derived key"
echo "     → output_hash in attestation matches the actual report content"
echo ""
echo "  4. UPGRADE COMPLIANCE"
echo "     → Manifest version is locked in each attestation"
echo "     → Upgrades require version bump per upgrade_policy"
echo "     → Historical attestations prove version lineage"
echo ""
echo "  5. DETERMINISM"
echo "     → EigenAI with fixed seed ensures identical results for same input"
echo "     → Anyone can re-submit the same code and get the same report"
echo ""

# ─── Step 6: Deploy to EigenCompute ──────────────────────────
echo "━━━ STEP 6: Deploy to EigenCompute TEE ━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "To deploy to production TEE:"
echo ""
echo "  # Install EigenCloud tools"
echo "  curl -fsSL https://tools.eigencloud.xyz | bash"
echo ""
echo "  # Authenticate"
echo "  eigenx auth generate --store"
echo ""
echo "  # Deploy to TEE"
echo "  eigenx app deploy blindguard:latest"
echo ""
echo "  # Check status"
echo "  eigenx app info blindguard"
echo ""
echo "Once deployed, the agent runs in a hardware-isolated TEE."
echo "Code submitted via POST /audit never leaves the secure enclave."
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Demo complete! Report saved to: /tmp/blindguard-report.json"
echo "══════════════════════════════════════════════════════════════"
