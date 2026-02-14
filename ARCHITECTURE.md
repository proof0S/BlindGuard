# BlindGuard — Private Security Agent

## Architecture (1-Page)

### Problem
Companies need code audits but fear IP leakage. Sharing source code with auditors creates
a trust dependency: the auditor could steal, leak, or mishandle proprietary code. Today,
you must choose between security insights and IP protection.

### Solution
**BlindGuard** is a Private Security Agent that audits code *without ever exposing it*.
The code enters a TEE (Trusted Execution Environment) on EigenCompute, gets analyzed by
EigenAI's deterministic LLM inference, and only a structured vulnerability report exits.
The raw source code never leaves the secure enclave.

### How It Works

```
┌──────────────┐     encrypted      ┌──────────────────────────────────┐
│   Client     │ ──────upload─────▶ │      EigenCompute TEE            │
│  (code owner)│                    │                                  │
│              │                    │  ┌────────────┐  ┌────────────┐  │
│              │                    │  │ Code Loader │─▶│ EigenAI    │  │
│              │                    │  │ (parse/prep)│  │ (analysis) │  │
│              │                    │  └────────────┘  └─────┬──────┘  │
│              │                    │                        │         │
│              │  attestation +     │  ┌─────────────────────▼──────┐  │
│              │ ◀── vuln report ── │  │  Report Generator         │  │
│              │                    │  │  (findings + commitments)  │  │
└──────────────┘                    │  └───────────────────────────┘  │
                                    └──────────────────────────────────┘
```

### Agent Identity (4 Pillars)

| Pillar            | Implementation                                             |
|-------------------|-------------------------------------------------------------|
| **Code Hash**     | SHA-256 of Docker image, verified by TEE attestation        |
| **Data Commitments** | SHA-256 hash of input code committed before analysis     |
| **Upgrade Policy**| Versioned `manifest.json` with semver + signed upgrades     |
| **Persisted State**| Audit history stored in TEE-encrypted state, queryable     |

### Verification Story
A third party can verify:
1. **Code Integrity** → TEE attestation proves the exact Docker image that ran
2. **Data Privacy** → Only the code hash (commitment) is revealed, never the code itself
3. **Output Authenticity** → Report is signed by TEE-derived key, includes code commitment
4. **Upgrade Compliance** → Manifest version checked against on-chain/published policy
5. **Determinism** → EigenAI ensures identical inputs produce identical analysis

### What We Prevent (Threat Model)
- ✅ Auditor stealing/leaking source code (code never leaves TEE)
- ✅ Tampered analysis (TEE attestation proves unmodified agent)
- ✅ Silent agent upgrades (manifest-gated upgrade policy)
- ✅ Forged reports (TEE-signed output with cryptographic binding)
- ✅ Non-deterministic results (EigenAI deterministic inference)

### What We Don't Prevent
- ❌ Side-channel attacks on TEE hardware (Intel SGX/TDX level)
- ❌ AI hallucinations (LLM may miss real vulns or report false positives)
- ❌ Denial of service (agent availability depends on EigenCompute uptime)
- ❌ Code quality beyond security (only scans for vulnerabilities)

### Tech Stack
- **Runtime**: Python 3.12 in Docker → EigenCompute TEE
- **AI Inference**: EigenAI (OpenAI-compatible API, deterministic mode)
- **CLI**: Click-based Python CLI for local + deployed interaction
- **State**: JSON-based encrypted state in TEE persistent storage
