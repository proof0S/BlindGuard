# BlindGuard — Private Security Agent

**Audits your code without ever seeing or stealing it.**

BlindGuard is a security agent that runs entirely inside an EigenCompute TEE (Trusted Execution Environment). You send your source code into the secure enclave, it gets analyzed for vulnerabilities, and the only thing that comes back out is a signed vulnerability report. The raw source code never leaves the enclave. Period.

We built this for the [EigenCloud "Build a Verifiable or Sovereign Agent" Challenge](https://ideas.eigencloud.xyz/).

---

## The Problem

Every company that needs a code audit faces the same uncomfortable tradeoff: to get your code reviewed, you have to hand it over to someone else. That someone could leak it, copy it, or mishandle it. For pre-launch startups and proprietary projects, this is a real risk, and it stops a lot of teams from getting the security review they actually need.

## How BlindGuard Solves It

BlindGuard flips the model. Instead of sending your code to an auditor, you send it into a hardware-isolated TEE on EigenCompute. The security agent lives inside that enclave. It analyzes your code, produces a vulnerability report, and signs everything with a cryptographic attestation. The attestation proves four things: which agent code ran (the Docker image hash), what was analyzed (a hash commitment of your input), what was found (the output hash tied to the report), and which AI model produced the analysis (EigenAI with deterministic inference). Your source code never touches the outside world.

---

## Quick Start

### Running the Demo

Clone the repo, enter the directory, and run the demo script:

```bash
cd blindguard
chmod +x demo.sh
bash demo.sh
```

That's it. The script will audit a sample vulnerable app and walk you through the full flow.

### Using the CLI

You can audit a single file or an entire directory:

```bash
python3 blindguard_cli.py audit path/to/code.py
```

If you want the report as a JSON file:

```bash
python3 blindguard_cli.py audit ./my-project -o report.json
```

To verify an attestation from a previous audit:

```bash
python3 blindguard_cli.py verify report.json
```

You can also check the agent's identity or browse the audit history:

```bash
python3 blindguard_cli.py identity
python3 blindguard_cli.py history
```

### Running as an HTTP Server

If you prefer to interact over HTTP:

```bash
python3 -m agent.server
```

Then submit code for audit:

```bash
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"files": {"app.py": "import os\nAPI_KEY=\"secret123\"\nos.system(input())"}}'
```

Check the agent's identity with `curl http://localhost:8000/identity` and verify an attestation by posting the report JSON to `/verify`.

### Deploying to EigenCompute TEE

Once you're ready for the real thing:

```bash
curl -fsSL https://tools.eigencloud.xyz | bash
eigenx auth generate --store
eigenx app deploy blindguard:latest
```

You can monitor your deployment with `eigenx app info blindguard` and `eigenx app logs blindguard`.

---

## Architecture

The flow is straightforward. The client (code owner) uploads encrypted source code into the EigenCompute TEE. Inside the enclave, a Code Loader parses and prepares the input, then passes it to the Analyzer, which combines static analysis with EigenAI-powered LLM inference. The Analyzer produces a vulnerability report and a cryptographic attestation. Only the report and attestation leave the TEE. The source code stays inside and is discarded after analysis.

```
┌──────────────┐     encrypted      ┌──────────────────────────────────┐
│   Client     │ ──────upload─────▶ │      EigenCompute TEE            │
│  (code owner)│                    │                                  │
│              │                    │  ┌────────────┐  ┌────────────┐  │
│              │                    │  │ Code Loader │─▶│ Analyzer   │  │
│              │                    │  │ (parse/prep)│  │ (static +  │  │
│              │                    │  └────────────┘  │  EigenAI)  │  │
│              │  attestation +     │                  └─────┬──────┘  │
│              │ ◀── vuln report ── │  ┌─────────────────────▼──────┐  │
│              │                    │  │  Report + Attestation      │  │
└──────────────┘                    │  └───────────────────────────┘  │
                                    └──────────────────────────────────┘
```

---

## Agent Identity

BlindGuard's identity is defined by four pillars, which together make the agent's behavior fully auditable.

**Code Hash.** The SHA-256 digest of the Docker image. The TEE attestation includes this hash, so anyone can verify that the exact published image is what actually ran.

**Data Commitment.** Before analysis begins, a SHA-256 hash of the submitted code is computed and committed. This proves what input was analyzed without revealing the input itself.

**Upgrade Policy.** The agent ships with a `manifest.json` that enforces semantic versioning. Upgrades can only happen through a defined process: the manifest version must increment, and upgrades are signed. No silent changes.

**Persisted State.** Every audit is recorded in TEE-encrypted storage. The audit history is queryable, so there's a verifiable trail of every analysis the agent has performed.

---

## Repo Structure

```
blindguard/
├── agent/                  Core agent logic (runs inside the TEE)
│   ├── analyzer.py         Security analysis engine (static + EigenAI)
│   ├── crypto.py           Hashing, commitments, attestation generation
│   ├── server.py           HTTP server for TEE deployment
│   ├── state.py            Persisted state and audit history
│   └── upgrade.py          Upgrade policy enforcement
├── cli/
│   └── blindguard_cli.py   Command-line interface
├── tests/
│   └── sample_vulnerable_app.py
├── scripts/
│   └── demo.sh             Full demo walkthrough
├── docs/
│   └── ARCHITECTURE.md     Detailed architecture doc
├── Dockerfile              EigenCompute-ready container
├── manifest.json           Agent identity and upgrade policy
└── README.md
```

---

## Threat Model

### What We Prevent

The core threat is an auditor stealing or leaking your code. BlindGuard handles this by ensuring code never leaves the TEE — only the report and a cryptographic commitment come out. If someone tries to tamper with the analysis, the TEE attestation will catch it, because it proves the exact agent code that ran. Silent upgrades are blocked by the manifest-gated upgrade policy with version checks. Forged reports are impossible because every report is bound to a TEE-signed attestation. And because EigenAI uses deterministic inference with a fixed seed, you can reproduce the same analysis for the same input.

### What We Don't Prevent

We're honest about the limits. TEE hardware side-channel attacks are a known class of vulnerability that's beyond what software can solve. The AI model might miss real vulnerabilities or flag false positives — that's the nature of LLM-based analysis today. Availability depends on EigenCompute uptime, so we can't guarantee against denial of service. And BlindGuard only looks at security issues, not code quality, performance, or architecture.

---

## Verification Story

Here's how a third party can verify any BlindGuard audit without ever seeing the original source code.

First, they check **code integrity**: the `agent_code_hash` in the attestation should match the published Docker image digest on EigenCompute. This confirms the right agent ran.

Second, they confirm **data privacy**: only the `input_commitment` (a hash) is revealed. The code owner can independently verify this hash matches what they submitted, but the verifier never sees the actual code.

Third, they validate **output authenticity**: the `output_hash` in the attestation must match the SHA-256 of the report content. This binds the report to the specific execution.

Fourth, they check **upgrade compliance**: the `manifest_version` in the attestation matches the deployed version, and the upgrade policy enforces semantic versioning.

Finally, **determinism**: because EigenAI runs with a fixed seed, anyone with the same input can re-run the analysis and get identical results.

---

## Tech Stack

The core agent is written in Python 3.12 with zero external dependencies. It runs inside an EigenCompute TEE for hardware-isolated execution. AI-powered analysis uses EigenAI for deterministic, verifiable LLM inference. The whole thing is packaged as a Docker container for TEE deployment.

---

## License

MIT
