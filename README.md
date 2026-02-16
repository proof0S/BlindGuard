# BlindGuard | Private Security Agent

**Audits your code without ever seeing or stealing it.**

BlindGuard is a security agent that runs entirely inside an EigenCompute TEE (Trusted Execution Environment). You send your source code into the secure enclave, it gets analyzed for vulnerabilities, and the only thing that comes back out is a signed vulnerability report. The raw source code never leaves the enclave. Period.

We built this for the [EigenCloud "Build a Verifiable or Sovereign Agent" Challenge](https://ideas.eigencloud.xyz/).

🔗 [Live Website](https://proof0s.github.io/BlindGuard) · 🔒 [TEE Dashboard](https://verify-sepolia.eigencloud.xyz/app/0x9d70dBAb76b6D97Cba8221Bd897d079DFC3f390E) · 📡 Live API: `http://34.187.234.237:8000`

---

## Live on EigenCompute

BlindGuard is deployed and running on EigenCompute Sepolia right now. You can talk to it directly from your terminal.

To check the agent's identity:

```bash
curl http://34.187.234.237:8000/identity
```

To run a security audit on some code:

```bash
curl -X POST http://34.187.234.237:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"files": {"app.py": "API_KEY=\"secret123\"\nimport os\nos.system(input())"}}'
```

You'll get back a full vulnerability report with a cryptographic attestation, proving that this exact agent analyzed this exact code inside the TEE. The verifiable build and deployment can be inspected on the [EigenCloud Dashboard](https://verify-sepolia.eigencloud.xyz/app/0x9d70dBAb76b6D97Cba8221Bd897d079DFC3f390E).

---

## The Problem

Every company that needs a code audit faces the same uncomfortable tradeoff: to get your code reviewed, you have to hand it over to someone else. That someone could leak it, copy it, or mishandle it. For pre-launch startups and proprietary projects, this is a real risk, and it stops a lot of teams from getting the security review they actually need.

## How BlindGuard Solves It

BlindGuard flips the model. Instead of sending your code to an auditor, you send it into a hardware-isolated TEE on EigenCompute. The security agent lives inside that enclave. It analyzes your code, produces a vulnerability report, and signs everything with a cryptographic attestation. The attestation proves four things: which agent code ran (the Docker image hash), what was analyzed (a hash commitment of your input), what was found (the output hash tied to the report), and which AI model produced the analysis (EigenAI with deterministic inference). Your source code never touches the outside world.

---

## Quick Start

### Using the CLI Locally

Clone the repo and you're ready to go. No dependencies needed.

```bash
git clone https://github.com/proof0S/BlindGuard.git
cd BlindGuard
```

To check the agent's identity, run `python3 blindguard_cli.py identity`. This shows you the code hash, manifest version, capabilities, and upgrade policy.

To audit a file, run `python3 blindguard_cli.py audit sample_vulnerable_app.py -o report.json`. This will analyze the sample vulnerable app and save the report as JSON.

To verify the attestation from that report, run `python3 blindguard_cli.py verify report.json`. And to see the full audit history, run `python3 blindguard_cli.py history`.

### Running the Demo Script

If you just want to see everything in action, run `chmod +x demo.sh` and then `bash demo.sh`. The script walks through all four commands automatically.

### Running as an HTTP Server

Start the server with `python3 server.py` and then you can submit code for audit over HTTP:

```bash
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"files": {"app.py": "import os\nAPI_KEY=\"secret123\"\nos.system(input())"}}'
```

You can also check the agent's identity with `curl http://localhost:8000/identity` and verify an attestation by posting the report JSON to `/verify`.

### Deploying to EigenCompute TEE

To deploy to a real TEE, first install the EigenCloud CLI with `curl -fsSL https://raw.githubusercontent.com/Layr-Labs/eigencloud-tools/master/install-all.sh | bash`. Then authenticate with `ecloud auth generate --store`, subscribe with `ecloud billing subscribe`, set the network with `ecloud compute env set sepolia`, and deploy with `ecloud compute app deploy`. The CLI will detect the Dockerfile, build the image, and push it to a TEE instance.

---

## Architecture

The flow is straightforward. The client (code owner) uploads source code into the EigenCompute TEE. Inside the enclave, a Code Loader parses and prepares the input, then passes it to the Analyzer, which combines static analysis with EigenAI-powered LLM inference. The Analyzer produces a vulnerability report and a cryptographic attestation. Only the report and attestation leave the TEE. The source code stays inside and is discarded after analysis.

```
┌──────────────┐     encrypted      ┌──────────────────────────────────┐
│   Client     │ ──────upload──────▶ │      EigenCompute TEE            │
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
