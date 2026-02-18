# BlindGuard

**Private security agent that audits your code without ever seeing or stealing it.**

BlindGuard runs entirely inside an EigenCompute TEE (Trusted Execution Environment). You send your source code into the secure enclave, it gets analyzed for vulnerabilities, and the only thing that comes back out is a signed report. The raw source code never leaves the enclave.

Built for the [EigenCloud Open Innovation Challenge](https://ideas.eigencloud.xyz/).

🌐 [Live Demo](http://34.187.234.237:8000/app) · 🔒 [TEE Dashboard](https://verify-sepolia.eigencloud.xyz/app/0x9d70dBAb76b6D97Cba8221Bd897d079DFC3f390E) · 🔧 [Install GitHub App](https://github.com/apps/blindguard-security)

---

## What It Does

Paste code or point BlindGuard at any public GitHub repo. The TEE fetches the files, runs a language-aware security analysis, and returns a vulnerability report with a cryptographic attestation. Your code never touches the outside world.

Supported languages: Solidity, Vyper, Rust (Solana/Anchor), Cairo (StarkNet), Move (Aptos/Sui), Python, JavaScript, TypeScript, Go.

The analysis catches real vulnerabilities: reentrancy in Solidity contracts, hardcoded private keys, command injection, SQL injection, insecure deserialization, prototype pollution, unsafe blocks in Rust, felt252 overflow in Cairo, unprotected initializers, delegatecall misuse, and more. Each finding includes a severity level, CWE identifier, file path, line number, and a concrete fix recommendation.

---

## Try It

### Web UI (easiest)

Open [http://34.187.234.237:8000/app](http://34.187.234.237:8000/app) in your browser. You can paste code directly or enter any public GitHub repo URL. The analysis runs inside the live TEE and returns real results with attestation.

### Terminal

Check the agent's identity:

```bash
curl http://34.187.234.237:8000/identity
```

Audit a file:

```bash
curl -X POST http://34.187.234.237:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"files": {"app.py": "API_KEY=\"secret123\"\nimport os\nos.system(input())"}}'
```

Audit a GitHub repo:

```bash
curl -X POST http://34.187.234.237:8000/audit-repo \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/OpenZeppelin/openzeppelin-contracts"}'
```

---

## GitHub App

Install the [BlindGuard Security](https://github.com/apps/blindguard-security) GitHub App on any repo. Every commit and every release triggers an automatic audit inside the TEE. Results are posted as commit status icons and detailed markdown comments with findings, severity badges, and a full attestation table.

The flow: you push code, GitHub sends a webhook to the TEE, BlindGuard fetches the changed files, runs the analysis, and posts the report back as a commit comment. For releases, it audits the entire repo at the release tag.

---

## How It Works

The client uploads source code into the EigenCompute TEE. Inside the enclave, the analyzer runs language-aware static analysis combined with pattern matching tuned for each supported language. The analyzer produces a vulnerability report and a cryptographic attestation. Only the report and attestation leave the TEE.

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

The attestation proves four things: which agent code ran (Docker image hash), what was analyzed (SHA-256 commitment of the input), what was found (output hash tied to the report), and which AI model produced the analysis (EigenAI with deterministic inference).

---

## Deployment

BlindGuard is live on EigenCompute Sepolia.

```
App ID:    0x9d70dBAb76b6D97Cba8221Bd897d079DFC3f390E
IP:        34.187.234.237
Instance:  g1-standard-4t (4 vCPUs, 16GB RAM, TDX)
Dashboard: https://verify-sepolia.eigencloud.xyz/app/0x9d70dBAb76b6D97Cba8221Bd897d079DFC3f390E
```

To deploy your own instance, install the EigenCloud CLI, authenticate, subscribe, set the network to sepolia, and run `ecloud compute app deploy`. The CLI detects the Dockerfile and pushes to a TEE instance.

---

## Verification

A third party can verify any BlindGuard audit without seeing the original source code.

**Code integrity:** the `agent_code_hash` in the attestation matches the published Docker image digest on EigenCompute. This confirms the right agent ran.

**Data privacy:** only the `input_commitment` (a SHA-256 hash) is revealed. The code owner can verify this hash matches what they submitted, but the verifier never sees the actual code.

**Output authenticity:** the `output_hash` in the attestation matches the SHA-256 of the report content. This binds the report to the specific execution.

**Determinism:** EigenAI runs with a fixed seed, so anyone with the same input can re-run the analysis and get identical results.

---

## Project Structure

```
analyzer.py          Language-aware security analysis engine
server.py            HTTP server with /audit, /audit-repo, /webhook endpoints
crypto.py            Attestation generation and verification
state.py             TEE-encrypted audit history
github_app.py        GitHub App webhook integration
upgrade.py           Manifest-gated upgrade policy
blindguard_cli.py    CLI tool for local usage
manifest.json        Agent identity and capabilities
index.html           Web UI served from TEE
Dockerfile           Container for TEE deployment
Caddyfile            TLS configuration
```

---

## Tech Stack

Python 3.12 with zero external dependencies. EigenCompute TEE for hardware-isolated execution. EigenAI for deterministic, verifiable LLM inference. Docker container for TEE deployment. GitHub App for CI/CD integration.

---

## License

MIT
