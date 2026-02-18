"""
BlindGuard — Security Analyzer v3
Precision-focused security analysis for crypto/web3 ecosystem.
Philosophy: fewer, high-confidence findings > many noisy ones.
Supports: Solidity, Vyper, Rust, Cairo, Move, Python, JS/TS, Go
"""

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    file_path: str
    line_hint: Optional[str] = None
    recommendation: str = ""
    cwe_id: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AuditReport:
    summary: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    analysis_duration_ms: float = 0
    eigenai_model: str = ""
    deterministic_seed: Optional[int] = None

    def to_dict(self):
        return {
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
            "analysis_duration_ms": self.analysis_duration_ms,
            "eigenai_model": self.eigenai_model,
            "deterministic_seed": self.deterministic_seed,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def detect_language(filepath: str) -> str:
    ext_map = {
        ".sol": "solidity", ".vy": "vyper",
        ".rs": "rust", ".cairo": "cairo", ".move": "move",
        ".py": "python",
        ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript",
        ".go": "go",
        ".rb": "ruby", ".php": "php",
        ".java": "java", ".cs": "csharp",
        ".c": "c", ".cpp": "cpp", ".h": "c",
    }
    for ext, lang in ext_map.items():
        if filepath.endswith(ext):
            return lang
    return "unknown"


def is_comment_line(line: str, lang: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if lang == "python" and stripped.startswith("#"):
        return True
    if lang in ("solidity", "vyper", "rust", "javascript", "typescript",
                "go", "java", "c", "cpp", "csharp", "cairo", "move") and stripped.startswith("//"):
        return True
    if stripped.startswith("/*") or stripped.startswith("*"):
        return True
    return False


def is_test_file(filepath: str) -> bool:
    skip = [
        "_test.go", ".test.js", ".test.ts", ".test.jsx", ".test.tsx",
        ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
        "test_", "/tests/", "/test/", "/spec/", "/__tests__/",
        "/mock/", "/mocks/", "/fixture/", "/fixtures/",
        "conftest.py", "setup.py", "setup.cfg",
    ]
    return any(s in filepath for s in skip)


def is_config_or_build(filepath: str) -> bool:
    skip = [
        "node_modules/", "venv/", ".git/", "__pycache__/",
        "dist/", "build/", ".min.", "vendor/", "migrations/",
        "package.json", "package-lock.json", "yarn.lock",
        "Cargo.lock", "go.sum", ".config.", "webpack.",
    ]
    return any(s in filepath for s in skip)


PATTERNS = [
    # ── UNIVERSAL ──
    {
        "id": "HARDCODED_SECRET", "langs": [],
        "patterns": [
            r"""(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]""",
            r"""(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]""",
            r"""(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"][^'\"]+['\"]""",
            r"""(?i)(PRIVATE_KEY|MNEMONIC|SEED_PHRASE|INFURA_KEY|ALCHEMY_KEY|ETHERSCAN_KEY)\s*[=:]\s*['\"][^'\"]+['\"]""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Secret or Credential",
        "description": "A secret, API key, or credential is hardcoded in source code. If this code is pushed to a repository, the secret is exposed to anyone with access.",
        "cwe": "CWE-798",
        "recommendation": "Store secrets in environment variables or a secrets manager. Add the file to .gitignore if it contains local config.",
    },
    {
        "id": "PRIVATE_KEY_HEX", "langs": [],
        "patterns": [r"""['\"]0x[a-fA-F0-9]{64}['\"]"""],
        "severity": Severity.CRITICAL,
        "title": "Potential Private Key in Code",
        "description": "A 64-character hex string (256-bit) was found. This matches the format of Ethereum and other blockchain private keys.",
        "cwe": "CWE-798",
        "recommendation": "Never store private keys in source code. Use hardware wallets, KMS, or secure environment variables.",
    },

    # ── SOLIDITY ──
    {
        "id": "SOL_REENTRANCY", "langs": ["solidity"],
        "patterns": [r"""\.call\{.*value""", r"""\.call\.value\s*\("""],
        "severity": Severity.CRITICAL,
        "title": "Potential Reentrancy",
        "description": "External call with value transfer detected. If contract state is updated after this call, a malicious contract can re-enter and drain funds.",
        "cwe": "CWE-841",
        "recommendation": "Follow checks-effects-interactions: update all state before external calls. Use OpenZeppelin ReentrancyGuard.",
    },
    {
        "id": "SOL_TX_ORIGIN", "langs": ["solidity"],
        "patterns": [r"""tx\.origin"""],
        "severity": Severity.HIGH,
        "title": "tx.origin Used for Authorization",
        "description": "tx.origin returns the original EOA, not the immediate caller. A phishing contract can trick users into calling it, inheriting their tx.origin.",
        "cwe": "CWE-284",
        "recommendation": "Use msg.sender for authorization. tx.origin should only check if caller is an EOA.",
    },
    {
        "id": "SOL_DELEGATECALL", "langs": ["solidity"],
        "patterns": [r"""\.delegatecall\("""],
        "severity": Severity.CRITICAL,
        "title": "delegatecall Usage",
        "description": "delegatecall executes external code in the caller's storage context. If the target is controllable, an attacker can overwrite any storage slot.",
        "cwe": "CWE-829",
        "recommendation": "Only delegatecall to trusted, verified, immutable contracts. Never use user-supplied addresses.",
    },
    {
        "id": "SOL_SELFDESTRUCT", "langs": ["solidity"],
        "patterns": [r"""selfdestruct\s*\("""],
        "severity": Severity.HIGH,
        "title": "selfdestruct Present",
        "description": "selfdestruct destroys the contract and force-sends ETH. Can break contracts depending on address(this).balance.",
        "cwe": "CWE-284",
        "recommendation": "Remove selfdestruct unless necessary. If kept, protect with multi-sig. Deprecated in newer EVM versions.",
    },
    {
        "id": "SOL_OLD_VERSION", "langs": ["solidity"],
        "patterns": [r"""pragma\s+solidity\s+[\^~]?0\.[0-6]\."""],
        "severity": Severity.HIGH,
        "title": "Solidity < 0.8 (No Overflow Protection)",
        "description": "Solidity before 0.8.0 silently overflows on arithmetic. This has caused numerous DeFi exploits.",
        "cwe": "CWE-190",
        "recommendation": "Upgrade to Solidity ^0.8.0 for built-in overflow checks, or use SafeMath.",
    },
    {
        "id": "SOL_UNPROTECTED_INIT", "langs": ["solidity"],
        "patterns": [r"""function\s+initialize\s*\([^)]*\)\s*(?:public|external)\s+(?!initializer)"""],
        "severity": Severity.CRITICAL,
        "title": "Unprotected Initializer",
        "description": "initialize() is publicly callable without the initializer modifier. An attacker can call it first and take ownership.",
        "cwe": "CWE-284",
        "recommendation": "Use OpenZeppelin's initializer modifier on all initialization functions.",
    },
    {
        "id": "SOL_UNSAFE_APPROVE", "langs": ["solidity"],
        "patterns": [r"""\.approve\s*\([^,]+,\s*type\(uint256\)\.max"""],
        "severity": Severity.MEDIUM,
        "title": "Unlimited Token Approval",
        "description": "Max uint256 approval gives permanent unlimited access to user tokens. If the approved contract is compromised, all tokens are at risk.",
        "cwe": "CWE-732",
        "recommendation": "Approve only the exact amount needed. Consider EIP-2612 permit for gasless approvals.",
    },

    # ── VYPER ──
    {
        "id": "VY_RAW_CALL", "langs": ["vyper"],
        "patterns": [r"""raw_call\s*\("""],
        "severity": Severity.HIGH,
        "title": "raw_call Usage",
        "description": "Low-level external call. Without return value checking and reentrancy protection, it can lead to fund loss.",
        "cwe": "CWE-841",
        "recommendation": "Check raw_call return values. Use @nonreentrant decorator.",
    },

    # ── RUST (Solana/Anchor) ──
    {
        "id": "RS_UNSAFE", "langs": ["rust"],
        "patterns": [r"""unsafe\s*\{"""],
        "severity": Severity.HIGH,
        "title": "unsafe Block",
        "description": "Unsafe blocks bypass Rust's memory safety. In on-chain programs, this can lead to exploitable memory corruption.",
        "cwe": "CWE-676",
        "recommendation": "Minimize unsafe usage. Document each unsafe block with a SAFETY comment.",
    },
    {
        "id": "RS_UNCHECKED_MATH", "langs": ["rust"],
        "patterns": [r"""\.wrapping_(?:add|sub|mul)\(""", r"""\.overflowing_(?:add|sub|mul)\("""],
        "severity": Severity.HIGH,
        "title": "Wrapping/Overflowing Arithmetic",
        "description": "Wrapping arithmetic silently overflows. In token calculations, this produces incorrect amounts.",
        "cwe": "CWE-190",
        "recommendation": "Use checked_add/checked_sub/checked_mul for financial calculations.",
    },

    # ── CAIRO (StarkNet) ──
    {
        "id": "CAIRO_FELT_ARITH", "langs": ["cairo"],
        "patterns": [r"""felt252\s*[+\-*/]""", r"""[+\-*/]\s*felt252"""],
        "severity": Severity.MEDIUM,
        "title": "felt252 Arithmetic",
        "description": "felt252 arithmetic wraps modulo a large prime. Subtraction going negative silently wraps to a huge number.",
        "cwe": "CWE-190",
        "recommendation": "Use u256 or bounded types for financial calculations. Add range checks.",
    },

    # ── MOVE (Aptos/Sui) ──
    {
        "id": "MOVE_COIN_TRANSFER", "langs": ["move"],
        "patterns": [r"""coin::transfer""", r"""transfer::public_transfer"""],
        "severity": Severity.MEDIUM,
        "title": "Token Transfer Operation",
        "description": "Token transfer detected. Verify signer/capability checks to prevent unauthorized transfers.",
        "cwe": "CWE-284",
        "recommendation": "Ensure all transfer functions validate signer authority and amounts.",
    },

    # ── PYTHON ──
    {
        "id": "PY_SQL_INJECTION", "langs": ["python"],
        "patterns": [
            r"""(?:execute|cursor\.execute)\s*\(\s*f['\"]""",
            r"""(?:execute|cursor\.execute)\s*\(\s*['\"].*%s""",
        ],
        "severity": Severity.HIGH,
        "title": "SQL Injection",
        "description": "SQL query built with f-strings or % formatting. Attackers can inject SQL to read, modify, or delete data.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    },
    {
        "id": "PY_CMD_INJECTION", "langs": ["python"],
        "patterns": [r"""os\.system\s*\(""", r"""os\.popen\s*\(""", r"""subprocess\.\w+\s*\(.*shell\s*=\s*True"""],
        "severity": Severity.CRITICAL,
        "title": "Shell Command Execution",
        "description": "os.system/popen/subprocess with shell=True enables arbitrary command execution if user input reaches the command string.",
        "cwe": "CWE-78",
        "recommendation": "Use subprocess.run() with shell=False and arguments as a list.",
    },
    {
        "id": "PY_PICKLE", "langs": ["python"],
        "patterns": [r"""pickle\.loads?\s*\("""],
        "severity": Severity.HIGH,
        "title": "Insecure Deserialization (pickle)",
        "description": "pickle can execute arbitrary code during deserialization. A crafted payload achieves full RCE.",
        "cwe": "CWE-502",
        "recommendation": "Never unpickle untrusted data. Use JSON instead.",
    },
    {
        "id": "PY_EVAL", "langs": ["python"],
        "patterns": [r"""\beval\s*\(\s*(?:request|input|sys\.argv)""", r"""\bexec\s*\(\s*(?:request|input|sys\.argv)"""],
        "severity": Severity.CRITICAL,
        "title": "Code Injection via eval/exec",
        "description": "eval/exec with external input allows arbitrary code execution.",
        "cwe": "CWE-95",
        "recommendation": "Use ast.literal_eval() for safe evaluation. Avoid eval/exec with external input.",
    },
    {
        "id": "PY_WEAK_CRYPTO", "langs": ["python"],
        "patterns": [r"""hashlib\.md5\s*\(""", r"""hashlib\.sha1\s*\("""],
        "severity": Severity.MEDIUM,
        "title": "Weak Cryptographic Hash",
        "description": "MD5/SHA1 have known collision attacks. Unsuitable for signatures or integrity checks.",
        "cwe": "CWE-328",
        "recommendation": "Use hashlib.sha256() or bcrypt/argon2 for passwords.",
    },
    {
        "id": "PY_DEBUG", "langs": ["python"],
        "patterns": [r"""app\.run\s*\(.*debug\s*=\s*True"""],
        "severity": Severity.MEDIUM,
        "title": "Flask Debug Mode",
        "description": "Flask debug mode enables the Werkzeug debugger which allows arbitrary code execution via the browser.",
        "cwe": "CWE-489",
        "recommendation": "Never use debug=True in production.",
    },

    # ── JAVASCRIPT / TYPESCRIPT ──
    {
        "id": "JS_CMD_INJECTION", "langs": ["javascript", "typescript"],
        "patterns": [r"""child_process\.exec\w*\s*\(.*\+""", r"""child_process\.exec\w*\s*\(.*\$\{"""],
        "severity": Severity.CRITICAL,
        "title": "Command Injection",
        "description": "User input concatenated into a shell command enables arbitrary command execution.",
        "cwe": "CWE-78",
        "recommendation": "Use child_process.execFile() or spawn() with arguments as an array.",
    },
    {
        "id": "JS_EVAL", "langs": ["javascript", "typescript"],
        "patterns": [r"""\beval\s*\(\s*(?:req\.|request\.|params|query|body)"""],
        "severity": Severity.CRITICAL,
        "title": "Code Injection via eval",
        "description": "eval() called with user input enables arbitrary JavaScript execution.",
        "cwe": "CWE-95",
        "recommendation": "Never pass user input to eval. Use JSON.parse() for data.",
    },
    {
        "id": "JS_PROTOTYPE_POLLUTION", "langs": ["javascript", "typescript"],
        "patterns": [r"""\[['"]__proto__['"]\]""", r"""\[['"]constructor['"]\]\s*\[['"]prototype['"]\]"""],
        "severity": Severity.HIGH,
        "title": "Prototype Pollution",
        "description": "Direct __proto__ or constructor.prototype access can modify Object prototype, affecting all objects.",
        "cwe": "CWE-1321",
        "recommendation": "Use Object.create(null) for dictionaries. Validate user keys are not __proto__/constructor/prototype.",
    },
    {
        "id": "JS_PRIVATE_KEY", "langs": ["javascript", "typescript"],
        "patterns": [
            r"""new\s+ethers\.Wallet\s*\(\s*['\"]0x[a-fA-F0-9]""",
            r"""web3\.eth\.accounts\.privateKeyToAccount\s*\(\s*['\"]""",
            r"""Keypair\.fromSecretKey\s*\(""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Private Key in Web3 Code",
        "description": "A blockchain private key is hardcoded. Anyone with code access can steal all funds.",
        "cwe": "CWE-798",
        "recommendation": "Load keys from environment variables or use hardware wallets / KMS.",
    },

    # ── GO ──
    {
        "id": "GO_SQL_INJECTION", "langs": ["go"],
        "patterns": [r"""fmt\.Sprintf\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)"""],
        "severity": Severity.HIGH,
        "title": "SQL Injection via fmt.Sprintf",
        "description": "SQL query built with fmt.Sprintf. User input can modify the query.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries: db.Query('SELECT * FROM users WHERE id = $1', userID)",
    },
    {
        "id": "GO_CMD_INJECTION", "langs": ["go"],
        "patterns": [r"""exec\.Command\s*\(\s*['"](?:sh|bash|cmd)['"]\s*,\s*['"]-c['"]"""],
        "severity": Severity.CRITICAL,
        "title": "Command Injection via Shell",
        "description": "Shell invocation with -c enables command injection if user input is included.",
        "cwe": "CWE-78",
        "recommendation": "Call programs directly without a shell interpreter.",
    },
]


def run_static_analysis(code_files: dict[str, str]) -> list[Finding]:
    findings = []
    counter = 0

    for filepath, content in code_files.items():
        if is_test_file(filepath) or is_config_or_build(filepath):
            continue

        lang = detect_language(filepath)
        lines = content.split("\n")

        for vuln in PATTERNS:
            target_langs = vuln["langs"]
            if target_langs and lang not in target_langs:
                continue

            for pattern in vuln["patterns"]:
                for line_num, line in enumerate(lines, 1):
                    if is_comment_line(line, lang):
                        continue
                    try:
                        if re.search(pattern, line):
                            counter += 1
                            findings.append(Finding(
                                id=f"SG-{counter:04d}",
                                title=vuln["title"],
                                severity=vuln["severity"],
                                description=vuln["description"],
                                file_path=filepath,
                                line_hint=f"Line {line_num}",
                                recommendation=vuln["recommendation"],
                                cwe_id=vuln.get("cwe"),
                            ))
                    except re.error:
                        pass

    # Dedup same title+file+line
    seen = set()
    deduped = []
    for f in findings:
        key = (f.title, f.file_path, f.line_hint)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Max 3 same finding per file
    tfc = {}
    limited = []
    for f in deduped:
        key = (f.title, f.file_path)
        tfc[key] = tfc.get(key, 0) + 1
        if tfc[key] <= 3:
            limited.append(f)

    # Max 5 same finding globally
    tgc = {}
    final = []
    for f in limited:
        tgc[f.title] = tgc.get(f.title, 0) + 1
        if tgc[f.title] <= 5:
            final.append(f)

    for i, f in enumerate(final, 1):
        f.id = f"SG-{i:04d}"

    return final


def build_eigenai_prompt(code_files: dict[str, str], static_findings: list[Finding]) -> str:
    code_section = ""
    for path, content in sorted(code_files.items()):
        lang = detect_language(path)
        truncated = content[:5000] + ("\n... [truncated]" if len(content) > 5000 else "")
        code_section += f"\n### File: {path} ({lang})\n```\n{truncated}\n```\n"

    static_section = ""
    if static_findings:
        static_section = "\n## Pre-detected Issues\n"
        for f in static_findings:
            static_section += f"- [{f.severity.value}] {f.title} in {f.file_path} ({f.line_hint})\n"

    return f"""You are a senior blockchain security auditor. Analyze this code for vulnerabilities.
Focus on: reentrancy, access control, overflow, front-running, injection, key management, logic bugs.
Only report high-confidence issues.

{static_section}

## Code
{code_section}

Return a JSON array of findings. Each: title, severity, description, file_path, line_hint, recommendation, cwe_id.
Return [] if no additional issues. Only JSON.
"""


def call_eigenai(prompt: str, model: str = "gpt-oss-120b-f16", seed: int = 42) -> str:
    eigenai_url = os.environ.get("EIGENAI_API_URL", "")
    eigenai_key = os.environ.get("EIGENAI_API_KEY", "")

    if eigenai_url and eigenai_key:
        import urllib.request
        req_body = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "seed": seed, "temperature": 0, "max_tokens": 4000,
        })
        req = urllib.request.Request(eigenai_url, data=req_body.encode(), headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {eigenai_key}",
        })
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]
    return "[]"


def analyze(code_files: dict[str, str], use_eigenai: bool = True) -> AuditReport:
    start = time.time()

    lang_counts = {}
    for fp in code_files:
        if not is_test_file(fp) and not is_config_or_build(fp):
            lang_counts[detect_language(fp)] = lang_counts.get(detect_language(fp), 0) + 1

    static_findings = run_static_analysis(code_files)

    ai_findings = []
    model_used = "none (static-only)"
    seed_used = None

    if use_eigenai:
        model_used = os.environ.get("EIGENAI_MODEL", "gpt-oss-120b-f16")
        seed_used = 42
        prompt = build_eigenai_prompt(code_files, static_findings)
        try:
            ai_response = call_eigenai(prompt, model=model_used, seed=seed_used)
            raw = ai_response.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
            parsed = json.loads(raw) if raw and raw != "[]" else []
            base_id = len(static_findings)
            for i, item in enumerate(parsed):
                ai_findings.append(Finding(
                    id=f"AI-{base_id + i + 1:04d}",
                    title=item.get("title", "AI-detected issue"),
                    severity=Severity(item.get("severity", "MEDIUM")),
                    description=item.get("description", ""),
                    file_path=item.get("file_path", "unknown"),
                    line_hint=item.get("line_hint"),
                    recommendation=item.get("recommendation", ""),
                    cwe_id=item.get("cwe_id"),
                ))
        except Exception:
            pass

    all_findings = static_findings + ai_findings
    all_findings = [f for f in all_findings if f.severity != Severity.INFO]
    duration_ms = (time.time() - start) * 1000

    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    parts = []
    if severity_counts.get("CRITICAL", 0): parts.append(f"{severity_counts['CRITICAL']} critical")
    if severity_counts.get("HIGH", 0): parts.append(f"{severity_counts['HIGH']} high")
    if severity_counts.get("MEDIUM", 0): parts.append(f"{severity_counts['MEDIUM']} medium")
    total = len(all_findings)
    summary = f"Found {total} issue(s): {', '.join(parts)}." if total else "No security issues detected."

    return AuditReport(
        summary=summary,
        findings=all_findings,
        stats={
            "total_findings": total,
            "by_severity": severity_counts,
            "files_analyzed": len(code_files),
            "files_scanned": sum(1 for f in code_files if not is_test_file(f) and not is_config_or_build(f)),
            "total_lines": sum(len(c.split("\n")) for c in code_files.values()),
            "static_findings": len(static_findings),
            "ai_findings": len(ai_findings),
            "languages": lang_counts,
        },
        analysis_duration_ms=round(duration_ms, 2),
        eigenai_model=model_used,
        deterministic_seed=seed_used,
    )
