"""
BlindGuard — Security Analyzer v2
Language-aware security analysis for crypto/web3 ecosystem.
Supports: Solidity, Rust, Cairo, Move, Python, JavaScript/TypeScript, Go, Vyper
Runs inside TEE using EigenAI for deterministic inference.
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


# ─── Language detection ──────────────────────────────────────────────────────

def detect_language(filepath: str) -> str:
    ext_map = {
        ".sol": "solidity",
        ".vy": "vyper",
        ".rs": "rust",
        ".cairo": "cairo",
        ".move": "move",
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".java": "java",
        ".cs": "csharp",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
    }
    for ext, lang in ext_map.items():
        if filepath.endswith(ext):
            return lang
    return "unknown"


# ─── Universal patterns (all languages) ─────────────────────────────────────

UNIVERSAL_PATTERNS = [
    {
        "id": "HARDCODED_SECRET",
        "patterns": [
            r"""(?i)(api[_-]?key|secret[_-]?key|password|auth[_-]?token|private[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]""",
            r"""(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"][^'\"]+['\"]""",
            r"""(?i)(PRIVATE_KEY|MNEMONIC|SEED_PHRASE|INFURA_KEY|ALCHEMY_KEY)\s*[=:]\s*['\"][^'\"]+['\"]""",
            r"""(?i)(0x[a-fA-F0-9]{64})\s*[;,]?\s*(?://|#|/\*).*(?:private|secret|key)""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Secret/Credential",
        "description": "A secret, API key, or private key is hardcoded in the source code. If this code is committed to a repository or deployed, the secret is exposed.",
        "cwe": "CWE-798",
        "recommendation": "Use environment variables, a secrets manager, or a .env file (excluded from version control).",
    },
    {
        "id": "HARDCODED_IP",
        "patterns": [
            r"""(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!.*(?:127\.0\.0\.1|0\.0\.0\.0|localhost))""",
        ],
        "severity": Severity.LOW,
        "title": "Hardcoded IP Address",
        "description": "A non-localhost IP address is hardcoded. This makes the code environment-dependent and harder to maintain.",
        "cwe": "CWE-547",
        "recommendation": "Use configuration files or environment variables for network addresses.",
    },
]

# ─── Solidity patterns ───────────────────────────────────────────────────────

SOLIDITY_PATTERNS = [
    {
        "id": "SOL_REENTRANCY",
        "patterns": [
            r"""\.call\{.*value\s*:""",
            r"""\.call\.value\s*\(""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Potential Reentrancy Vulnerability",
        "description": "An external call with value transfer was detected. If state changes happen after this call, an attacker contract could re-enter and drain funds.",
        "cwe": "CWE-841",
        "recommendation": "Apply the checks-effects-interactions pattern: update state before making external calls. Use OpenZeppelin's ReentrancyGuard.",
    },
    {
        "id": "SOL_TX_ORIGIN",
        "patterns": [
            r"""tx\.origin""",
        ],
        "severity": Severity.HIGH,
        "title": "Use of tx.origin for Authorization",
        "description": "tx.origin returns the original sender of a transaction, not the immediate caller. A malicious contract can trick a user into calling it, inheriting the user's tx.origin.",
        "cwe": "CWE-284",
        "recommendation": "Use msg.sender instead of tx.origin for all authorization checks.",
    },
    {
        "id": "SOL_UNCHECKED_CALL",
        "patterns": [
            r"""\.call\(.*\)\s*;(?!\s*(?:require|if|assert|bool))""",
            r"""\.send\(.*\)\s*;(?!\s*(?:require|if|assert))""",
        ],
        "severity": Severity.HIGH,
        "title": "Unchecked External Call Return Value",
        "description": "The return value of an external call or send is not checked. If the call fails silently, funds could be lost or contract state corrupted.",
        "cwe": "CWE-252",
        "recommendation": "Always check the return value: (bool success, ) = addr.call{value: amount}(''); require(success);",
    },
    {
        "id": "SOL_DELEGATECALL",
        "patterns": [
            r"""\.delegatecall\(""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Use of delegatecall",
        "description": "delegatecall executes code from another contract in the context of the calling contract. If the target is user-controlled, an attacker can overwrite storage or steal funds.",
        "cwe": "CWE-829",
        "recommendation": "Only delegatecall to trusted, immutable contracts. Never allow user input to determine the delegatecall target.",
    },
    {
        "id": "SOL_SELFDESTRUCT",
        "patterns": [
            r"""selfdestruct\s*\(""",
        ],
        "severity": Severity.HIGH,
        "title": "Use of selfdestruct",
        "description": "selfdestruct permanently destroys the contract and sends remaining ETH to a specified address. If access control is missing, anyone could destroy the contract.",
        "cwe": "CWE-284",
        "recommendation": "Remove selfdestruct if not needed. If required, protect with strict access control (onlyOwner with multi-sig).",
    },
    {
        "id": "SOL_TIMESTAMP_DEPEND",
        "patterns": [
            r"""block\.timestamp""",
            r"""block\.number""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Block Timestamp/Number Dependency",
        "description": "Using block.timestamp or block.number for critical logic (randomness, deadlines) can be manipulated by miners within a ~15 second window.",
        "cwe": "CWE-330",
        "recommendation": "Do not use block.timestamp for randomness. For deadlines, allow a margin of error. Consider using Chainlink VRF for randomness.",
    },
    {
        "id": "SOL_OVERFLOW",
        "patterns": [
            r"""pragma\s+solidity\s+[\^~]?0\.[0-6]\.""",
        ],
        "severity": Severity.HIGH,
        "title": "Integer Overflow/Underflow Risk (Solidity < 0.8)",
        "description": "Solidity versions before 0.8.0 do not have built-in overflow checks. Arithmetic operations can silently wrap around.",
        "cwe": "CWE-190",
        "recommendation": "Upgrade to Solidity 0.8+ which has built-in overflow checks, or use SafeMath library.",
    },
    {
        "id": "SOL_UNPROTECTED_INIT",
        "patterns": [
            r"""function\s+initialize\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:initializer|onlyOwner))""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Unprotected Initializer",
        "description": "An initialize function is publicly accessible without an initializer modifier. An attacker could call it to take ownership of the contract.",
        "cwe": "CWE-284",
        "recommendation": "Use OpenZeppelin's initializer modifier or add access control to initialization functions.",
    },
    {
        "id": "SOL_MISSING_ACCESS",
        "patterns": [
            r"""function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s*(?!view|pure|override|virtual|returns|onlyOwner|onlyRole|require|_only)""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Potentially Unprotected Public Function",
        "description": "A public/external function appears to lack access control modifiers. If this function modifies state, it may be callable by anyone.",
        "cwe": "CWE-284",
        "recommendation": "Add appropriate access control (onlyOwner, onlyRole, or custom modifiers) to state-changing functions.",
    },
    {
        "id": "SOL_FRONT_RUNNING",
        "patterns": [
            r"""function\s+(?:swap|trade|buy|sell|mint|claim|deposit)\s*\(""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Potential Front-Running Vulnerability",
        "description": "Functions involving token swaps, trades, or mints can be front-run by MEV bots who observe pending transactions and insert their own transactions ahead.",
        "cwe": "CWE-362",
        "recommendation": "Implement slippage protection, commit-reveal schemes, or use Flashbots/MEV protection.",
    },
    {
        "id": "SOL_UNSAFE_APPROVE",
        "patterns": [
            r"""\.approve\s*\([^,]+,\s*type\(uint256\)\.max""",
            r"""\.approve\s*\([^,]+,\s*2\*\*256""",
            r"""\.approve\s*\([^,]+,\s*uint256\(-1\)""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Unlimited Token Approval",
        "description": "Approving the maximum uint256 amount gives a spender unlimited access to the user's tokens. If the spender contract is compromised, all tokens can be drained.",
        "cwe": "CWE-732",
        "recommendation": "Approve only the specific amount needed for each transaction. Consider implementing increaseAllowance/decreaseAllowance.",
    },
]

# ─── Vyper patterns ──────────────────────────────────────────────────────────

VYPER_PATTERNS = [
    {
        "id": "VY_RAW_CALL",
        "patterns": [
            r"""raw_call\s*\(""",
        ],
        "severity": Severity.HIGH,
        "title": "Use of raw_call",
        "description": "raw_call performs a low-level external call. Return values must be checked and reentrancy must be considered.",
        "cwe": "CWE-841",
        "recommendation": "Check raw_call return values. Use @nonreentrant decorator to prevent reentrancy.",
    },
    {
        "id": "VY_SEND",
        "patterns": [
            r"""send\s*\(""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Use of send for ETH Transfer",
        "description": "send has a 2300 gas stipend and returns False on failure. If the return value is unchecked, ETH transfers can silently fail.",
        "cwe": "CWE-252",
        "recommendation": "Check the return value of send, or use raw_call with appropriate gas.",
    },
    {
        "id": "VY_NO_REENTRANCY",
        "patterns": [
            r"""@external\s*\n(?:(?!@nonreentrant)[\s\S])*?(?:raw_call|send)\s*\(""",
        ],
        "severity": Severity.HIGH,
        "title": "External Function Without Reentrancy Guard",
        "description": "An external function making an external call does not have a @nonreentrant decorator.",
        "cwe": "CWE-841",
        "recommendation": "Add @nonreentrant('lock') decorator to external functions that make external calls.",
    },
]

# ─── Rust (Solana/Anchor/Substrate) patterns ─────────────────────────────────

RUST_PATTERNS = [
    {
        "id": "RS_UNSAFE",
        "patterns": [
            r"""unsafe\s*\{""",
        ],
        "severity": Severity.HIGH,
        "title": "Use of unsafe Block",
        "description": "Unsafe blocks bypass Rust's safety guarantees. Memory corruption, undefined behavior, and security vulnerabilities become possible.",
        "cwe": "CWE-676",
        "recommendation": "Minimize unsafe usage. Document why each unsafe block is necessary and what invariants must be maintained.",
    },
    {
        "id": "RS_UNWRAP",
        "patterns": [
            r"""\.unwrap\(\)""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Use of unwrap() Without Error Handling",
        "description": "unwrap() panics on None/Err values. In on-chain programs, this can cause transaction failures or denial of service.",
        "cwe": "CWE-755",
        "recommendation": "Use proper error handling with match, if let, or the ? operator instead of unwrap().",
    },
    {
        "id": "RS_MISSING_SIGNER",
        "patterns": [
            r"""pub\s+fn\s+\w+\s*\([^)]*ctx\s*:\s*Context<[^>]+>[^)]*\)(?:(?!require_keys_eq|has_one|constraint|signer)[\s\S])*?\{""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential Missing Signer Check (Anchor)",
        "description": "An Anchor instruction handler may lack proper signer validation. Without signer checks, unauthorized accounts can execute privileged operations.",
        "cwe": "CWE-284",
        "recommendation": "Use Anchor account constraints: #[account(signer)] or add explicit signer validation.",
    },
    {
        "id": "RS_OVERFLOW",
        "patterns": [
            r"""(?:checked_add|checked_sub|checked_mul|checked_div)""",
        ],
        "severity": Severity.INFO,
        "title": "Checked Arithmetic Used (Good Practice)",
        "description": "The code uses checked arithmetic operations, which is good practice for preventing overflow/underflow.",
        "cwe": None,
        "recommendation": "Continue using checked arithmetic throughout the codebase.",
    },
    {
        "id": "RS_UNCHECKED_MATH",
        "patterns": [
            r"""\.overflowing_(?:add|sub|mul)""",
            r"""\.wrapping_(?:add|sub|mul)""",
        ],
        "severity": Severity.HIGH,
        "title": "Unchecked/Wrapping Arithmetic",
        "description": "Wrapping or overflowing arithmetic is used. In financial calculations, this can lead to incorrect token amounts or fund loss.",
        "cwe": "CWE-190",
        "recommendation": "Use checked_add/checked_sub/checked_mul for financial calculations. Handle overflow errors explicitly.",
    },
    {
        "id": "RS_ACCOUNT_CONFUSION",
        "patterns": [
            r"""AccountInfo""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Raw AccountInfo Usage (Solana)",
        "description": "Using raw AccountInfo without proper type checking can lead to account confusion attacks where an attacker passes a different account type.",
        "cwe": "CWE-843",
        "recommendation": "Use Anchor's typed accounts or manually verify account discriminators and owners.",
    },
]

# ─── Cairo (StarkNet) patterns ───────────────────────────────────────────────

CAIRO_PATTERNS = [
    {
        "id": "CAIRO_ASSERT",
        "patterns": [
            r"""assert\s*\(""",
            r"""assert_nn\s*\(""",
        ],
        "severity": Severity.INFO,
        "title": "Assertion Used",
        "description": "Cairo assertions halt execution on failure. Ensure assertions cover all critical invariants.",
        "cwe": None,
        "recommendation": "Verify that assertions cover all edge cases, especially around arithmetic bounds.",
    },
    {
        "id": "CAIRO_FELT_OVERFLOW",
        "patterns": [
            r"""felt252""",
        ],
        "severity": Severity.MEDIUM,
        "title": "felt252 Arithmetic (Overflow Risk)",
        "description": "felt252 arithmetic wraps modulo a large prime. Operations that overflow can produce unexpected results in financial calculations.",
        "cwe": "CWE-190",
        "recommendation": "Use u256 or bounded integer types for financial calculations. Add range checks after arithmetic operations.",
    },
    {
        "id": "CAIRO_STORAGE_ACCESS",
        "patterns": [
            r"""storage_read\s*\(""",
            r"""storage_write\s*\(""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Direct Storage Access",
        "description": "Direct storage read/write bypasses higher-level access control abstractions and can lead to state corruption.",
        "cwe": "CWE-284",
        "recommendation": "Use typed storage variables with proper access control instead of raw storage operations.",
    },
    {
        "id": "CAIRO_MISSING_ACCESS",
        "patterns": [
            r"""#\[external\(v0\)\]\s*fn\s+\w+\s*\((?!.*self:\s*@ContractState)""",
        ],
        "severity": Severity.HIGH,
        "title": "External Function Without Access Control",
        "description": "A StarkNet external function may lack proper access control. Any user can call external functions.",
        "cwe": "CWE-284",
        "recommendation": "Add access control using OpenZeppelin's Ownable or AccessControl components.",
    },
]

# ─── Move (Aptos/Sui) patterns ───────────────────────────────────────────────

MOVE_PATTERNS = [
    {
        "id": "MOVE_PUBLIC_ENTRY",
        "patterns": [
            r"""public\s+entry\s+fun\s+\w+""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Public Entry Function",
        "description": "Public entry functions can be called by any user. Ensure proper capability/signer checks are in place.",
        "cwe": "CWE-284",
        "recommendation": "Verify that signer capabilities are checked. Use capability-based access control.",
    },
    {
        "id": "MOVE_UNCHECKED_ABORT",
        "patterns": [
            r"""abort\s+\d+""",
        ],
        "severity": Severity.LOW,
        "title": "Numeric Abort Code",
        "description": "Using numeric abort codes makes debugging harder. Named error constants improve maintainability.",
        "cwe": None,
        "recommendation": "Define named error constants instead of using raw numeric abort codes.",
    },
    {
        "id": "MOVE_COIN_TRANSFER",
        "patterns": [
            r"""coin::transfer""",
            r"""transfer::public_transfer""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Token Transfer Operation",
        "description": "Token transfer detected. Ensure proper authorization and amount validation before transfers.",
        "cwe": "CWE-284",
        "recommendation": "Validate signer authority and transfer amounts. Check for overflow in amount calculations.",
    },
]

# ─── Python patterns ─────────────────────────────────────────────────────────

PYTHON_PATTERNS = [
    {
        "id": "PY_SQL_INJECTION",
        "patterns": [
            r"""(?:execute|cursor\.execute)\s*\(\s*f?['\"].*\{.*\}""",
            r"""(?:execute|cursor\.execute)\s*\(\s*['\"].*%[sd]""",
            r"""query\s*=\s*f?['\"].*SELECT.*\{""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential SQL Injection",
        "description": "User input appears to be interpolated directly into an SQL query using f-strings or % formatting. This allows attackers to modify the query.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    {
        "id": "PY_CMD_INJECTION",
        "patterns": [
            r"""os\.system\s*\(""",
            r"""subprocess\.call\s*\(.*shell\s*=\s*True""",
            r"""subprocess\.Popen\s*\(.*shell\s*=\s*True""",
            r"""os\.popen\s*\(""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Potential Command Injection",
        "description": "Shell command execution detected. If user input reaches these functions, an attacker can execute arbitrary system commands.",
        "cwe": "CWE-78",
        "recommendation": "Use subprocess.run() with shell=False and pass arguments as a list: subprocess.run(['ls', '-la', directory])",
    },
    {
        "id": "PY_PICKLE",
        "patterns": [
            r"""pickle\.loads?\s*\(""",
            r"""yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)""",
        ],
        "severity": Severity.HIGH,
        "title": "Insecure Deserialization",
        "description": "Deserializing untrusted data with pickle or yaml.load can execute arbitrary code. An attacker can craft payloads that run malicious commands.",
        "cwe": "CWE-502",
        "recommendation": "Use yaml.safe_load() instead of yaml.load(). Avoid pickle for untrusted data; use JSON instead.",
    },
    {
        "id": "PY_EVAL",
        "patterns": [
            r"""\beval\s*\(""",
            r"""\bexec\s*\(""",
        ],
        "severity": Severity.HIGH,
        "title": "Use of eval/exec",
        "description": "eval() and exec() execute arbitrary Python code. If user input reaches these functions, full system compromise is possible.",
        "cwe": "CWE-95",
        "recommendation": "Use ast.literal_eval() for safe evaluation of literals. Avoid eval/exec entirely if possible.",
    },
    {
        "id": "PY_WEAK_CRYPTO",
        "patterns": [
            r"""hashlib\.md5\s*\(""",
            r"""hashlib\.sha1\s*\(""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Weak Cryptographic Hash",
        "description": "MD5 and SHA1 are cryptographically broken. Collisions can be generated, making them unsuitable for security purposes.",
        "cwe": "CWE-328",
        "recommendation": "Use hashlib.sha256() or hashlib.sha3_256() for cryptographic hashing. Use bcrypt/scrypt/argon2 for passwords.",
    },
    {
        "id": "PY_DEBUG",
        "patterns": [
            r"""(?i)DEBUG\s*=\s*True""",
            r"""app\.run\s*\(.*debug\s*=\s*True""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Debug Mode Enabled",
        "description": "Debug mode exposes detailed error messages, stack traces, and potentially an interactive debugger to users.",
        "cwe": "CWE-489",
        "recommendation": "Set DEBUG=False in production. Use environment variables to control debug mode.",
    },
    {
        "id": "PY_OPEN_REDIRECT",
        "patterns": [
            r"""redirect\s*\(\s*request\.(args|form|params)""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Potential Open Redirect",
        "description": "Redirecting to a user-controlled URL can be exploited for phishing attacks.",
        "cwe": "CWE-601",
        "recommendation": "Validate redirect URLs against an allowlist of trusted domains.",
    },
]

# ─── JavaScript/TypeScript patterns ──────────────────────────────────────────

JS_PATTERNS = [
    {
        "id": "JS_XSS",
        "patterns": [
            r"""\.innerHTML\s*=""",
            r"""document\.write\s*\(""",
            r"""dangerouslySetInnerHTML""",
            r"""v-html\s*=""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential Cross-Site Scripting (XSS)",
        "description": "Setting innerHTML or using document.write with user input allows attackers to inject malicious scripts that steal cookies or hijack sessions.",
        "cwe": "CWE-79",
        "recommendation": "Use textContent instead of innerHTML. In React, avoid dangerouslySetInnerHTML. Sanitize with DOMPurify if HTML rendering is required.",
    },
    {
        "id": "JS_EVAL",
        "patterns": [
            r"""\beval\s*\(""",
            r"""new\s+Function\s*\(""",
            r"""setTimeout\s*\(\s*['"]""",
            r"""setInterval\s*\(\s*['"]""",
        ],
        "severity": Severity.HIGH,
        "title": "Code Injection via eval/Function",
        "description": "eval(), new Function(), and string-based setTimeout/setInterval execute arbitrary code. User input in these functions leads to full compromise.",
        "cwe": "CWE-95",
        "recommendation": "Never pass user input to eval or Function constructors. Use JSON.parse() for data parsing.",
    },
    {
        "id": "JS_CMD_INJECTION",
        "patterns": [
            r"""child_process\.(exec|execSync)\s*\(.*\+""",
            r"""child_process\.(exec|execSync)\s*\(.*\$\{""",
            r"""child_process\.(exec|execSync)\s*\(.*req\.""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Command Injection",
        "description": "User input is concatenated into a shell command. Attackers can inject additional commands using ; or && operators.",
        "cwe": "CWE-78",
        "recommendation": "Use child_process.execFile() or spawn() with arguments as an array, never as a concatenated string.",
    },
    {
        "id": "JS_WEAK_CRYPTO",
        "patterns": [
            r"""createHash\s*\(\s*['"]md5['"]\)""",
            r"""createHash\s*\(\s*['"]sha1['"]\)""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Weak Cryptographic Hash",
        "description": "MD5 and SHA1 are cryptographically broken and should not be used for security-sensitive operations.",
        "cwe": "CWE-328",
        "recommendation": "Use crypto.createHash('sha256') or crypto.createHash('sha3-256').",
    },
    {
        "id": "JS_SENSITIVE_LOG",
        "patterns": [
            r"""console\.log\s*\(.*(?:password|secret|token|private_key|mnemonic)""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Sensitive Data in Console Log",
        "description": "Logging sensitive data (passwords, tokens, keys) exposes it in browser consoles, log files, and monitoring systems.",
        "cwe": "CWE-532",
        "recommendation": "Remove console.log statements containing sensitive data. Use a proper logging library with data masking.",
    },
    {
        "id": "JS_PROTOTYPE_POLLUTION",
        "patterns": [
            r"""Object\.assign\s*\(\s*\{\}.*req\.""",
            r"""\[['"]__proto__['"]\]""",
            r"""\.constructor\.prototype""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential Prototype Pollution",
        "description": "Merging user input into objects without sanitization can modify Object.prototype, affecting all objects in the application.",
        "cwe": "CWE-1321",
        "recommendation": "Validate and sanitize user input. Use Object.create(null) for dictionaries. Consider using Map instead of plain objects.",
    },
    {
        "id": "JS_PRIVATE_KEY_MEMORY",
        "patterns": [
            r"""(?:privateKey|private_key|secretKey|secret_key)\s*=\s*""",
            r"""ethers\.Wallet\s*\(\s*['"]0x""",
            r"""web3\.eth\.accounts\.privateKeyToAccount\s*\(""",
        ],
        "severity": Severity.HIGH,
        "title": "Private Key Handling in Code",
        "description": "Private keys are being handled directly in code. Keys in memory can be extracted via memory dumps or debugging.",
        "cwe": "CWE-312",
        "recommendation": "Use hardware wallets, KMS, or secure enclaves for key management. Never store private keys in source code.",
    },
]

# ─── Go patterns ─────────────────────────────────────────────────────────────

GO_PATTERNS = [
    {
        "id": "GO_SQL_INJECTION",
        "patterns": [
            r"""fmt\.Sprintf\s*\(\s*['"]\s*SELECT""",
            r"""db\.(?:Query|Exec)\s*\(\s*.*\+""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential SQL Injection",
        "description": "SQL queries are built using string formatting or concatenation. User input can modify the query structure.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries: db.Query('SELECT * FROM users WHERE id = $1', userID)",
    },
    {
        "id": "GO_CMD_INJECTION",
        "patterns": [
            r"""exec\.Command\s*\(\s*['"](?:sh|bash|cmd)['"]\s*,\s*['"]-c['"]""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Potential Command Injection",
        "description": "Using exec.Command with a shell interpreter and -c flag allows command injection if user input is included.",
        "cwe": "CWE-78",
        "recommendation": "Call the program directly without a shell: exec.Command('ls', '-la', dir) instead of exec.Command('sh', '-c', 'ls -la '+dir)",
    },
    {
        "id": "GO_UNHANDLED_ERR",
        "patterns": [
            r"""[^_]\s*,\s*_\s*:?=\s*\w+\.\w+\(""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Unhandled Error",
        "description": "An error return value is being discarded with _. Unhandled errors can lead to silent failures and security issues.",
        "cwe": "CWE-755",
        "recommendation": "Always handle errors: if err != nil { return err }",
    },
]

# ─── Map languages to their specific patterns ────────────────────────────────

LANGUAGE_PATTERNS = {
    "solidity": SOLIDITY_PATTERNS,
    "vyper": VYPER_PATTERNS,
    "rust": RUST_PATTERNS,
    "cairo": CAIRO_PATTERNS,
    "move": MOVE_PATTERNS,
    "python": PYTHON_PATTERNS,
    "javascript": JS_PATTERNS,
    "typescript": JS_PATTERNS,
    "go": GO_PATTERNS,
}


# ─── Analysis engine ─────────────────────────────────────────────────────────

def run_static_analysis(code_files: dict[str, str]) -> list[Finding]:
    """
    Run language-aware static analysis on code files.
    Each file is analyzed with universal patterns + language-specific patterns.
    """
    findings = []
    finding_counter = 0

    for filepath, content in code_files.items():
        lang = detect_language(filepath)
        lines = content.split("\n")

        # Get applicable patterns
        applicable = list(UNIVERSAL_PATTERNS)
        if lang in LANGUAGE_PATTERNS:
            applicable.extend(LANGUAGE_PATTERNS[lang])

        for vuln in applicable:
            for pattern in vuln["patterns"]:
                for line_num, line in enumerate(lines, 1):
                    # Skip comment lines
                    stripped = line.strip()
                    if lang in ("python",) and stripped.startswith("#"):
                        continue
                    if lang in ("solidity", "rust", "javascript", "typescript", "go", "java", "c", "cpp", "csharp", "cairo", "move") and stripped.startswith("//"):
                        continue

                    if re.search(pattern, line):
                        finding_counter += 1
                        findings.append(Finding(
                            id=f"SG-{finding_counter:04d}",
                            title=vuln["title"],
                            severity=vuln["severity"],
                            description=vuln["description"],
                            file_path=filepath,
                            line_hint=f"Line {line_num}",
                            recommendation=vuln["recommendation"],
                            cwe_id=vuln.get("cwe"),
                        ))

    # Deduplicate: same title + same file + same line = keep only one
    seen = set()
    deduped = []
    for f in findings:
        key = (f.title, f.file_path, f.line_hint)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def build_eigenai_prompt(code_files: dict[str, str], static_findings: list[Finding]) -> str:
    """Build the prompt for EigenAI security analysis."""
    code_section = ""
    for path, content in sorted(code_files.items()):
        lang = detect_language(path)
        truncated = content[:5000] + ("\n... [truncated]" if len(content) > 5000 else "")
        code_section += f"\n### File: {path} (language: {lang})\n```\n{truncated}\n```\n"

    static_section = ""
    if static_findings:
        static_section = "\n## Pre-detected Issues (static analysis)\n"
        for f in static_findings:
            static_section += f"- [{f.severity.value}] {f.title} in {f.file_path} ({f.line_hint})\n"

    return f"""You are a senior security auditor specializing in blockchain and web3 applications.
Analyze the following code for security vulnerabilities.
Focus on: reentrancy, access control, overflow/underflow, front-running, injection flaws,
cryptographic weaknesses, key management, and logic bugs.

{static_section}

## Code Under Review
{code_section}

Respond with a JSON array of findings. Each finding must have:
- "title": short description
- "severity": one of CRITICAL, HIGH, MEDIUM, LOW, INFO
- "description": detailed explanation
- "file_path": which file
- "line_hint": approximate location
- "recommendation": how to fix
- "cwe_id": CWE identifier if applicable

Only return the JSON array, no other text. If no additional issues found beyond static analysis, return [].
"""


def call_eigenai(prompt: str, model: str = "gpt-oss-120b-f16", seed: int = 42) -> str:
    """Call EigenAI for deterministic inference."""
    eigenai_url = os.environ.get("EIGENAI_API_URL", "")
    eigenai_key = os.environ.get("EIGENAI_API_KEY", "")

    if eigenai_url and eigenai_key:
        import urllib.request
        req_body = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "seed": seed,
            "temperature": 0,
            "max_tokens": 4000,
        })
        req = urllib.request.Request(
            eigenai_url,
            data=req_body.encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {eigenai_key}",
            },
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]
    else:
        return "[]"


def analyze(code_files: dict[str, str], use_eigenai: bool = True) -> AuditReport:
    """
    Main analysis entry point.
    1. Detect languages
    2. Run language-aware static analysis
    3. Optionally run EigenAI deep analysis
    4. Merge and deduplicate results
    """
    start = time.time()

    # Language stats
    lang_counts = {}
    for filepath in code_files:
        lang = detect_language(filepath)
        lang_counts[lang] = lang_counts.get(lang, 0) + 1

    # Step 1: Static analysis
    static_findings = run_static_analysis(code_files)

    # Step 2: EigenAI deep analysis
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
        except Exception as e:
            ai_findings.append(Finding(
                id="AI-ERR",
                title="EigenAI analysis note",
                severity=Severity.INFO,
                description=f"AI analysis returned non-parseable output: {str(e)[:200]}",
                file_path="N/A",
                recommendation="Review static analysis findings. AI analysis can be retried.",
            ))

    # Merge
    all_findings = static_findings + ai_findings
    duration_ms = (time.time() - start) * 1000

    # Stats
    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    summary_parts = []
    if severity_counts.get("CRITICAL", 0):
        summary_parts.append(f"{severity_counts['CRITICAL']} critical")
    if severity_counts.get("HIGH", 0):
        summary_parts.append(f"{severity_counts['HIGH']} high")
    if severity_counts.get("MEDIUM", 0):
        summary_parts.append(f"{severity_counts['MEDIUM']} medium")
    total = len(all_findings)
    summary = f"Found {total} issue(s): {', '.join(summary_parts) or 'no critical/high issues'}."

    return AuditReport(
        summary=summary,
        findings=all_findings,
        stats={
            "total_findings": total,
            "by_severity": severity_counts,
            "files_analyzed": len(code_files),
            "total_lines": sum(len(c.split("\n")) for c in code_files.values()),
            "static_findings": len(static_findings),
            "ai_findings": len(ai_findings),
            "languages": lang_counts,
        },
        analysis_duration_ms=round(duration_ms, 2),
        eigenai_model=model_used,
        deterministic_seed=seed_used,
    )
