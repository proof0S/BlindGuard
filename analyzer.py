"""
BlindGuard — Security Analyzer
Runs code analysis inside TEE using EigenAI for deterministic inference.
Private inputs stay in the container; only the report exits.
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


# ─── Built-in static analysis patterns (runs WITHOUT LLM) ─────────────────────

VULN_PATTERNS = {
    "HARDCODED_SECRET": {
        "patterns": [
            r"""(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]""",
            r"""(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"][^'\"]+['\"]""",
            r"""(?i)(PRIVATE_KEY|MNEMONIC|SEED_PHRASE)\s*[=:]\s*['\"][^'\"]+['\"]""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Secret/Credential",
        "cwe": "CWE-798",
        "recommendation": "Use environment variables or a secrets manager.",
    },
    "SQL_INJECTION": {
        "patterns": [
            r"""(?i)(execute|cursor\.execute|raw\s*\()\s*.*(%s|format|f['\"]).*""",
            r"""(?i)query\s*=\s*f?['\"].*\{.*\}.*['\"]""",
            r"""(?i)query\s*[=+].*\+.*req\.|query\s*[=+].*\+.*request\.""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential SQL Injection",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries instead of string formatting.",
    },
    "COMMAND_INJECTION": {
        "patterns": [
            r"""(?i)(os\.system|subprocess\.call|subprocess\.Popen|os\.popen)\s*\(.*\+.*\)""",
            r"""(?i)(os\.system|subprocess\.call)\s*\(.*f['\"]""",
            r"""(?i)child_process\.(exec|spawn)\s*\(.*\+""",
            r"""(?i)child_process\.(exec|spawn)\s*\(.*\$\{""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Potential Command Injection",
        "cwe": "CWE-78",
        "recommendation": "Use subprocess with shell=False and list arguments. In JS, avoid child_process.exec with user input.",
    },
    "INSECURE_DESERIALIZATION": {
        "patterns": [
            r"""(?i)pickle\.loads?\(""",
            r"""(?i)yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)""",
            r"""(?i)JSON\.parse\s*\(\s*req\.""",
            r"""(?i)unserialize\s*\(""",
        ],
        "severity": Severity.HIGH,
        "title": "Insecure Deserialization",
        "cwe": "CWE-502",
        "recommendation": "Use safe deserialization (yaml.safe_load, avoid pickle on untrusted data).",
    },
    "EVAL_USAGE": {
        "patterns": [
            r"""(?i)\beval\s*\(""",
            r"""(?i)\bexec\s*\(""",
            r"""(?i)new\s+Function\s*\(""",
            r"""(?i)setTimeout\s*\(\s*['\"]""",
            r"""(?i)setInterval\s*\(\s*['\"]""",
        ],
        "severity": Severity.HIGH,
        "title": "Use of eval/exec",
        "cwe": "CWE-95",
        "recommendation": "Avoid eval/exec on user-controllable input. Use ast.literal_eval if needed.",
    },
    "WEAK_CRYPTO": {
        "patterns": [
            r"""(?i)(md5|sha1)\s*\(""",
            r"""(?i)hashlib\.(md5|sha1)\s*\(""",
            r"""(?i)createHash\s*\(\s*['\"]md5['\"]""",
            r"""(?i)createHash\s*\(\s*['\"]sha1['\"]""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Weak Cryptographic Hash",
        "cwe": "CWE-328",
        "recommendation": "Use SHA-256 or stronger hashing algorithms.",
    },
    "DEBUG_ENABLED": {
        "patterns": [
            r"""(?i)DEBUG\s*=\s*True""",
            r"""(?i)app\.run\s*\(.*debug\s*=\s*True""",
            r"""(?i)console\.log\s*\(.*password|console\.log\s*\(.*secret|console\.log\s*\(.*token""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Debug Mode Enabled",
        "cwe": "CWE-489",
        "recommendation": "Disable debug mode in production. Remove sensitive data from logs.",
    },
    "OPEN_REDIRECT": {
        "patterns": [
            r"""(?i)redirect\s*\(\s*request\.(args|form|params)""",
            r"""(?i)res\.redirect\s*\(\s*req\.(query|body|params)""",
            r"""(?i)window\.location\s*=\s*.*\burl\b""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Potential Open Redirect",
        "cwe": "CWE-601",
        "recommendation": "Validate redirect URLs against an allowlist.",
    },
    "XSS": {
        "patterns": [
            r"""(?i)innerHTML\s*=\s*.*req\.|innerHTML\s*=\s*.*request\.""",
            r"""(?i)document\.write\s*\(""",
            r"""(?i)\.html\s*\(\s*req\.|\.html\s*\(\s*request\.""",
            r"""(?i)dangerouslySetInnerHTML""",
            r"""(?i)v-html\s*=""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "recommendation": "Sanitize user input before rendering. Use textContent instead of innerHTML.",
    },
    "PATH_TRAVERSAL": {
        "patterns": [
            r"""(?i)(open|readFile|readFileSync|createReadStream)\s*\(.*\+.*req\.""",
            r"""(?i)(open|readFile|readFileSync|createReadStream)\s*\(.*\$\{.*req\.""",
            r"""(?i)\.\.\/|\.\.\\""",
        ],
        "severity": Severity.HIGH,
        "title": "Potential Path Traversal",
        "cwe": "CWE-22",
        "recommendation": "Validate and sanitize file paths. Use path.resolve and check against a base directory.",
    },
    "HARDCODED_IP_URL": {
        "patterns": [
            r"""(?i)(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
            r"""(?i)(https?://localhost)""",
        ],
        "severity": Severity.LOW,
        "title": "Hardcoded IP/URL",
        "cwe": "CWE-547",
        "recommendation": "Use configuration files or environment variables for URLs and IPs.",
    },
    "REENTRANCY": {
        "patterns": [
            r"""(?i)\.call\{value:""",
            r"""(?i)\.call\.value\(""",
            r"""(?i)\.send\(|\.transfer\(""",
        ],
        "severity": Severity.CRITICAL,
        "title": "Potential Reentrancy Vulnerability",
        "cwe": "CWE-841",
        "recommendation": "Use checks-effects-interactions pattern. Consider using ReentrancyGuard.",
    },
    "UNCHECKED_RETURN": {
        "patterns": [
            r"""(?i)\.call\(.*\)\s*;(?!\s*require)""",
            r"""(?i)\.send\(.*\)\s*;(?!\s*(require|if))""",
        ],
        "severity": Severity.HIGH,
        "title": "Unchecked Return Value",
        "cwe": "CWE-252",
        "recommendation": "Always check return values of external calls. Use require() in Solidity.",
    },
    "TX_ORIGIN": {
        "patterns": [
            r"""(?i)tx\.origin""",
        ],
        "severity": Severity.HIGH,
        "title": "Use of tx.origin for Authorization",
        "cwe": "CWE-284",
        "recommendation": "Use msg.sender instead of tx.origin for authorization checks.",
    },
    "UNSAFE_REGEX": {
        "patterns": [
            r"""(?i)new\s+RegExp\s*\(\s*(req\.|request\.|user)""",
        ],
        "severity": Severity.MEDIUM,
        "title": "Unsafe Regular Expression",
        "cwe": "CWE-1333",
        "recommendation": "Avoid constructing regex from user input. Can cause ReDoS attacks.",
    },
}


def run_static_analysis(code_files: dict[str, str]) -> list[Finding]:
    """
    Run pattern-based static analysis on code files.
    This runs entirely inside the TEE with no external calls.
    """
    findings = []
    finding_counter = 0

    for filepath, content in code_files.items():
        lines = content.split("\n")
        for vuln_id, vuln_info in VULN_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        finding_counter += 1
                        findings.append(Finding(
                            id=f"SG-{finding_counter:04d}",
                            title=vuln_info["title"],
                            severity=vuln_info["severity"],
                            description=f"Pattern match for {vuln_id} detected.",
                            file_path=filepath,
                            line_hint=f"Line {line_num}",
                            recommendation=vuln_info["recommendation"],
                            cwe_id=vuln_info.get("cwe"),
                        ))
    return findings


def build_eigenai_prompt(code_files: dict[str, str], static_findings: list[Finding]) -> str:
    """
    Build the prompt for EigenAI security analysis.
    The code is included in the prompt — but this all stays INSIDE the TEE.
    EigenAI runs within the EigenCloud trusted boundary.
    """
    code_section = ""
    for path, content in sorted(code_files.items()):
        # Truncate very large files for the prompt
        truncated = content[:5000] + ("\n... [truncated]" if len(content) > 5000 else "")
        code_section += f"\n### File: {path}\n```\n{truncated}\n```\n"

    static_section = ""
    if static_findings:
        static_section = "\n## Pre-detected Issues (static analysis)\n"
        for f in static_findings:
            static_section += f"- [{f.severity.value}] {f.title} in {f.file_path} ({f.line_hint})\n"

    return f"""You are a senior security auditor. Analyze the following code for security vulnerabilities.
Focus on: injection flaws, authentication issues, cryptographic weaknesses, data exposure,
insecure configurations, and logic bugs.

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
    """
    Call EigenAI for deterministic inference.
    In production, this hits the EigenAI API endpoint.
    In dev mode, returns a simulated response.
    """
    eigenai_url = os.environ.get("EIGENAI_API_URL", "")
    eigenai_key = os.environ.get("EIGENAI_API_KEY", "")

    if eigenai_url and eigenai_key:
        # Production: call real EigenAI
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
        # Dev mode: simulate EigenAI response
        return "[]"


def analyze(code_files: dict[str, str], use_eigenai: bool = True) -> AuditReport:
    """
    Main analysis entry point.
    1. Run static analysis (pattern matching)
    2. Optionally run EigenAI deep analysis
    3. Merge results into a single report
    All processing happens inside the TEE.
    """
    start = time.time()

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
            # Parse AI response
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
        },
        analysis_duration_ms=round(duration_ms, 2),
        eigenai_model=model_used,
        deterministic_seed=seed_used,
    )
