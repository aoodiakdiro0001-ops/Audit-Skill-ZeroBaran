"""طبقة الفحص الساكن: محرّك القواعد المدمج + تغليف اختياري لـ Semgrep/Bandit."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field

from .identity import run_identity_checks
from .rules import Rule, rules_for, severity_rank

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist",
    "build", ".mypy_cache", ".pytest_cache", "vendor", ".idea", ".vscode",
    "audit-out", ".trivy-cache",
}
# ملفات النواتج: لا تُفحص (وإلا فحص الفحص نفسه سيُصدر إنذارات)
SKIP_FILES = ("audit-report.*", "self-report.*", "self.*.json", "report.json",
              "report.md", "*.min.js", "*.min.css", "*.map", "*.lock")

# وضعه في نهاية أي سطر يُلغي التنبيه عنه (كتم الإنذار الكاذب)
IGNORE_MARKER = "audit:ignore"
MAX_BYTES = 1_500_000
TEXT_EXT = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".md", ".mdx", ".txt", ".yml",
    ".yaml", ".sh", ".ps1", ".env", ".toml", ".cfg", ".ini", ".html", ".css",
    ".sql", ".go", ".rb", ".php", ".java", ".rs", ".c", ".h", ".cpp", ".vue",
    ".svelte", ".xml", ".cfg", ".properties", "",
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    reason: str
    fix: str
    file: str
    line: int
    excerpt: str
    group: str = "code"  # code | skills | identity

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_lines: int = 0
    errors: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def worst(self) -> str:
        best = "info"
        for f in self.findings:
            if severity_rank(f.severity) > severity_rank(best):
                best = f.severity
        return best if self.findings else "clean"


def _mask(text: str) -> str:
    """إخفاء أي مفتاح يظهر داخل المقتطف حتى لا يُسجَّل في التقارير."""
    patterns = [
        r"ghp_[A-Za-z0-9]{36}", r"github_pat_[A-Za-z0-9_]{50,}",
        r"\bsk-[A-Za-z0-9_\-]{20,}\b", r"\bsk-or-v1-[A-Za-z0-9]{32,}\b",
        r"\bgsk_[A-Za-z0-9]{30,}\b", r"\bhf_[A-Za-z0-9]{30,}\b",
        r"\bAKIA[0-9A-Z]{16}\b", r"\b0x[a-fA-F0-9]{64}\b",
    ]
    for p in patterns:
        text = re.sub(p, "***REDACTED***", text)
    return text


def _is_text(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in TEXT_EXT:
        return True
    name = os.path.basename(path).lower()
    return name.startswith(".env") or name in {"makefile", "dockerfile", "license"}


def iter_files(root: str):
    from fnmatch import fnmatch
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for fn in filenames:
            if any(fnmatch(fn, pat) for pat in SKIP_FILES):
                continue
            yield os.path.join(dirpath, fn)


def _match_glob(name: str, globs: tuple) -> bool:
    if "*" in globs:
        return True
    from fnmatch import fnmatch
    return any(fnmatch(name, g) for g in globs)


def scan_text(path: str, rel: str, text: str, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    name = os.path.basename(path)
    compiled = [(r, re.compile(r.pattern, re.IGNORECASE | re.MULTILINE)) for r in rules]
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue
        if IGNORE_MARKER in line:  # تمييز كتم يدوي للإنذار الكاذب
            continue
        for rule, rx in compiled:
            if not _match_glob(name, rule.globs):
                continue
            if rx.search(line):
                findings.append(Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    title=rule.title,
                    reason=rule.reason,
                    fix=rule.fix,
                    file=rel,
                    line=lineno,
                    excerpt=_mask(line.strip()[:220]),
                    group="skills" if "skills" in rule.profiles else "code",
                ))
    return findings


def run_builtin_scan(root: str, profiles: set[str] | None = None) -> ScanResult:
    profiles = profiles or {"default", "skills"}
    rules = rules_for(profiles)
    result = ScanResult()
    root = os.path.abspath(root)
    for path in iter_files(root):
        if not _is_text(path):
            continue
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        result.scanned_files += 1
        result.scanned_lines += text.count("\n") + 1
        result.findings.extend(scan_text(path, rel, text, rules))
    return result


# --------------------------------------------------------------- أدوات خارجية
def _run(cmd: list[str], timeout: int = 600) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "not-installed"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def run_semgrep(root: str) -> list[Finding]:
    """اختياري: يعمل إن كان Semgrep مثبتاً — وإلا يُتخطّى بهدوء."""
    if not shutil.which("semgrep"):
        return []
    code, out = _run(["semgrep", "--config", "auto", "--json", "--quiet", root])
    findings: list[Finding] = []
    if code not in (0, 1):
        return findings
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return findings
    for m in data.get("results", [])[:400]:
        sev = str(m.get("extra", {}).get("severity", "medium")).lower()
        sev = {"error": "high", "warning": "medium", "info": "low"}.get(sev, sev)
        findings.append(Finding(
            rule_id=f"semgrep.{m.get('check_id', 'rule')}",
            severity=sev if sev in {"critical", "high", "medium", "low"} else "medium",
            title=m.get("check_id", "Semgrep rule"),
            reason=(m.get("extra", {}).get("message") or "").strip()[:400],
            fix="راجع توثيق القاعدة في تقرير Semgrep واتبع الإجراء التصحيحي المقترح.",
            file=os.path.relpath(m.get("path", ""), root).replace(os.sep, "/"),
            line=int(m.get("start", {}).get("line", 0) or 0),
            excerpt=_mask(str(m.get("extra", {}).get("lines", "")).strip()[:220]),
            group="code",
        ))
    return findings


def run_bandit(root: str) -> list[Finding]:
    """اختياري: Bandit للكود بايثوني."""
    if not shutil.which("bandit"):
        return []
    code, out = _run(["bandit", "-r", root, "-f", "json", "-q"])
    if code == 127:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings: list[Finding] = []
    for r in data.get("results", [])[:400]:
        findings.append(Finding(
            rule_id=f"bandit.{r.get('test_id', '')}",
            severity=mapping.get(str(r.get("issue_severity", "")).upper(), "medium"),
            title=str(r.get("test_name", "Bandit finding")),
            reason=str(r.get("issue_text", ""))[:400],
            fix=str(r.get("more_info", "راجع توثيق Bandit للإصلاح.")),
            file=os.path.relpath(r.get("filename", ""), root).replace(os.sep, "/"),
            line=int(r.get("line_number", 0) or 0),
            excerpt=_mask(str(r.get("code", "")).strip()[:220]),
            group="code",
        ))
    return findings


def full_scan(root: str, profiles: set[str] | None = None, external: bool = True) -> ScanResult:
    profiles = profiles or {"default", "skills"}
    result = run_builtin_scan(root, profiles)
    if external:
        result.findings.extend(run_semgrep(root))
        result.findings.extend(run_bandit(root))
    if "identity" in profiles:
        for f in run_identity_checks(root):
            result.findings.append(f)
    result.findings.sort(key=lambda f: (-severity_rank(f.severity), f.file, f.line))
    return result
