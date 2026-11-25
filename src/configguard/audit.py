"""Orquestração das varreduras e modelo de resultado compartilhado por storage, reporter e CLI."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .scanners.configs import ConfigFinding, ConfigScanner
from .scanners.secrets import (
    BINARY_EXTENSIONS,
    DEFAULT_SKIP_DIRS,
    DEFAULT_SKIP_FILES,
    SecretFinding,
    SecretScanner,
    Severity,
)

SEVERITY_ORDER: tuple[Severity, ...] = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
}


def severity_rank(severity: Severity) -> int:
    return SEVERITY_ORDER.index(severity)


@dataclass(frozen=True)
class AuditFinding:
    category: str
    rule_id: str
    severity: Severity
    file_path: str
    line_number: int
    description: str
    evidence: str
    recommendation: str = ""

    @classmethod
    def from_secret(cls, finding: SecretFinding, file_path: str) -> AuditFinding:
        return cls(
            category="secret",
            rule_id=finding.rule_id,
            severity=finding.severity,
            file_path=file_path,
            line_number=finding.line_number,
            description=finding.description,
            evidence=finding.redacted_match,
            recommendation="Revogue a credencial, remova-a do código e do histórico git e use um cofre de segredos.",
        )

    @classmethod
    def from_config(cls, finding: ConfigFinding, file_path: str) -> AuditFinding:
        return cls(
            category="config",
            rule_id=finding.rule_id,
            severity=finding.severity,
            file_path=file_path,
            line_number=finding.line_number,
            description=finding.description,
            evidence=finding.evidence,
            recommendation=finding.recommendation,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class GitContext:
    branch: str | None = None
    commit: str | None = None


@dataclass
class ScanResult:
    target: str
    started_at: str
    duration_ms: int
    files_scanned: int
    findings: list[AuditFinding] = field(default_factory=list)
    git: GitContext = field(default_factory=GitContext)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def score(self) -> float:
        return quality_score(self.findings)

    def blocking_findings(self, fail_on: Severity | None) -> list[AuditFinding]:
        if fail_on is None:
            return []
        threshold = severity_rank(fail_on)
        return [f for f in self.findings if severity_rank(f.severity) <= threshold]

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
            "branch": self.git.branch,
            "commit": self.git.commit,
            "score": self.score,
            "summary": {s.value: n for s, n in self.severity_counts.items()},
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def quality_score(findings: Iterable[AuditFinding]) -> float:
    """Nota de 0 a 100 penalizada pela severidade de cada achado."""
    penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return float(max(0, 100 - penalty))


def detect_git_context(path: str | os.PathLike[str]) -> GitContext:
    directory = Path(path)
    if directory.is_file():
        directory = directory.parent
    branch = _git(directory, "symbolic-ref", "--short", "-q", "HEAD")
    commit = _git(directory, "rev-parse", "--verify", "-q", "HEAD")
    return GitContext(branch=branch, commit=commit)


def git_toplevel(path: str | os.PathLike[str]) -> Path | None:
    root = _git(Path(path), "rev-parse", "--show-toplevel")
    return Path(root) if root else None


def git_path(repo: str | os.PathLike[str], name: str) -> Path | None:
    """Resolve caminhos internos do git respeitando core.hooksPath e worktrees."""
    relative = _git(Path(repo), "rev-parse", "--git-path", name)
    return (Path(repo) / relative).resolve() if relative else None


def staged_files(repo: str | os.PathLike[str]) -> list[Path]:
    root = git_toplevel(repo)
    output = _git(Path(repo), "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    if root is None or not output:
        return []
    return [root / name for name in output.split("\0") if name]


def _git(directory: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(directory), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip("\n") or None


def iter_target_files(root: Path, skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs)
        for name in sorted(files):
            yield Path(current) / name


def run_scan(
    target: str | os.PathLike[str],
    *,
    files: Iterable[Path] | None = None,
    scan_secrets: bool = True,
    scan_configs: bool = True,
    entropy: bool = True,
    check_permissions: bool | None = None,
) -> ScanResult:
    root = Path(target).resolve()
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()

    secret_scanner = SecretScanner(entropy_enabled=entropy)
    config_scanner = ConfigScanner() if check_permissions is None else ConfigScanner(check_permissions=check_permissions)
    candidates = iter_target_files(root) if files is None else (Path(f) for f in files)

    findings: list[AuditFinding] = []
    files_scanned = 0
    for path in candidates:
        if not path.is_file():
            continue
        files_scanned += 1
        label = _display_path(path, root)
        if scan_secrets and _secret_scannable(path):
            findings.extend(AuditFinding.from_secret(f, label) for f in secret_scanner.scan_file(path))
        if scan_configs:
            findings.extend(AuditFinding.from_config(f, label) for f in config_scanner.scan_file(path))

    findings.sort(key=lambda f: (severity_rank(f.severity), f.file_path, f.line_number))
    return ScanResult(
        target=str(root),
        started_at=started.isoformat(timespec="seconds"),
        duration_ms=int((time.perf_counter() - clock) * 1000),
        files_scanned=files_scanned,
        findings=findings,
        git=detect_git_context(root),
    )


def _secret_scannable(path: Path) -> bool:
    name = path.name
    if name in DEFAULT_SKIP_FILES or name.endswith(".min.js"):
        return False
    return path.suffix.lower() not in BINARY_EXTENSIONS


def _display_path(path: Path, root: Path) -> str:
    base = root if root.is_dir() else root.parent
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()
