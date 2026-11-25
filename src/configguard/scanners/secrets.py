"""Detecção de segredos expostos via expressões regulares e entropia de Shannon."""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Iterator, Pattern

IGNORE_PRAGMA = "configguard:ignore"

BASE64_CHARSET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
HEX_CHARSET = frozenset("0123456789abcdefABCDEF")

DEFAULT_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".idea",
})
DEFAULT_SKIP_FILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock",
})
BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf",
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo",
    ".db", ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi",
})

PLACEHOLDER_WORDS = frozenset({
    "password", "passwd", "pass", "secret", "changeme", "change_me",
    "example", "sample", "dummy", "placeholder", "redacted", "test",
    "your_password", "your_api_key", "your-api-key", "yourpassword",
    "none", "null", "undefined", "todo", "fixme", "xxx",
})
_PLACEHOLDER_SHAPES = re.compile(
    r"""^(
        \$\{[^}]*\}        |
        \$\([^)]*\)        |
        \$[A-Za-z_]\w*     |
        \{\{.*\}\}         |
        \{[^}]*\}          |
        <[^>]*>            |
        %\(?\w*\)?s        |
        \*+                |
        x+                 |
        \.\.\.+
    )$""",
    re.IGNORECASE | re.VERBOSE,
)
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/=_-]+")
_HASH_PREFIX = re.compile(r"(sha1|sha256|sha384|sha512|md5)[:\-=]$", re.IGNORECASE)
_HASH_TOKEN = re.compile(r"^(sha1|sha256|sha384|sha512|md5)-", re.IGNORECASE)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    description: str
    severity: Severity
    file_path: str
    line_number: int
    column: int
    redacted_match: str
    entropy: float

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "match": self.redacted_match,
            "entropy": round(self.entropy, 3),
        }


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    description: str
    severity: Severity
    pattern: Pattern[str]
    secret_group: int | str = 0
    validator: Callable[[re.Match[str]], bool] | None = None


def shannon_entropy(data: str) -> float:
    """Entropia de Shannon em bits por caractere."""
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(data).values()
    )


def redact(value: str, visible: int = 4) -> str:
    if len(value) <= visible * 2:
        return value[:1] + "*" * (len(value) - 1)
    return f"{value[:visible]}{'*' * 8}{value[-2:]}"


def is_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("'\"")
    if not cleaned:
        return True
    if cleaned.lower() in PLACEHOLDER_WORDS:
        return True
    return bool(_PLACEHOLDER_SHAPES.match(cleaned))


def _looks_like_code_reference(value: str) -> bool:
    if any(ch in value for ch in "([{<"):
        return True
    if value.startswith(("$", "process.env", "os.environ", "getenv")):
        return True
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z_.]*", value))


def _db_url_has_real_password(match: re.Match[str]) -> bool:
    return not is_placeholder(match.group("password"))


def _generic_assignment_is_secret(match: re.Match[str]) -> bool:
    value = match.group("value")
    quoted = match.group("quote") is not None
    if is_placeholder(value):
        return False
    if not quoted and _looks_like_code_reference(value):
        return False
    return len(value) >= 8


def _bearer_is_token(match: re.Match[str]) -> bool:
    token = match.group("token")
    return not is_placeholder(token) and shannon_entropy(token) >= 3.0


DEFAULT_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private-key",
        "Chave privada em formato PEM",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    SecretRule(
        "aws-access-key-id",
        "AWS Access Key ID",
        Severity.CRITICAL,
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ),
    SecretRule(
        "aws-secret-access-key",
        "AWS Secret Access Key",
        Severity.CRITICAL,
        re.compile(
            r"(?i)aws.{0,20}?secret.{0,20}?['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        secret_group="secret",
    ),
    SecretRule(
        "github-token",
        "Token de acesso do GitHub",
        Severity.HIGH,
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    SecretRule(
        "gitlab-token",
        "Personal Access Token do GitLab",
        Severity.HIGH,
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ),
    SecretRule(
        "slack-token",
        "Token do Slack",
        Severity.HIGH,
        re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    ),
    SecretRule(
        "slack-webhook",
        "Webhook do Slack",
        Severity.HIGH,
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
    ),
    SecretRule(
        "stripe-secret-key",
        "Chave secreta do Stripe",
        Severity.CRITICAL,
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b"),
    ),
    SecretRule(
        "google-api-key",
        "Chave de API do Google",
        Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
    ),
    SecretRule(
        "openai-api-key",
        "Chave de API da OpenAI",
        Severity.HIGH,
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"),
    ),
    SecretRule(
        "anthropic-api-key",
        "Chave de API da Anthropic",
        Severity.HIGH,
        re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b"),
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        Severity.HIGH,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    SecretRule(
        "bearer-token",
        "Token Bearer em cabeçalho de autorização",
        Severity.HIGH,
        re.compile(r"\bBearer\s+(?P<token>[A-Za-z0-9\-._~+/]{20,}=*)", re.IGNORECASE),
        secret_group="token",
        validator=_bearer_is_token,
    ),
    SecretRule(
        "database-connection-string",
        "String de conexão de banco de dados com credenciais",
        Severity.CRITICAL,
        re.compile(
            r"\b(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|"
            r"mssql|sqlserver|oracle|amqps?|jdbc:[a-z]+)://"
            r"(?P<user>[^\s:/@'\"]+):(?P<password>[^\s@'\"]+)@(?P<host>[^\s/'\"?]+)"
        ),
        secret_group="password",
        validator=_db_url_has_real_password,
    ),
    SecretRule(
        "database-connection-string",
        "String de conexão ADO.NET/ODBC com senha",
        Severity.CRITICAL,
        re.compile(r"(?i)(?:Server|Data Source|Host)=[^;]+;.*?(?:Password|Pwd)=(?P<password>[^;'\"\s]+)"),
        secret_group="password",
        validator=_db_url_has_real_password,
    ),
    SecretRule(
        "generic-secret-assignment",
        "Atribuição de segredo em variável sensível",
        Severity.MEDIUM,
        re.compile(
            r"(?i)\b[\w.-]*(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|"
            r"auth[_-]?token|private[_-]?key|password|passwd|pwd|secret)\b['\"]?\s*(?::|=(?!=))\s*"
            r"(?P<quote>['\"])?(?P<value>(?(quote)[^'\"]+|[^\s'\"#;,]+))(?(quote)['\"])"
        ),
        secret_group="value",
        validator=_generic_assignment_is_secret,
    ),
)


@dataclass
class SecretScanner:
    """Varre texto, arquivos e diretórios em busca de segredos."""

    rules: tuple[SecretRule, ...] = DEFAULT_RULES
    entropy_enabled: bool = True
    base64_threshold: float = 4.0
    hex_threshold: float = 3.0
    min_token_length: int = 20
    max_file_size: int = 5 * 1024 * 1024
    skip_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_DIRS)
    skip_files: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_FILES)

    def scan_text(self, text: str, file_path: str = "<string>") -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if IGNORE_PRAGMA in line:
                continue
            findings.extend(self._scan_line(line, line_number, file_path))
        return findings

    def scan_file(self, path: str | os.PathLike[str]) -> list[SecretFinding]:
        file_path = Path(path)
        try:
            if file_path.stat().st_size > self.max_file_size:
                return []
            raw = file_path.read_bytes()
        except OSError:
            return []
        if b"\x00" in raw[:8192]:
            return []
        return self.scan_text(raw.decode("utf-8", errors="replace"), str(file_path))

    def scan_path(self, root: str | os.PathLike[str]) -> list[SecretFinding]:
        root_path = Path(root)
        if root_path.is_file():
            return self.scan_file(root_path)
        findings: list[SecretFinding] = []
        for file_path in self.iter_files(root_path):
            findings.extend(self.scan_file(file_path))
        return findings

    def iter_files(self, root: Path) -> Iterator[Path]:
        for current, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in self.skip_dirs)
            for name in sorted(files):
                if name in self.skip_files or name.endswith(".min.js"):
                    continue
                if Path(name).suffix.lower() in BINARY_EXTENSIONS:
                    continue
                yield Path(current) / name

    def _scan_line(self, line: str, line_number: int, file_path: str) -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        claimed: list[tuple[int, int]] = []

        for rule in self.rules:
            for match in rule.pattern.finditer(line):
                start, end = match.span(rule.secret_group)
                if _overlaps(start, end, claimed):
                    continue
                if rule.validator is not None and not rule.validator(match):
                    continue
                secret = match.group(rule.secret_group)
                claimed.append(match.span())
                findings.append(SecretFinding(
                    rule_id=rule.rule_id,
                    description=rule.description,
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=line_number,
                    column=start + 1,
                    redacted_match=redact(secret),
                    entropy=shannon_entropy(secret),
                ))

        if self.entropy_enabled:
            findings.extend(self._entropy_findings(line, line_number, file_path, claimed))
        return findings

    def _entropy_findings(
        self,
        line: str,
        line_number: int,
        file_path: str,
        claimed: list[tuple[int, int]],
    ) -> Iterable[SecretFinding]:
        for match in _TOKEN_PATTERN.finditer(line):
            token = match.group().strip("=")
            start, end = match.span()
            if len(token) < self.min_token_length or _overlaps(start, end, claimed):
                continue
            if _HASH_PREFIX.search(line[:start]) or _HASH_TOKEN.match(token):
                continue
            kind = self._classify_high_entropy(token)
            if kind is None:
                continue
            claimed.append((start, end))
            yield SecretFinding(
                rule_id=f"high-entropy-{kind}",
                description=f"String {kind} de alta entropia",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_number,
                column=start + 1,
                redacted_match=redact(token),
                entropy=shannon_entropy(token),
            )

    def _classify_high_entropy(self, token: str) -> str | None:
        entropy = shannon_entropy(token)
        if set(token) <= HEX_CHARSET:
            if len(token) >= 32 and entropy >= self.hex_threshold and _has_hex_mix(token):
                return "hex"
            return None
        if set(token) <= BASE64_CHARSET and entropy >= self.base64_threshold and _has_mixed_classes(token):
            return "base64"
        return None


def _overlaps(start: int, end: int, spans: Iterable[tuple[int, int]]) -> bool:
    return any(start < other_end and other_start < end for other_start, other_end in spans)


def _has_mixed_classes(token: str) -> bool:
    return (
        any(c.isupper() for c in token)
        and any(c.islower() for c in token)
        and any(c.isdigit() for c in token)
    )


def _has_hex_mix(token: str) -> bool:
    return any(c.isdigit() for c in token) and any(c.isalpha() for c in token)
