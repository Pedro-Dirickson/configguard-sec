"""Auditoria de configurações inseguras em Dockerfiles, compose, arquivos de config e permissões."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .secrets import BINARY_EXTENSIONS, DEFAULT_SKIP_DIRS, Severity


@dataclass(frozen=True)
class ConfigFinding:
    rule_id: str
    description: str
    severity: Severity
    file_path: str
    line_number: int
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


CRITICAL_PORTS: dict[int, tuple[str, Severity]] = {
    21: ("FTP", Severity.HIGH),
    22: ("SSH", Severity.HIGH),
    23: ("Telnet", Severity.CRITICAL),
    445: ("SMB", Severity.HIGH),
    1433: ("SQL Server", Severity.HIGH),
    1521: ("Oracle DB", Severity.HIGH),
    2375: ("Docker API sem TLS", Severity.CRITICAL),
    2379: ("etcd", Severity.HIGH),
    3306: ("MySQL/MariaDB", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    5601: ("Kibana", Severity.MEDIUM),
    5900: ("VNC", Severity.HIGH),
    5984: ("CouchDB", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
    11211: ("Memcached", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
}

ROOT_USERS = frozenset({"root", "0"})
NONROOT_IMAGE_HINTS = ("nonroot", "rootless")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

SCRIPT_EXTENSIONS = frozenset({".sh", ".bash", ".zsh", ".ksh", ".py", ".pl", ".rb", ".ps1", ".bat", ".cmd"})
SENSITIVE_EXTENSIONS = frozenset({".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ovpn"})
SENSITIVE_NAMES = frozenset({
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pgpass", ".netrc", ".htpasswd",
    "credentials", "credentials.json", "kubeconfig", "secrets.yaml", "secrets.yml",
    "shadow", "authorized_keys",
})
CONFIG_EXTENSIONS = frozenset({
    ".py", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml", ".json", ".properties", ".env",
})

_INSTRUCTION = re.compile(r"^\s*([A-Za-z]+)\s+(.*)$")
_DEBUG_FLAG = re.compile(
    r"""(?ix)
    (?P<key>\b(?:[a-z0-9]+_)*debug(?:_mode)?)\b["']?
    \s*(?::|=(?!=))\s*
    ["']?(?P<value>true|1|yes|on)\b["']?
    """
)
_DEV_ENVIRONMENT = re.compile(
    r"""(?ix)\b(?P<key>flask_env|node_env|app_env|rails_env|environment)\b["']?
    \s*(?::|=(?!=))\s*["']?(?P<value>development|dev)\b"""
)
_CHMOD = re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*(?P<mode>[0-7]{3,4}|[ugoa]*[+=][rwxXst]+(?:,[ugoa]*[+=-][rwxXst]+)*)(?=\s|$)")
_SYMBOLIC_OTHERS_WRITE = re.compile(r"(?:^|,)[ugoa]*[oa][ugoa]*[+=][rwxXst]*w")
_COMPOSE_PORT = re.compile(
    r"""^\s*-\s*["']?
    (?:(?P<host_ip>\[[^\]]+\]|[\w.:]+?):)??
    (?:(?P<host_port>\d+(?:-\d+)?):)?
    (?P<container_port>\d+)(?:-\d+)?(?:/(?:tcp|udp))?["']?\s*(?:\#.*)?$""",
    re.VERBOSE,
)
_COMMENT_PREFIXES = ("#", "//", ";")


def is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in {"dockerfile", "containerfile"}
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
    )


def is_compose_file(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in {".yml", ".yaml"} and (
        name.startswith("docker-compose") or name.startswith("compose")
    )


def is_env_file(path: Path) -> bool:
    name = path.name.lower()
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def is_sensitive_file(path: Path) -> bool:
    return (
        path.name.lower() in SENSITIVE_NAMES
        or path.suffix.lower() in SENSITIVE_EXTENSIONS
        or is_env_file(path)
    )


def is_script(path: Path) -> bool:
    return path.suffix.lower() in SCRIPT_EXTENSIONS


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Junta continuações com barra invertida, preservando a linha inicial da instrução."""
    buffer: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].strip())
            continue
        buffer.append(stripped)
        yield start, " ".join(part for part in buffer if part)
        buffer = []
    if buffer:
        yield start, " ".join(part for part in buffer if part)


@dataclass
class _Stage:
    from_line: int
    image: str
    user: str | None = None
    user_line: int = 0


def audit_dockerfile(text: str, file_path: str = "Dockerfile") -> list[ConfigFinding]:
    findings: list[ConfigFinding] = []
    stages: list[_Stage] = []

    for line_number, instruction in _logical_lines(text):
        match = _INSTRUCTION.match(instruction)
        if not match:
            continue
        keyword, args = match.group(1).upper(), match.group(2).strip()

        if keyword == "FROM":
            image = next((t for t in args.split() if not t.startswith("--")), "")
            stages.append(_Stage(from_line=line_number, image=image))
        elif keyword == "USER" and stages:
            stages[-1].user = args.split()[0] if args else ""
            stages[-1].user_line = line_number
        elif keyword == "EXPOSE":
            findings.extend(_exposed_ports(args, line_number, file_path))
        elif keyword == "RUN":
            findings.extend(_permissive_chmod(instruction, line_number, file_path))

    if stages:
        findings.extend(_root_user_findings(stages[-1], file_path))
    return sorted(findings, key=lambda f: f.line_number)


def _root_user_findings(stage: _Stage, file_path: str) -> list[ConfigFinding]:
    if stage.user is None:
        if any(hint in stage.image.lower() for hint in NONROOT_IMAGE_HINTS):
            return []
        return [ConfigFinding(
            rule_id="dockerfile-missing-user",
            description="Container final executa como root (nenhuma instrução USER)",
            severity=Severity.HIGH,
            file_path=file_path,
            line_number=stage.from_line,
            evidence=f"FROM {stage.image}",
            recommendation="Crie um usuário sem privilégios e adicione 'USER <usuario>' ao estágio final.",
        )]
    name = stage.user.split(":", 1)[0]
    if name.lower() in ROOT_USERS:
        return [ConfigFinding(
            rule_id="dockerfile-root-user",
            description="Container final executa explicitamente como root",
            severity=Severity.HIGH,
            file_path=file_path,
            line_number=stage.user_line,
            evidence=f"USER {stage.user}",
            recommendation="Troque para um usuário não-root (UID >= 1000) no estágio final.",
        )]
    return []


def _exposed_ports(args: str, line_number: int, file_path: str) -> Iterator[ConfigFinding]:
    for token in args.split():
        port_text = token.split("/", 1)[0]
        if not port_text.isdigit():
            continue
        port = int(port_text)
        if port in CRITICAL_PORTS:
            service, severity = CRITICAL_PORTS[port]
            yield ConfigFinding(
                rule_id="dockerfile-critical-port",
                description=f"Porta crítica exposta: {port} ({service})",
                severity=severity,
                file_path=file_path,
                line_number=line_number,
                evidence=f"EXPOSE {args}",
                recommendation=f"Remova a exposição de {service} da imagem; acesse-o por rede interna ou túnel.",
            )


def chmod_grants_world_write(mode: str) -> bool:
    if mode.isdigit():
        value = int(mode, 8)
        return bool(value & 0o002) and not value & 0o1000
    return bool(_SYMBOLIC_OTHERS_WRITE.search(mode))


def _permissive_chmod(command: str, line_number: int, file_path: str) -> Iterator[ConfigFinding]:
    for match in _CHMOD.finditer(command):
        if not chmod_grants_world_write(match.group("mode")):
            continue
        yield ConfigFinding(
            rule_id="permissive-chmod",
            description="Comando chmod concede escrita para todos os usuários",
            severity=Severity.HIGH,
            file_path=file_path,
            line_number=line_number,
            evidence=match.group(0),
            recommendation="Use permissões mínimas (ex.: 750 para scripts, 640 para configs).",
        )


def audit_compose_ports(text: str, file_path: str = "docker-compose.yml") -> list[ConfigFinding]:
    findings: list[ConfigFinding] = []
    ports_indent: int | None = None

    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())

        if ports_indent is not None and (indent < ports_indent or (indent == ports_indent and not stripped.startswith("-"))):
            ports_indent = None
        if re.match(r"^ports\s*:\s*$", stripped):
            ports_indent = indent
            continue
        if ports_indent is None:
            continue

        match = _COMPOSE_PORT.match(raw)
        if not match:
            continue
        host_ip = (match.group("host_ip") or "").lower()
        if host_ip in LOOPBACK_HOSTS:
            continue
        port = int(match.group("container_port"))
        if port not in CRITICAL_PORTS:
            continue
        service, severity = CRITICAL_PORTS[port]
        findings.append(ConfigFinding(
            rule_id="compose-critical-port",
            description=f"Porta crítica publicada no host: {port} ({service})",
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            evidence=stripped,
            recommendation=f"Vincule {service} a 127.0.0.1 ou remova o mapeamento e use a rede interna do compose.",
        ))
    return findings


def audit_debug_flags(text: str, file_path: str = "<config>") -> list[ConfigFinding]:
    findings: list[ConfigFinding] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        for pattern, rule_id, description, recommendation in (
            (
                _DEBUG_FLAG,
                "debug-enabled",
                "Modo debug habilitado em configuração",
                "Desative o debug em produção e controle-o por variável de ambiente com padrão False.",
            ),
            (
                _DEV_ENVIRONMENT,
                "development-environment",
                "Ambiente configurado como desenvolvimento",
                "Defina o ambiente como 'production' nos artefatos de deploy.",
            ),
        ):
            match = pattern.search(raw)
            if match:
                findings.append(ConfigFinding(
                    rule_id=rule_id,
                    description=description,
                    severity=Severity.HIGH if rule_id == "debug-enabled" else Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_number,
                    evidence=match.group(0).strip(),
                    recommendation=recommendation,
                ))
                break
    return findings


def audit_permissions(path: str | os.PathLike[str], mode: int) -> list[ConfigFinding]:
    """Avalia o modo POSIX de um arquivo; aplica-se a scripts e arquivos sensíveis."""
    file_path = Path(path)
    sensitive = is_sensitive_file(file_path)
    executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    if not (sensitive or is_script(file_path) or executable):
        return []

    permissions = stat.S_IMODE(mode)
    kind = "arquivo sensível" if sensitive else "script"
    if permissions & 0o777 == 0o777:
        return [ConfigFinding(
            rule_id="permissions-0777",
            description=f"Permissão 0777 em {kind}",
            severity=Severity.CRITICAL if sensitive else Severity.HIGH,
            file_path=str(file_path),
            line_number=0,
            evidence=f"mode {permissions:04o}",
            recommendation="Restrinja para 0600 (sensíveis) ou 0750 (scripts).",
        )]
    if permissions & stat.S_IWOTH:
        return [ConfigFinding(
            rule_id="permissions-world-writable",
            description=f"{kind.capitalize()} gravável por qualquer usuário",
            severity=Severity.CRITICAL if sensitive else Severity.HIGH,
            file_path=str(file_path),
            line_number=0,
            evidence=f"mode {permissions:04o}",
            recommendation="Remova a escrita para 'others' (chmod o-w).",
        )]
    return []


@dataclass
class ConfigScanner:
    """Orquestra as auditorias de configuração sobre arquivos e diretórios."""

    check_permissions: bool = os.name == "posix"
    max_file_size: int = 2 * 1024 * 1024
    skip_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_DIRS)

    def scan_path(self, root: str | os.PathLike[str]) -> list[ConfigFinding]:
        root_path = Path(root)
        if root_path.is_file():
            return self.scan_file(root_path)
        findings: list[ConfigFinding] = []
        for current, dirs, files in os.walk(root_path):
            dirs[:] = sorted(d for d in dirs if d not in self.skip_dirs)
            for name in sorted(files):
                findings.extend(self.scan_file(Path(current) / name))
        return findings

    def scan_file(self, path: str | os.PathLike[str]) -> list[ConfigFinding]:
        file_path = Path(path)
        try:
            info = file_path.stat()
        except OSError:
            return []

        findings: list[ConfigFinding] = []
        if self.check_permissions:
            findings.extend(audit_permissions(file_path, info.st_mode))

        if file_path.suffix.lower() in BINARY_EXTENSIONS or info.st_size > self.max_file_size:
            return findings
        text = self._read_text(file_path)
        if text is None:
            return findings

        label = str(file_path)
        if is_dockerfile(file_path):
            findings.extend(audit_dockerfile(text, label))
        if is_compose_file(file_path):
            findings.extend(audit_compose_ports(text, label))
        if is_env_file(file_path) or file_path.suffix.lower() in CONFIG_EXTENSIONS:
            findings.extend(audit_debug_flags(text, label))
        if file_path.suffix.lower() in {".sh", ".bash", ".zsh", ".ksh"}:
            for number, line in enumerate(text.splitlines(), start=1):
                if not line.lstrip().startswith("#"):
                    findings.extend(_permissive_chmod(line, number, label))
        return findings

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        if b"\x00" in raw[:8192]:
            return None
        return raw.decode("utf-8", errors="replace")
