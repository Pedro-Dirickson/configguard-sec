import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from configguard.scanners.configs import (  # noqa: E402
    ConfigScanner,
    audit_compose_ports,
    audit_debug_flags,
    audit_dockerfile,
    audit_permissions,
    chmod_grants_world_write,
)
from configguard.scanners.secrets import Severity  # noqa: E402


def dedent(text):
    return textwrap.dedent(text).lstrip("\n")


def rule_ids(findings):
    return [f.rule_id for f in findings]


class DockerfileUserTests(unittest.TestCase):
    def test_missing_user_runs_as_root(self):
        findings = audit_dockerfile(dedent("""
            FROM python:3.12-slim
            COPY . /app
            CMD ["python", "app.py"]
        """))
        self.assertEqual(rule_ids(findings), ["dockerfile-missing-user"])
        self.assertEqual(findings[0].line_number, 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_explicit_root_user(self):
        for user in ("root", "0", "root:root", "0:0"):
            with self.subTest(user=user):
                findings = audit_dockerfile(f"FROM alpine:3.20\nUSER {user}\nCMD [\"sh\"]\n")
                self.assertEqual(rule_ids(findings), ["dockerfile-root-user"])
                self.assertEqual(findings[0].line_number, 2)

    def test_non_root_user_is_accepted(self):
        findings = audit_dockerfile(dedent("""
            FROM node:20-alpine
            RUN addgroup -S app && adduser -S app -G app
            USER app
            CMD ["node", "server.js"]
        """))
        self.assertEqual(findings, [])

    def test_root_then_drop_privileges(self):
        findings = audit_dockerfile("FROM debian:12\nUSER root\nRUN apt-get update\nUSER 1001\n")
        self.assertEqual(findings, [])

    def test_only_final_stage_matters(self):
        findings = audit_dockerfile(dedent("""
            FROM golang:1.23 AS builder
            RUN go build -o /out/app ./...

            FROM gcr.io/distroless/static:nonroot
            COPY --from=builder /out/app /app
            ENTRYPOINT ["/app"]
        """))
        self.assertEqual(findings, [])

    def test_builder_user_does_not_leak_into_final_stage(self):
        findings = audit_dockerfile(dedent("""
            FROM python:3.12 AS build
            USER 1000
            FROM python:3.12-slim
            CMD ["python"]
        """))
        self.assertEqual(rule_ids(findings), ["dockerfile-missing-user"])
        self.assertEqual(findings[0].line_number, 3)

    def test_lowercase_instructions_and_comments(self):
        findings = audit_dockerfile("# USER app\nfrom ubuntu:24.04\nuser root\n")
        self.assertEqual(rule_ids(findings), ["dockerfile-root-user"])


class DockerfilePortTests(unittest.TestCase):
    def test_critical_ports_are_reported(self):
        findings = audit_dockerfile("FROM ubuntu\nEXPOSE 22 5432/tcp 8080\nUSER app\n")
        self.assertEqual(rule_ids(findings), ["dockerfile-critical-port"] * 2)
        self.assertIn("22 (SSH)", findings[0].description)
        self.assertIn("5432 (PostgreSQL)", findings[1].description)

    def test_docker_api_port_is_critical(self):
        findings = audit_dockerfile("FROM docker:dind\nEXPOSE 2375\nUSER app\n")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_web_ports_are_ignored(self):
        findings = audit_dockerfile("FROM nginx\nEXPOSE 80 443 8080 ${PORT}\nUSER nginx\n")
        self.assertEqual(findings, [])


class DockerfileEnvTests(unittest.TestCase):
    def audit_env(self, env_line):
        findings = audit_dockerfile(f"FROM python:3.12-slim\n{env_line}\nUSER app\n")
        return [f for f in findings if f.rule_id in {"debug-enabled", "development-environment"}]

    def test_debug_enabled_via_env(self):
        lines = [
            "ENV DEBUG=True",
            "ENV DEBUG=true",
            'ENV DEBUG="1"',
            "ENV DJANGO_DEBUG=yes",
            "ENV DEBUG True",
            "env FLASK_DEBUG=on",
            "ENV PYTHONUNBUFFERED=1 DEBUG=True LANG=C.UTF-8",
        ]
        for line in lines:
            with self.subTest(line=line):
                findings = self.audit_env(line)
                self.assertEqual(rule_ids(findings), ["debug-enabled"])
                self.assertEqual(findings[0].severity, Severity.HIGH)
                self.assertEqual(findings[0].line_number, 2)
                self.assertTrue(findings[0].evidence.startswith("ENV "))
                self.assertIn("ENV da imagem", findings[0].description)

    def test_development_environment_via_env(self):
        findings = self.audit_env("ENV FLASK_ENV=development")
        self.assertEqual(rule_ids(findings), ["development-environment"])
        self.assertEqual(findings[0].evidence, "ENV FLASK_ENV=development")

    def test_multiple_flags_in_one_instruction(self):
        findings = self.audit_env('ENV NODE_ENV=development DEBUG="true" PORT=8000')
        self.assertEqual(sorted(rule_ids(findings)), ["debug-enabled", "development-environment"])

    def test_line_continuation_reports_instruction_start(self):
        findings = audit_dockerfile(dedent("""
            FROM python:3.12-slim
            ENV APP_HOME=/app \\
                DEBUG=True \\
                LOG_LEVEL=info
            USER app
        """))
        self.assertEqual(rule_ids(findings), ["debug-enabled"])
        self.assertEqual(findings[0].line_number, 2)

    def test_safe_env_values(self):
        lines = [
            "ENV DEBUG=False",
            "ENV DEBUG=0",
            "ENV DEBUG=${DEBUG:-false}",
            "ENV LOG_LEVEL=DEBUG",
            "ENV FLASK_ENV=production NODE_ENV=production",
            "ENV DEBUG_TOOLBAR_ENABLED=false",
            'ENV GREETING="debug=true is not a key here"',
            "ENV",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(self.audit_env(line), [])

    def test_commented_env_is_ignored(self):
        self.assertEqual(self.audit_env("# ENV DEBUG=True"), [])

    def test_arg_is_not_treated_as_env(self):
        self.assertEqual(self.audit_env("ARG DEBUG=true"), [])


class DockerfileChmodTests(unittest.TestCase):
    def test_chmod_777_in_run(self):
        findings = audit_dockerfile(dedent("""
            FROM alpine
            RUN mkdir /data && \\
                chmod -R 777 /data
            USER app
        """))
        self.assertEqual(rule_ids(findings), ["permissive-chmod"])
        self.assertEqual(findings[0].line_number, 2)

    def test_chmod_mode_parsing(self):
        cases = {
            "777": True,
            "0777": True,
            "666": True,
            "0757": True,
            "1777": False,
            "755": False,
            "0640": False,
            "a+rwx": True,
            "o+w": True,
            "u+x,o+w": True,
            "+x": False,
            "u+rwx": False,
            "go-w": False,
        }
        for mode, expected in cases.items():
            with self.subTest(mode=mode):
                self.assertEqual(chmod_grants_world_write(mode), expected)


class ComposePortTests(unittest.TestCase):
    COMPOSE = dedent("""
        services:
          db:
            image: postgres:16
            ports:
              - "5432:5432"
          cache:
            image: redis:7
            ports:
              - "127.0.0.1:6379:6379"
          mongo:
            image: mongo:7
            ports:
              - 0.0.0.0:27018:27017
          web:
            image: nginx
            ports:
              - "80:80"
              - "443:443"
            environment:
              - "3306"
    """)

    def test_publicly_bound_critical_ports(self):
        findings = audit_compose_ports(self.COMPOSE)
        self.assertEqual(rule_ids(findings), ["compose-critical-port"] * 2)
        self.assertEqual([f.line_number for f in findings], [5, 13])
        self.assertIn("MongoDB", findings[1].description)

    def test_ipv6_loopback_binding_is_ignored(self):
        text = 'services:\n  db:\n    ports:\n      - "[::1]:5432:5432"\n'
        self.assertEqual(audit_compose_ports(text), [])


class DebugFlagTests(unittest.TestCase):
    def test_debug_enabled_variants(self):
        lines = [
            "DEBUG=True",
            "DEBUG = True",
            "DJANGO_DEBUG=1",
            "FLASK_DEBUG=on",
            "debug: true",
            '"debug": true',
            "app.run(host='0.0.0.0', debug=True)",
            "debug_mode = yes",
        ]
        for line in lines:
            with self.subTest(line=line):
                findings = audit_debug_flags(line)
                self.assertEqual(rule_ids(findings), ["debug-enabled"])
                self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_development_environment(self):
        for line in ("FLASK_ENV=development", "NODE_ENV: dev", "environment = 'development'"):
            with self.subTest(line=line):
                self.assertEqual(rule_ids(audit_debug_flags(line)), ["development-environment"])

    def test_safe_or_unrelated_settings(self):
        lines = [
            "DEBUG=False",
            "DEBUG = os.getenv('DEBUG', 'False') == 'True'",
            "if DEBUG == True:",
            "LOG_LEVEL=DEBUG",
            "debug_toolbar_enabled = false",
            "# DEBUG=True",
            "// debug: true",
            "NODE_ENV=production",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(audit_debug_flags(line), [])

    def test_reports_line_number(self):
        findings = audit_debug_flags("SECRET_KEY=x\nALLOWED_HOSTS=*\nDEBUG=True\n")
        self.assertEqual(findings[0].line_number, 3)


class PermissionTests(unittest.TestCase):
    def test_0777_on_script(self):
        findings = audit_permissions("deploy.sh", stat.S_IFREG | 0o777)
        self.assertEqual(rule_ids(findings), ["permissions-0777"])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_0777_on_sensitive_file_is_critical(self):
        findings = audit_permissions("keys/id_rsa", stat.S_IFREG | 0o777)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_world_writable_sensitive_files(self):
        for name in (".env", ".env.production", "server.pem", "tls.key", "credentials.json"):
            with self.subTest(name=name):
                findings = audit_permissions(name, stat.S_IFREG | 0o666)
                self.assertEqual(rule_ids(findings), ["permissions-world-writable"])
                self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_world_writable_executable_without_extension(self):
        findings = audit_permissions("bin/entrypoint", stat.S_IFREG | 0o757)
        self.assertEqual(rule_ids(findings), ["permissions-world-writable"])

    def test_safe_modes(self):
        cases = [
            ("deploy.sh", 0o755),
            ("deploy.sh", 0o750),
            (".env", 0o600),
            ("id_rsa", 0o400),
            ("README.md", 0o666),
            ("index.html", 0o664),
        ]
        for name, mode in cases:
            with self.subTest(name=name, mode=oct(mode)):
                self.assertEqual(audit_permissions(name, stat.S_IFREG | mode), [])


class ConfigScannerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scanner = ConfigScanner(check_permissions=False)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_scan_path_routes_files_to_auditors(self):
        self.write("Dockerfile", "FROM python:3.12\nEXPOSE 22\n")
        self.write("docker-compose.yml", "services:\n  db:\n    ports:\n      - \"3306:3306\"\n")
        self.write(".env", "DEBUG=True\n")
        self.write("config/settings.py", "DEBUG = True\n")
        self.write("scripts/setup.sh", "#!/bin/sh\n# chmod 777 is bad\nchmod 777 /srv/app\n")
        self.write("docs/notes.md", "DEBUG=True and EXPOSE 22 are discussed here.\n")
        self.write("node_modules/pkg/.env", "DEBUG=True\n")

        findings = self.scanner.scan_path(self.root)
        by_file = {(Path(f.file_path).name, f.rule_id) for f in findings}

        self.assertEqual(by_file, {
            ("Dockerfile", "dockerfile-critical-port"),
            ("Dockerfile", "dockerfile-missing-user"),
            ("docker-compose.yml", "compose-critical-port"),
            (".env", "debug-enabled"),
            ("settings.py", "debug-enabled"),
            ("setup.sh", "permissive-chmod"),
        })
        self.assertEqual(len(findings), 6)

    def test_scan_single_file(self):
        path = self.write("Dockerfile.prod", "FROM alpine\nUSER root\n")
        self.assertEqual(rule_ids(self.scanner.scan_path(path)), ["dockerfile-root-user"])

    def test_missing_file(self):
        self.assertEqual(self.scanner.scan_file(self.root / "nope"), [])

    def test_finding_serialization(self):
        finding = audit_debug_flags("DEBUG=True", ".env")[0]
        data = finding.to_dict()
        self.assertEqual(data["severity"], "high")
        self.assertEqual(data["file_path"], ".env")
        self.assertIn("recommendation", data)

    @unittest.skipUnless(os.name == "posix", "permissões POSIX reais exigem sistema POSIX")
    def test_real_file_permissions(self):
        script = self.write("run.sh", "echo ok\n")
        os.chmod(script, 0o777)
        scanner = ConfigScanner(check_permissions=True)
        self.assertIn("permissions-0777", rule_ids(scanner.scan_file(script)))


if __name__ == "__main__":
    unittest.main()
