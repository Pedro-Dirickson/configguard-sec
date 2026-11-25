import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from configguard.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, HOOK_MARKER, main  # noqa: E402

AWS_KEY_ID = "AKIA" + "Q3EGRKZ7X4PLM2NW"
GIT = shutil.which("git")


def run_cli(*argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(list(argv))
    return code, stdout.getvalue(), stderr.getvalue()


class TempWorkspace(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.db = self.root / "history.db"

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, relative, content):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def history_rows(self, db=None):
        conn = sqlite3.connect(db or self.db)
        try:
            return conn.execute("SELECT branch, commit_sha, total_findings FROM scans ORDER BY id").fetchall()
        finally:
            conn.close()


class ScanCommandTests(TempWorkspace):
    def test_clean_project_passes_and_is_recorded(self):
        self.write("app.py", "print('hello')\n")
        code, out, _ = run_cli("scan", str(self.project), "--db", str(self.db), "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Nenhum problema encontrado.", out)
        self.assertIn("APROVADO", out)
        self.assertEqual(len(self.history_rows()), 1)

    def test_insecure_project_fails_with_findings(self):
        self.write("settings.py", f"AWS_KEY = '{AWS_KEY_ID}'\nDEBUG = True\n")
        self.write("Dockerfile", "FROM python:3.12\nEXPOSE 22\n")
        code, out, _ = run_cli("scan", str(self.project), "--db", str(self.db), "--no-color")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("[CRITICAL] settings.py:1", out)
        self.assertIn("dockerfile-missing-user", out)
        self.assertNotIn(AWS_KEY_ID, out)
        self.assertEqual(self.history_rows()[0][2], 4)

    def test_json_output(self):
        self.write(".env", "DEBUG=True\n")
        code, out, _ = run_cli("scan", str(self.project), "--format", "json", "--no-history")
        self.assertEqual(code, EXIT_FINDINGS)
        data = json.loads(out)
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual([f["rule_id"] for f in data["findings"]], ["debug-enabled"])
        self.assertEqual(data["findings"][0]["file_path"], ".env")

    def test_markdown_report_written_to_file(self):
        self.write(".env", "DEBUG=True\n")
        report = self.root / "reports" / "audit.md"
        code, out, err = run_cli(
            "scan", str(self.project), "-f", "markdown", "-o", str(report), "--no-history",
        )
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(out, "")
        self.assertIn("Relatório salvo em", err)
        self.assertIn("# Relatório de Auditoria ConfigGuard", report.read_text(encoding="utf-8"))

    def test_fail_on_threshold(self):
        self.write(".env", "FLASK_ENV=development\n")
        self.assertEqual(run_cli("scan", str(self.project), "--no-history")[0], EXIT_OK)
        self.assertEqual(run_cli("scan", str(self.project), "--no-history", "--fail-on", "medium")[0], EXIT_FINDINGS)
        self.write("k.py", f"k = '{AWS_KEY_ID}'\n")
        self.assertEqual(run_cli("scan", str(self.project), "--no-history", "--fail-on", "none")[0], EXIT_OK)

    def test_scanner_toggles(self):
        self.write("settings.py", f"AWS_KEY = '{AWS_KEY_ID}'\nDEBUG = True\n")
        _, out, _ = run_cli("scan", str(self.project), "-f", "json", "--no-history", "--no-secrets")
        self.assertEqual({f["category"] for f in json.loads(out)["findings"]}, {"config"})
        _, out, _ = run_cli("scan", str(self.project), "-f", "json", "--no-history", "--no-configs")
        self.assertEqual({f["category"] for f in json.loads(out)["findings"]}, {"secret"})

    def test_no_entropy_flag(self):
        self.write("token.txt", "value = Q2hhbmdlTWUhX3Byb2Q9a9Zx7LmP4wR\n")
        _, out, _ = run_cli("scan", str(self.project), "-f", "json", "--no-history")
        self.assertEqual(json.loads(out)["total_findings"], 1)
        _, out, _ = run_cli("scan", str(self.project), "-f", "json", "--no-history", "--no-entropy")
        self.assertEqual(json.loads(out)["total_findings"], 0)

    def test_no_history_skips_database(self):
        run_cli("scan", str(self.project), "--db", str(self.db), "--no-history")
        self.assertFalse(self.db.exists())

    def test_db_from_environment(self):
        env_db = self.root / "env.db"
        with mock.patch.dict(os.environ, {"CONFIGGUARD_DB": str(env_db)}):
            run_cli("scan", str(self.project))
        self.assertTrue(env_db.exists())

    def test_invalid_usage(self):
        code, _, err = run_cli("scan", str(self.root / "missing"), "--no-history")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("caminho não encontrado", err)
        code, _, _ = run_cli("scan", str(self.project), "--no-secrets", "--no-configs")
        self.assertEqual(code, EXIT_ERROR)
        with self.assertRaises(SystemExit) as ctx:
            run_cli("scan", "--format", "xml")
        self.assertEqual(ctx.exception.code, 2)


class VulnerableSampleTests(unittest.TestCase):
    SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_sample"

    def test_sample_produces_documented_findings(self):
        code, out, _ = run_cli("scan", str(self.SAMPLE), "-f", "json", "--no-history")
        data = json.loads(out)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(data["files_scanned"], 3)
        self.assertEqual(data["summary"], {"critical": 4, "high": 8, "medium": 2, "low": 0})
        by_file = {}
        for finding in data["findings"]:
            by_file.setdefault(finding["file_path"], set()).add(finding["rule_id"])
        self.assertEqual(by_file, {
            ".env.example": {
                "database-connection-string", "aws-access-key-id", "aws-secret-access-key",
                "debug-enabled", "development-environment", "generic-secret-assignment",
            },
            "Dockerfile": {"permissive-chmod", "dockerfile-critical-port", "dockerfile-root-user"},
            "deploy.sh": {"jwt", "bearer-token", "permissive-chmod"},
        })


class HistoryCommandTests(TempWorkspace):
    def test_history_terminal_and_json(self):
        self.write("app.py", "x = 1\n")
        run_cli("scan", str(self.project), "--db", str(self.db))
        self.write(".env", "DEBUG=True\n")
        run_cli("scan", str(self.project), "--db", str(self.db))

        code, out, _ = run_cli("history", "--db", str(self.db), "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Métricas por branch", out)
        self.assertIn("Scans recentes", out)
        self.assertIn("-10", out)

        code, out, _ = run_cli("history", "--db", str(self.db), "-f", "json", "--target", str(self.project))
        data = json.loads(out)
        self.assertEqual([s["total_findings"] for s in data["scans"]], [1, 0])
        self.assertEqual(data["branches"][0]["scans"], 2)
        self.assertEqual(data["branches"][0]["trend"], -10.0)

    def test_limit(self):
        for _ in range(3):
            run_cli("scan", str(self.project), "--db", str(self.db))
        _, out, _ = run_cli("history", "--db", str(self.db), "-f", "json", "-n", "2")
        self.assertEqual(len(json.loads(out)["scans"]), 2)

    def test_missing_database(self):
        code, _, err = run_cli("history", "--db", str(self.root / "none.db"))
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("histórico não encontrado", err)


@unittest.skipUnless(GIT, "git não está disponível")
class GitIntegrationTests(TempWorkspace):
    def setUp(self):
        super().setUp()
        isolated = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "ConfigGuard Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "ConfigGuard Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
        self._env = mock.patch.dict(os.environ, isolated)
        self._env.start()
        self.addCleanup(self._env.stop)
        self.git("init", "-q", "-b", "main")
        self.git("config", "core.hooksPath", ".git/hooks")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args, check=True):
        return subprocess.run(
            [GIT, "-C", str(self.project), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=check, timeout=120,
        )

    def commit_all(self, message):
        self.git("add", "-A")
        return self.git("commit", "-q", "-m", message, check=False)

    def test_scan_records_branch_and_commit(self):
        self.write("README.md", "# demo\n")
        self.commit_all("init")
        head = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("checkout", "-q", "-b", "feature/login")

        run_cli("scan", str(self.project), "--db", str(self.db))
        self.assertEqual(self.history_rows(), [("feature/login", head, 0)])

        code, out, _ = run_cli("history", "--db", str(self.db), "--branch", "feature/login", "-f", "json")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["branches"][0]["branch"], "feature/login")

    def test_repository_without_commits(self):
        run_cli("scan", str(self.project), "--db", str(self.db))
        self.assertEqual(self.history_rows(), [("main", None, 0)])

    def test_staged_scans_only_index(self):
        self.write("committed.py", f"OLD = '{AWS_KEY_ID}'  # configguard:ignore\n")
        self.commit_all("init")
        self.write("staged.env", "DEBUG=True\n")
        self.write("untracked.env", "DEBUG=True\n")
        self.git("add", "staged.env")

        code, out, _ = run_cli("scan", str(self.project), "--staged", "-f", "json", "--no-history")
        data = json.loads(out)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual({f["file_path"] for f in data["findings"]}, {"staged.env"})

    def test_staged_requires_repository(self):
        outside = self.root / "plain"
        outside.mkdir()
        with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(self.root)}):
            code, _, err = run_cli("scan", str(outside), "--staged", "--no-history")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("--staged exige", err)

    def test_install_hook(self):
        code, out, _ = run_cli("install-hook", str(self.project), "--fail-on", "critical")
        self.assertEqual(code, EXIT_OK)
        hook = self.project / ".git" / "hooks" / "pre-commit"
        content = hook.read_text(encoding="utf-8")
        self.assertIn(str(hook.name), out)
        self.assertTrue(content.startswith("#!/bin/sh\n"))
        self.assertIn(HOOK_MARKER, content)
        self.assertIn("--staged", content)
        self.assertIn("--fail-on critical", content)
        self.assertNotIn("\r\n", hook.read_bytes().decode("utf-8"))
        if os.name == "posix":
            self.assertTrue(os.access(hook, os.X_OK))

        self.assertEqual(run_cli("install-hook", str(self.project))[0], EXIT_OK)
        self.assertIn("--fail-on high", hook.read_text(encoding="utf-8"))

    def test_install_hook_preserves_foreign_hook(self):
        hook = self.project / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\nnpm test\n", encoding="utf-8")

        code, _, err = run_cli("install-hook", str(self.project))
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("--force", err)
        self.assertIn("npm test", hook.read_text(encoding="utf-8"))

        self.assertEqual(run_cli("install-hook", str(self.project), "--force")[0], EXIT_OK)
        self.assertIn(HOOK_MARKER, hook.read_text(encoding="utf-8"))

    def test_install_hook_outside_repository(self):
        outside = self.root / "plain"
        outside.mkdir()
        with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(self.root)}):
            code, _, err = run_cli("install-hook", str(outside))
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("não é um repositório git", err)

    def test_pre_commit_hook_blocks_secrets_end_to_end(self):
        self.write("README.md", "# demo\n")
        self.assertEqual(self.commit_all("init").returncode, 0)
        self.assertEqual(run_cli("install-hook", str(self.project))[0], EXIT_OK)

        self.write("config.py", f"AWS_ACCESS_KEY_ID = '{AWS_KEY_ID}'\n")
        blocked = self.commit_all("add credentials")
        self.assertNotEqual(blocked.returncode, 0, msg=blocked.stdout + blocked.stderr)
        self.assertIn("aws-access-key-id", blocked.stdout + blocked.stderr)
        self.assertIn("ConfigGuard: commit bloqueado", blocked.stderr)
        self.assertEqual(self.git("rev-list", "--count", "HEAD").stdout.strip(), "1")

        self.write("config.py", "import os\nAWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']\n")
        allowed = self.commit_all("read credentials from env")
        self.assertEqual(allowed.returncode, 0, msg=allowed.stdout + allowed.stderr)
        self.assertEqual(self.git("rev-list", "--count", "HEAD").stdout.strip(), "2")

        rows = self.history_rows(self.project / ".git" / "configguard" / "audit_history.db")
        self.assertEqual([r[2] for r in rows], [1, 0])
        self.assertTrue(all(r[0] == "main" for r in rows))


if __name__ == "__main__":
    unittest.main()
