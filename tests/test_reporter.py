import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from configguard.audit import AuditFinding, GitContext, ScanResult  # noqa: E402
from configguard.reporter import (  # noqa: E402
    history_to_json,
    render,
    render_history,
    render_terminal,
    to_json,
    to_markdown,
    write_report,
)
from configguard.scanners.secrets import Severity  # noqa: E402
from configguard.storage import AuditStorage  # noqa: E402


def make_result(findings=None):
    return ScanResult(
        target="/srv/app",
        started_at="2026-11-24T12:00:00+00:00",
        duration_ms=42,
        files_scanned=3,
        findings=findings if findings is not None else [
            AuditFinding(
                category="secret",
                rule_id="aws-access-key-id",
                severity=Severity.CRITICAL,
                file_path="config/settings.py",
                line_number=12,
                description="AWS Access Key ID",
                evidence="AKIA********NW",
                recommendation="Revogue a credencial.",
            ),
            AuditFinding(
                category="config",
                rule_id="debug-enabled",
                severity=Severity.MEDIUM,
                file_path="app|weird.env",
                line_number=1,
                description="Modo debug habilitado",
                evidence="DEBUG=True",
                recommendation="Desative o debug.",
            ),
        ],
        git=GitContext(branch="main", commit="0123456789abcdef" * 2 + "01234567"),
    )


class TerminalReportTests(unittest.TestCase):
    def test_plain_output_contains_findings_and_summary(self):
        output = render_terminal(make_result())
        self.assertIn("[CRITICAL] config/settings.py:12  AWS Access Key ID", output)
        self.assertIn("aws-access-key-id | AKIA********NW", output)
        self.assertIn("main @ 0123456789ab", output)
        self.assertIn("critical: 1", output)
        self.assertIn("Nota:     71/100 (C)", output)
        self.assertIn("REPROVADO (1 achado(s) >= high)", output)
        self.assertNotIn("\033[", output)

    def test_color_output_uses_ansi(self):
        self.assertIn("\033[", render_terminal(make_result(), color=True))

    def test_clean_result(self):
        output = render_terminal(make_result([]))
        self.assertIn("Nenhum problema encontrado.", output)
        self.assertIn("APROVADO", output)
        self.assertIn("100/100 (A)", output)

    def test_fail_on_threshold(self):
        self.assertIn("REPROVADO", render_terminal(make_result(), fail_on=Severity.MEDIUM))
        self.assertIn("APROVADO", render_terminal(make_result([make_result().findings[1]]), fail_on=Severity.HIGH))
        self.assertNotIn("Status:", render_terminal(make_result(), fail_on=None))


class JsonReportTests(unittest.TestCase):
    def test_structure(self):
        data = json.loads(to_json(make_result()))
        self.assertEqual(data["tool"], "configguard")
        self.assertEqual(data["branch"], "main")
        self.assertEqual(data["total_findings"], 2)
        self.assertEqual(data["summary"], {"critical": 1, "high": 0, "medium": 1, "low": 0})
        self.assertEqual(data["score"], 71.0)
        self.assertEqual(data["findings"][0]["rule_id"], "aws-access-key-id")
        self.assertEqual(data["findings"][0]["severity"], "critical")


class MarkdownReportTests(unittest.TestCase):
    def test_sections_and_tables(self):
        output = to_markdown(make_result())
        self.assertTrue(output.startswith("# Relatório de Auditoria ConfigGuard"))
        self.assertIn("## Resumo por severidade", output)
        self.assertIn("| critical | 1 |", output)
        self.assertIn("| Status (limite `high`) | **Reprovado** |", output)
        self.assertIn("`aws-access-key-id`", output)
        self.assertIn("## Recomendações", output)
        self.assertIn("- **debug-enabled**: Desative o debug.", output)

    def test_pipes_are_escaped(self):
        output = to_markdown(make_result())
        self.assertIn("app\\|weird.env", output)
        for line in output.splitlines():
            if line.startswith("| medium | config"):
                self.assertEqual(line.count(" | "), 6)

    def test_clean_result(self):
        output = to_markdown(make_result([]))
        self.assertIn("Nenhum problema encontrado.", output)
        self.assertNotIn("## Recomendações", output)


class RenderDispatchTests(unittest.TestCase):
    def test_render_by_format(self):
        result = make_result()
        self.assertEqual(render(result, "json"), to_json(result))
        self.assertEqual(render(result, "markdown"), to_markdown(result))
        self.assertEqual(render(result, "terminal"), render_terminal(result))
        with self.assertRaises(ValueError):
            render(result, "xml")

    def test_write_report_creates_parents(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_report("conteúdo", Path(tmp) / "out" / "report.md")
            self.assertEqual(path.read_text(encoding="utf-8"), "conteúdo")


class HistoryReportTests(unittest.TestCase):
    def test_history_rendering(self):
        with AuditStorage(":memory:") as storage:
            storage.record(make_result())
            storage.record(make_result([]))
            scans = storage.list_scans()
            metrics = storage.branch_metrics()

        text = render_history(scans, metrics)
        self.assertIn("Métricas por branch", text)
        self.assertIn("main", text)
        self.assertIn("+29", text)
        self.assertIn("/srv/app", text)

        data = json.loads(history_to_json(scans, metrics))
        self.assertEqual(len(data["scans"]), 2)
        self.assertEqual(data["branches"][0]["trend"], 29.0)

    def test_empty_history(self):
        self.assertEqual(render_history([], []), "Nenhum scan registrado no histórico.\n")


if __name__ == "__main__":
    unittest.main()
