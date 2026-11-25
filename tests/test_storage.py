import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from configguard.audit import AuditFinding, GitContext, ScanResult, quality_score  # noqa: E402
from configguard.scanners.secrets import Severity  # noqa: E402
from configguard.storage import AuditStorage  # noqa: E402


def finding(severity, rule_id="rule", path="app.py", line=1):
    return AuditFinding(
        category="secret",
        rule_id=rule_id,
        severity=severity,
        file_path=path,
        line_number=line,
        description="desc",
        evidence="ab********yz",
    )


def result(findings=(), branch="main", commit="a" * 40, target="/repo"):
    return ScanResult(
        target=target,
        started_at="2026-11-24T12:00:00+00:00",
        duration_ms=12,
        files_scanned=5,
        findings=list(findings),
        git=GitContext(branch=branch, commit=commit),
    )


class QualityScoreTests(unittest.TestCase):
    def test_clean_scan_scores_100(self):
        self.assertEqual(quality_score([]), 100.0)

    def test_weights_by_severity(self):
        findings = [finding(Severity.CRITICAL), finding(Severity.HIGH), finding(Severity.MEDIUM), finding(Severity.LOW)]
        self.assertEqual(quality_score(findings), 100.0 - 25 - 10 - 4 - 1)

    def test_score_never_negative(self):
        self.assertEqual(quality_score([finding(Severity.CRITICAL)] * 10), 0.0)


class AuditStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "nested" / "audit_history.db"
        self.storage = AuditStorage(self.db_path)

    def tearDown(self):
        self.storage.close()
        self._tmp.cleanup()

    def test_creates_database_and_parent_dirs(self):
        self.assertTrue(self.db_path.exists())

    def test_record_and_read_back(self):
        scan_id = self.storage.record(result([finding(Severity.CRITICAL, "aws-access-key-id", "cfg.py", 7)]))
        record = self.storage.get_scan(scan_id)
        self.assertEqual(record.branch, "main")
        self.assertEqual(record.critical, 1)
        self.assertEqual(record.total_findings, 1)
        self.assertEqual(record.score, 75.0)
        self.assertEqual(self.storage.findings_for(scan_id), [{
            "category": "secret",
            "rule_id": "aws-access-key-id",
            "severity": "critical",
            "file_path": "cfg.py",
            "line_number": 7,
            "description": "desc",
            "evidence": "ab********yz",
        }])

    def test_list_scans_newest_first_with_filters(self):
        self.storage.record(result(branch="main"))
        self.storage.record(result(branch="feature/x"))
        self.storage.record(result(branch="main", target="/other"))

        self.assertEqual([s.id for s in self.storage.list_scans()], [3, 2, 1])
        self.assertEqual([s.id for s in self.storage.list_scans(branch="main")], [3, 1])
        self.assertEqual([s.id for s in self.storage.list_scans(target="/repo")], [2, 1])
        self.assertEqual(len(self.storage.list_scans(limit=1)), 1)

    def test_branch_metrics_and_trend(self):
        self.storage.record(result([finding(Severity.HIGH)] * 3, commit="1" * 40))
        self.storage.record(result([finding(Severity.HIGH)], commit="2" * 40))
        self.storage.record(result([], branch="dev", commit="3" * 40))

        metrics = {m.branch: m for m in self.storage.branch_metrics("/repo")}
        main = metrics["main"]
        self.assertEqual(main.scans, 2)
        self.assertEqual(main.last_score, 90.0)
        self.assertEqual(main.previous_score, 70.0)
        self.assertEqual(main.trend, 20.0)
        self.assertEqual(main.average_score, 80.0)
        self.assertEqual(main.worst_score, 70.0)
        self.assertEqual(main.last_commit, "2" * 40)
        self.assertEqual(main.open_high, 1)
        self.assertIsNone(metrics["dev"].trend)

    def test_scans_without_git_are_grouped(self):
        self.storage.record(result(branch=None, commit=None))
        self.storage.record(result(branch=None, commit=None))
        metrics = self.storage.branch_metrics()
        self.assertEqual(len(metrics), 1)
        self.assertIsNone(metrics[0].branch)
        self.assertEqual(metrics[0].scans, 2)
        self.assertEqual(metrics[0].previous_score, 100.0)

    def test_persists_across_connections(self):
        self.storage.record(result())
        self.storage.close()
        with AuditStorage(self.db_path) as reopened:
            self.assertEqual(len(reopened.list_scans()), 1)
        self.storage = AuditStorage(self.db_path)

    def test_findings_cascade_on_scan_delete(self):
        scan_id = self.storage.record(result([finding(Severity.LOW)]))
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        self.assertEqual(self.storage.findings_for(scan_id), [])


if __name__ == "__main__":
    unittest.main()
