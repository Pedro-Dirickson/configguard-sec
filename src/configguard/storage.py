"""Persistência do histórico de auditorias e métricas de qualidade em SQLite."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path

from .audit import ScanResult
from .scanners.secrets import Severity

DEFAULT_DB_NAME = "audit_history.db"
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    branch          TEXT,
    commit_sha      TEXT,
    files_scanned   INTEGER NOT NULL,
    total_findings  INTEGER NOT NULL,
    critical        INTEGER NOT NULL,
    high            INTEGER NOT NULL,
    medium          INTEGER NOT NULL,
    low             INTEGER NOT NULL,
    score           REAL    NOT NULL,
    duration_ms     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category     TEXT    NOT NULL,
    rule_id      TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    file_path    TEXT    NOT NULL,
    line_number  INTEGER NOT NULL,
    description  TEXT    NOT NULL,
    evidence     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_target_branch ON scans(target, branch, id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def default_db_path() -> Path:
    return Path(os.environ.get("CONFIGGUARD_DB", DEFAULT_DB_NAME))


@dataclass(frozen=True)
class ScanRecord:
    id: int
    started_at: str
    target: str
    branch: str | None
    commit_sha: str | None
    files_scanned: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    score: float
    duration_ms: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class BranchMetrics:
    target: str
    branch: str | None
    scans: int
    last_score: float
    previous_score: float | None
    average_score: float
    best_score: float
    worst_score: float
    last_commit: str | None
    last_scan_at: str
    open_critical: int
    open_high: int

    @property
    def trend(self) -> float | None:
        if self.previous_score is None:
            return None
        return self.last_score - self.previous_score

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["trend"] = self.trend
        return data


class AuditStorage:
    """Repositório SQLite de execuções de scan e seus achados."""

    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(db_path) if db_path is not None else default_db_path()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def __enter__(self) -> AuditStorage:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _migrate(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def record(self, result: ScanResult) -> int:
        counts = result.severity_counts
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO scans (started_at, target, branch, commit_sha, files_scanned,
                                   total_findings, critical, high, medium, low, score, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.started_at,
                    result.target,
                    result.git.branch,
                    result.git.commit,
                    result.files_scanned,
                    len(result.findings),
                    counts[Severity.CRITICAL],
                    counts[Severity.HIGH],
                    counts[Severity.MEDIUM],
                    counts[Severity.LOW],
                    result.score,
                    result.duration_ms,
                ),
            )
            scan_id = int(cursor.lastrowid)
            self._conn.executemany(
                """
                INSERT INTO findings (scan_id, category, rule_id, severity, file_path,
                                      line_number, description, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (scan_id, f.category, f.rule_id, f.severity.value, f.file_path,
                     f.line_number, f.description, f.evidence)
                    for f in result.findings
                ],
            )
        return scan_id

    def list_scans(
        self,
        *,
        limit: int = 20,
        target: str | None = None,
        branch: str | None = None,
    ) -> list[ScanRecord]:
        clauses, params = self._filters(target, branch)
        rows = self._conn.execute(
            f"SELECT * FROM scans {clauses} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [ScanRecord(**dict(row)) for row in rows]

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return ScanRecord(**dict(row)) if row else None

    def findings_for(self, scan_id: int) -> list[dict[str, object]]:
        rows = self._conn.execute(
            """
            SELECT category, rule_id, severity, file_path, line_number, description, evidence
            FROM findings WHERE scan_id = ? ORDER BY id
            """,
            (scan_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def branch_metrics(self, target: str | None = None) -> list[BranchMetrics]:
        clauses, params = self._filters(target, None)
        groups = self._conn.execute(
            f"""
            SELECT target, branch, COUNT(*) AS scans, AVG(score) AS average_score,
                   MAX(score) AS best_score, MIN(score) AS worst_score, MAX(id) AS last_id
            FROM scans {clauses}
            GROUP BY target, branch
            ORDER BY MAX(id) DESC
            """,
            params,
        ).fetchall()

        metrics: list[BranchMetrics] = []
        for group in groups:
            last = self.get_scan(group["last_id"])
            assert last is not None
            previous = self._conn.execute(
                "SELECT score FROM scans WHERE target = ? AND branch IS ? AND id < ? ORDER BY id DESC LIMIT 1",
                (group["target"], group["branch"], group["last_id"]),
            ).fetchone()
            metrics.append(BranchMetrics(
                target=group["target"],
                branch=group["branch"],
                scans=group["scans"],
                last_score=last.score,
                previous_score=previous["score"] if previous else None,
                average_score=round(group["average_score"], 2),
                best_score=group["best_score"],
                worst_score=group["worst_score"],
                last_commit=last.commit_sha,
                last_scan_at=last.started_at,
                open_critical=last.critical,
                open_high=last.high,
            ))
        return metrics

    @staticmethod
    def _filters(target: str | None, branch: str | None) -> tuple[str, tuple[object, ...]]:
        conditions: list[str] = []
        params: list[object] = []
        if target is not None:
            conditions.append("target = ?")
            params.append(target)
        if branch is not None:
            conditions.append("branch = ?")
            params.append(branch)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return where, tuple(params)
