"""Relatórios de auditoria em terminal, JSON e Markdown."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Sequence, TextIO

from . import __version__
from .audit import SEVERITY_ORDER, AuditFinding, ScanResult
from .scanners.secrets import Severity
from .storage import BranchMetrics, ScanRecord

FORMATS = ("terminal", "json", "markdown")

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_GREEN = "\033[32m"
_RED = "\033[31m"


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text

    def severity(self, severity: Severity, text: str | None = None) -> str:
        return self(text or severity.value.upper(), _SEVERITY_COLORS[severity])


def _score_label(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "F"


def render_terminal(result: ScanResult, *, color: bool = False, fail_on: Severity | None = Severity.HIGH) -> str:
    style = _Style(color)
    lines = [
        style(f"ConfigGuard v{__version__} - relatório de auditoria", _BOLD),
        f"Alvo:     {result.target}",
    ]
    if result.git.branch or result.git.commit:
        commit = (result.git.commit or "sem commits")[:12]
        lines.append(f"Git:      {result.git.branch or '(detached)'} @ {commit}")
    lines.append(f"Arquivos: {result.files_scanned}  |  Duração: {result.duration_ms} ms")
    lines.append("")

    if not result.findings:
        lines.append(style("Nenhum problema encontrado.", _GREEN))
    else:
        for finding in result.findings:
            lines.extend(_terminal_finding(finding, style))

    counts = result.severity_counts
    summary = "  ".join(f"{style.severity(s, s.value)}: {counts[s]}" for s in SEVERITY_ORDER)
    lines.append("")
    lines.append(f"Resumo:   {summary}  |  total: {len(result.findings)}")
    lines.append(f"Nota:     {result.score:.0f}/100 ({_score_label(result.score)})")

    blocking = result.blocking_findings(fail_on)
    if fail_on is not None:
        if blocking:
            lines.append(style(f"Status:   REPROVADO ({len(blocking)} achado(s) >= {fail_on.value})", _RED))
        else:
            lines.append(style(f"Status:   APROVADO (limite: {fail_on.value})", _GREEN))
    return "\n".join(lines) + "\n"


def _terminal_finding(finding: AuditFinding, style: _Style) -> list[str]:
    location = f"{finding.file_path}:{finding.line_number}" if finding.line_number else finding.file_path
    return [
        f"[{style.severity(finding.severity)}] {style(location, _BOLD)}  {finding.description}",
        style(f"    {finding.rule_id} | {finding.evidence}", _DIM),
        *([style(f"    -> {finding.recommendation}", _DIM)] if finding.recommendation else []),
    ]


def to_json(result: ScanResult) -> str:
    payload = {"tool": "configguard", "version": __version__, **result.to_dict()}
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _md_cell(value: object) -> str:
    text = str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
    return text.replace("`", "'")


def to_markdown(result: ScanResult, *, fail_on: Severity | None = Severity.HIGH) -> str:
    counts = result.severity_counts
    blocking = result.blocking_findings(fail_on)
    status = "Reprovado" if blocking else "Aprovado"

    lines = [
        "# Relatório de Auditoria ConfigGuard",
        "",
        "| Campo | Valor |",
        "|---|---|",
        f"| Alvo | `{_md_cell(result.target)}` |",
        f"| Branch | {_md_cell(result.git.branch or '-')} |",
        f"| Commit | `{_md_cell((result.git.commit or '-')[:12])}` |",
        f"| Início (UTC) | {result.started_at} |",
        f"| Arquivos analisados | {result.files_scanned} |",
        f"| Nota de qualidade | **{result.score:.0f}/100 ({_score_label(result.score)})** |",
    ]
    if fail_on is not None:
        lines.append(f"| Status (limite `{fail_on.value}`) | **{status}** |")

    lines += ["", "## Resumo por severidade", "", "| Severidade | Quantidade |", "|---|---:|"]
    lines += [f"| {s.value} | {counts[s]} |" for s in SEVERITY_ORDER]
    lines.append(f"| **total** | **{len(result.findings)}** |")

    lines += ["", "## Achados", ""]
    if not result.findings:
        lines.append("Nenhum problema encontrado.")
    else:
        lines += [
            "| Severidade | Categoria | Arquivo | Linha | Regra | Descrição | Evidência |",
            "|---|---|---|---:|---|---|---|",
        ]
        for f in result.findings:
            lines.append(
                f"| {f.severity.value} | {f.category} | `{_md_cell(f.file_path)}` | {f.line_number or '-'} "
                f"| `{f.rule_id}` | {_md_cell(f.description)} | `{_md_cell(f.evidence)}` |"
            )
        recommendations = _unique_recommendations(result.findings)
        lines += ["", "## Recomendações", ""]
        lines += [f"- **{rule}**: {_md_cell(text)}" for rule, text in recommendations]
    return "\n".join(lines) + "\n"


def _unique_recommendations(findings: Iterable[AuditFinding]) -> list[tuple[str, str]]:
    seen: dict[str, str] = {}
    for finding in findings:
        if finding.recommendation and finding.rule_id not in seen:
            seen[finding.rule_id] = finding.recommendation
    return list(seen.items())


def render(result: ScanResult, fmt: str, *, color: bool = False, fail_on: Severity | None = Severity.HIGH) -> str:
    if fmt == "json":
        return to_json(result)
    if fmt == "markdown":
        return to_markdown(result, fail_on=fail_on)
    if fmt == "terminal":
        return render_terminal(result, color=color, fail_on=fail_on)
    raise ValueError(f"formato desconhecido: {fmt}")


def write_report(content: str, destination: str | os.PathLike[str]) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def render_history(
    scans: Sequence[ScanRecord],
    metrics: Sequence[BranchMetrics],
    *,
    color: bool = False,
) -> str:
    style = _Style(color)
    if not scans and not metrics:
        return "Nenhum scan registrado no histórico.\n"

    lines = [style("Métricas por branch", _BOLD)]
    header = (
        f"{'branch':<20} {'scans':>5} {'nota':>6} {'tend.':>6} {'média':>6} {'crit':>4} {'high':>4}  "
        f"{'commit':<12}  alvo"
    )
    lines += [header, "-" * len(header)]
    for m in metrics:
        trend = "-" if m.trend is None else f"{m.trend:+.0f}"
        lines.append(
            f"{_truncate(m.branch or '(sem git)', 20):<20} {m.scans:>5} {m.last_score:>6.0f} {trend:>6} "
            f"{m.average_score:>6.1f} {m.open_critical:>4} {m.open_high:>4}  {(m.last_commit or '-')[:12]:<12}  "
            f"{m.target}"
        )

    lines += ["", style("Scans recentes", _BOLD)]
    header = f"{'id':>4}  {'data (UTC)':<25} {'branch':<16} {'commit':<12} {'nota':>5} {'achados':>7}  alvo"
    lines += [header, "-" * len(header)]
    for s in scans:
        lines.append(
            f"{s.id:>4}  {s.started_at:<25} {_truncate(s.branch or '-', 16):<16} {(s.commit_sha or '-')[:12]:<12} "
            f"{s.score:>5.0f} {s.total_findings:>7}  {s.target}"
        )
    return "\n".join(lines) + "\n"


def history_to_json(scans: Sequence[ScanRecord], metrics: Sequence[BranchMetrics]) -> str:
    payload = {
        "branches": [m.to_dict() for m in metrics],
        "scans": [s.to_dict() for s in scans],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "~"
