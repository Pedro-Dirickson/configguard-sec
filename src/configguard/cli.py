"""Interface de linha de comando do ConfigGuard."""

from __future__ import annotations

import argparse
import os
import shlex
import stat
import sys
from pathlib import Path
from typing import Sequence

import configguard

from . import __version__
from .audit import git_path, git_toplevel, run_scan, staged_files
from .reporter import FORMATS, history_to_json, render, render_history, supports_color, write_report
from .scanners.secrets import Severity
from .storage import AuditStorage, default_db_path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

HOOK_MARKER = "# configguard-hook"
FAIL_ON_CHOICES = [s.value for s in Severity] + ["none"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="configguard",
        description="Audita repositórios em busca de segredos expostos e configurações inseguras.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{scan,history,install-hook}")

    scan = sub.add_parser("scan", help="varre um diretório ou arquivo")
    scan.add_argument("path", nargs="?", default=".", help="diretório ou arquivo alvo (padrão: .)")
    scan.add_argument("-f", "--format", choices=FORMATS, default="terminal")
    scan.add_argument("-o", "--output", help="grava o relatório neste arquivo")
    scan.add_argument(
        "--fail-on", choices=FAIL_ON_CHOICES, default=Severity.HIGH.value,
        help="severidade mínima que gera exit code 1 (padrão: high)",
    )
    scan.add_argument("--staged", action="store_true", help="analisa apenas arquivos em stage no git")
    scan.add_argument("--no-secrets", action="store_true", help="desativa o scanner de segredos")
    scan.add_argument("--no-configs", action="store_true", help="desativa o auditor de configurações")
    scan.add_argument("--no-entropy", action="store_true", help="desativa a análise de entropia")
    _add_db_options(scan)
    scan.add_argument("--no-history", action="store_true", help="não registra o scan no histórico")
    scan.add_argument("--no-color", action="store_true")
    scan.set_defaults(handler=cmd_scan)

    history = sub.add_parser("history", help="mostra histórico e métricas por branch")
    _add_db_options(history)
    history.add_argument("--target", help="filtra por diretório alvo")
    history.add_argument("--branch", help="filtra por branch")
    history.add_argument("-n", "--limit", type=int, default=20)
    history.add_argument("-f", "--format", choices=("terminal", "json"), default="terminal")
    history.add_argument("--no-color", action="store_true")
    history.set_defaults(handler=cmd_history)

    hook = sub.add_parser("install-hook", help="instala o hook pre-commit em um repositório git")
    hook.add_argument("path", nargs="?", default=".", help="repositório alvo (padrão: .)")
    hook.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default=Severity.HIGH.value)
    hook.add_argument("--force", action="store_true", help="sobrescreve um hook pre-commit existente")
    hook.set_defaults(handler=cmd_install_hook)
    return parser


def _add_db_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", help="arquivo SQLite do histórico (padrão: $CONFIGGUARD_DB ou ./audit_history.db)")


def _fail_on(value: str) -> Severity | None:
    return None if value == "none" else Severity(value)


def _db_path(value: str | None) -> Path:
    return Path(value) if value else default_db_path()


def _error(message: str) -> int:
    print(f"configguard: erro: {message}", file=sys.stderr)
    return EXIT_ERROR


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        return _error(f"caminho não encontrado: {target}")
    if args.no_secrets and args.no_configs:
        return _error("--no-secrets e --no-configs juntos desativam toda a análise")

    files = None
    if args.staged:
        root = git_toplevel(target)
        if root is None:
            return _error(f"--staged exige um repositório git: {target}")
        files = staged_files(root)
        target = root

    result = run_scan(
        target,
        files=files,
        scan_secrets=not args.no_secrets,
        scan_configs=not args.no_configs,
        entropy=not args.no_entropy,
    )
    fail_on = _fail_on(args.fail_on)

    if not args.no_history:
        with AuditStorage(_db_path(args.db)) as storage:
            storage.record(result)

    if args.output:
        path = write_report(render(result, args.format, fail_on=fail_on), args.output)
        print(f"Relatório salvo em {path}", file=sys.stderr)
    else:
        color = not args.no_color and args.format == "terminal" and supports_color(sys.stdout)
        sys.stdout.write(render(result, args.format, color=color, fail_on=fail_on))

    return EXIT_FINDINGS if result.blocking_findings(fail_on) else EXIT_OK


def cmd_history(args: argparse.Namespace) -> int:
    db = _db_path(args.db)
    if not db.exists():
        return _error(f"histórico não encontrado: {db}")
    target = str(Path(args.target).resolve()) if args.target else None
    with AuditStorage(db) as storage:
        scans = storage.list_scans(limit=args.limit, target=target, branch=args.branch)
        metrics = storage.branch_metrics(target)
    if args.branch is not None:
        metrics = [m for m in metrics if m.branch == args.branch]

    if args.format == "json":
        sys.stdout.write(history_to_json(scans, metrics))
    else:
        color = not args.no_color and supports_color(sys.stdout)
        sys.stdout.write(render_history(scans, metrics, color=color))
    return EXIT_OK


def build_hook_script(fail_on: str, python: str | None = None) -> str:
    interpreter = Path(python or sys.executable).as_posix()
    package_root = Path(configguard.__file__).resolve().parent.parent.as_posix()
    return f"""#!/bin/sh
{HOOK_MARKER} v{__version__}
# Gerado por 'configguard install-hook'. Reinstale com --force para alterar.
cd "$(git rev-parse --show-toplevel)" || exit 2
PYTHONPATH={shlex.quote(package_root)}"${{PYTHONPATH:+{os.pathsep}$PYTHONPATH}}"
export PYTHONPATH
{shlex.quote(interpreter)} -m configguard scan --staged --no-color --fail-on {shlex.quote(fail_on)} \\
    --db "$(git rev-parse --git-dir)/configguard/audit_history.db" .
status=$?
if [ "$status" -ne 0 ]; then
    echo "ConfigGuard: commit bloqueado. Corrija os achados acima ou use 'git commit --no-verify' conscientemente." >&2
fi
exit "$status"
"""


def cmd_install_hook(args: argparse.Namespace) -> int:
    repo = Path(args.path)
    if git_toplevel(repo) is None:
        return _error(f"não é um repositório git: {repo}")
    hooks_dir = git_path(repo, "hooks")
    if hooks_dir is None:
        return _error("não foi possível localizar o diretório de hooks")

    hook = hooks_dir / "pre-commit"
    if hook.exists() and not args.force:
        existing = hook.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER not in existing:
            return _error(f"já existe um hook pre-commit em {hook}; use --force para substituí-lo")

    hooks_dir.mkdir(parents=True, exist_ok=True)
    with open(hook, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(build_hook_script(args.fail_on))
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Hook pre-commit instalado em {hook} (fail-on: {args.fail_on})")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
