"""CLI-интерфейс audit-llm на основе typer."""
import logging
import sys
import typer
import json
import shutil

from pathlib import Path

from auditllm.config import load_secret_key, load_config, Config
from auditllm.logging_setup import setup_logger, suppress_console_logging
from auditllm.progress import ProgressReporter
from auditllm.trust import check_trust, status_from_score
from auditllm.core import (
    cmd_audit, cmd_init, cmd_list, cmd_inbox, cmd_inspect,
    cmd_promote, cmd_report, cmd_reset,
)

app = typer.Typer(
    name="auditllm",
    help="Аудит локальных LLM: проверка целостности файлов моделей",
    no_args_is_help=True,
)


def _prepare(
        config_path: Path | None,
        models_dir: Path | None,
        data_dir: Path | None,
        quarantine_dir: Path | None,
        verbose: bool,
) -> tuple[Config, logging.Logger, bytes]:
    """Общий setup: конфиг + логгер + ключ."""
    if config_path is not None and not config_path.is_file():
        typer.echo(f"🚨 Конфиг не найден: {config_path}", err=True)
        raise typer.Exit(1)

    config = load_config(
        config_path=config_path or Path("config.toml"),
        models_dir=models_dir,
        data_dir=data_dir,
        quarantine_dir=quarantine_dir,
    )
    logger = setup_logger(config.log_path, verbose=verbose)
    try:
        key = load_secret_key()
    except ValueError as e:
        logger.error("secret_key_invalid", extra={"extra_data": {"error": str(e)}})
        raise typer.Exit(1)
    return config, logger, key


def _make_progress(no_progress: bool = False) -> ProgressReporter:
    """Создаёт ProgressReporter с авто-детектом TTY."""
    if no_progress or not sys.stdout.isatty():
        return ProgressReporter(enabled=False)
    return ProgressReporter(enabled=True, use_tty=True)


# ─── init ───────────────────────────────────────────────
@app.command()
def init(
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    no_progress: bool = typer.Option(
        False, "--no-progress",
        help="Отключить прогресс-бар",
        rich_help_panel="Output",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Создать эталон: запомнить хеши всех моделей в папке."""
    config, logger, key = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    progress = _make_progress(no_progress=no_progress)
    try:
        if progress.enabled and progress.use_tty:
            with suppress_console_logging(logger):
                code = cmd_init(config, logger, key, progress=progress)
        else:
            code = cmd_init(config, logger, key, progress=progress)
    except KeyboardInterrupt:
        progress.finish()
        typer.echo("\n🚫 Отменено пользователем", err=True)
        raise typer.Exit(130)
    if code != 0:
        typer.echo(
            f"⚠️  Init завершился с кодом {code}. "
            f"Подробности: {config.log_path}",
            err=True,
        )
    raise typer.Exit(code)


# ─── audit ──────────────────────────────────────────────
@app.command()
def audit(
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    update_etalon: bool = typer.Option(
        False, "--update-etalon",
        help="Обновить эталон: добавить новые, убрать удалённые "
             "(modified не обновляются!)",
        rich_help_panel="Audit Behavior",
    ),
    no_quarantine: bool = typer.Option(
        False, "--no-quarantine",
        help="Не перемещать подозрительные файлы в карантин",
        rich_help_panel="Audit Behavior",
    ),
    new_only: bool = typer.Option(
        False, "--new-only",
        help="Проверять только файлы, которых нет в эталоне (быстро). "
             "Существующие файлы не перепроверяются.",
        rich_help_panel="Audit Behavior",
    ),
    check: list[str] | None = typer.Option(
        None, "--check",
        help="Проверки для запуска (можно несколько: --check hash --check header). "
             "По умолчанию — все зарегистрированные.",
        rich_help_panel="Audit Behavior",
    ),
    no_progress: bool = typer.Option(
        False, "--no-progress",
        help="Отключить прогресс-бар",
        rich_help_panel="Output",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Запустить аудит: сравнить модели с эталоном."""
    config, logger, key = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    progress = _make_progress(no_progress=no_progress)
    try:
        if progress.enabled and progress.use_tty:
            with suppress_console_logging(logger):
                code = cmd_audit(
                    config, logger, key,
                    update_etalon=update_etalon,
                    no_quarantine=no_quarantine,
                    new_only=new_only,
                    progress=progress,
                    check_names=check,
                )
        else:
            code = cmd_audit(
                config, logger, key,
                update_etalon=update_etalon,
                no_quarantine=no_quarantine,
                new_only=new_only,
                progress=progress,
                check_names=check,
            )
    except KeyboardInterrupt:
        progress.finish()
        typer.echo("\n🚫 Отменено пользователем", err=True)
        raise typer.Exit(130)
    if code != 0:
        typer.echo(f"⚠️  Аудит завершился с кодом {code}. "
                   f"Подробности: {config.log_path}", err=True)
    raise typer.Exit(code)


# ─── list ───────────────────────────────────────────────
@app.command("list")
def list_models(
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    as_json: bool = typer.Option(
        False, "--json",
        help="Вывод в JSON (для CI/CD)",
        rich_help_panel="Output",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Показать реестр проверенных моделей.

    Источник — models_state.json. Показывает все модели, которые когда-либо
    проходили проверку, включая отсутствующие на диске сейчас.
    Для просмотра того, что лежит в папке сейчас — команда inbox.
    """
    config, logger, _ = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_list(config, logger, as_json=as_json))


# ─── report ─────────────────────────────────────────────
@app.command()
def report(
    paths: list[Path] = typer.Argument(
        None,
        help="Файлы для просмотра (если не указано — последний audit из лога)",
    ),
    as_json: bool = typer.Option(
        False, "--json",
        help="JSON-вывод",
        rich_help_panel="Output",
    ),
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Показать результат последней проверки.

    Без аргументов — последний audit из лога (diff).
    С файлами — детали из state (мгновенно, без сканирования).
    """
    config, logger, _ = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_report(config, logger, paths=paths, as_json=as_json))


# ─── reset ──────────────────────────────────────────────
@app.command("reset")
def reset(
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    no_backup: bool = typer.Option(
        False, "--no-backup",
        help="Не создавать бэкап (опасно)",
        rich_help_panel="Reset Behavior",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Без подтверждения (для CI/CD)",
        rich_help_panel="Reset Behavior",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Сбросить эталон, state и лог с бэкапом.

    Начало с чистого листа. Модели и карантин не трогаются.
    Бэкапы — в data/backups/.
    """
    config, logger, key = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_reset(config, logger, key, no_backup=no_backup, yes=yes))


# ─── inbox ──────────────────────────────────────────────
@app.command("inbox")
def inbox(
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    new_only: bool = typer.Option(
        False, "--new-only",
        help="Только непроверенные (новые)",
        rich_help_panel="Output",
    ),
    as_json: bool = typer.Option(
        False, "--json",
        help="Вывод в JSON (для CI/CD)",
        rich_help_panel="Output",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Показать файлы в папке моделей (транзитная папка inbox).

    Источник — файловая система. Показывает, что лежит в папке сейчас,
    и связывает с реестром (models_state.json).
    """
    config, logger, _ = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_inbox(config, logger, as_json=as_json, new_only=new_only))


# ─── inspect ────────────────────────────────────────────
@app.command()
def inspect(
    paths: list[Path] = typer.Argument(
        None,
        help="Файлы для просмотра (можно несколько)",
    ),
    all_files: bool = typer.Option(
        False, "--all",
        help="Показать все файлы в папке моделей",
        rich_help_panel="Inspect Behavior",
    ),
    show: list[str] | None = typer.Option(
        None, "--show",
        help="Проверки для показа. "
             "По умолчанию: header, pickle (быстрые). "
             "Для hash: --show hash (медленно — читает весь файл).",
        rich_help_panel="Inspect Behavior",
    ),
    as_json: bool = typer.Option(
        False, "--json",
        help="Вывод в JSON (для CI/CD)",
        rich_help_panel="Output",
    ),
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Показать содержимое файлов (без сохранения в реестр).

    Запускает проверки для указанных файлов и показывает результат.
    Не изменяет models_state.json, не перемещает в карантин.

    По умолчанию запускает БЫСТРЫЕ проверки (header, pickle).
    Для проверки хеша используй --show hash (читает весь файл).
    """
    if not paths and not all_files:
        typer.echo("🚨 Укажи файлы или --all", err=True)
        raise typer.Exit(1)

    config, logger, _ = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_inspect(
        config, logger,
        paths=paths,
        all_files=all_files,
        check_names=show,
        as_json=as_json,
    ))


# ─── promote ────────────────────────────────────────────
@app.command("promote")
def promote(
    paths: list[Path] = typer.Argument(
        None,
        help="Файлы (если не указано — все из state)",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Добавить даже файлы с fail-проверками",
        rich_help_panel="Promote Behavior",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Показать, что будет добавлено, но не менять эталон",
        rich_help_panel="Promote Behavior",
    ),
    as_json: bool = typer.Option(
        False, "--json",
        help="JSON-вывод",
        rich_help_panel="Output",
    ),
    config_path: Path | None = typer.Option(
        None, "--config",
        help="Путь к config.toml",
        rich_help_panel="Configuration",
    ),
    models_dir: Path | None = typer.Option(
        None, "--models-dir",
        help="Переопределить папку моделей",
        rich_help_panel="Path Overrides",
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir",
        help="Переопределить папку данных",
        rich_help_panel="Path Overrides",
    ),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir",
        help="Переопределить карантин",
        rich_help_panel="Path Overrides",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Добавить проверенные файлы из state в эталон (без сканирования).

    Берёт результаты последнего audit из models_state.json.
    Для файлов без fail — добавляет. С --force — даже fail.
    """
    config, logger, key = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_promote(
        config, logger, key,
        paths=paths,
        force=force,
        dry_run=dry_run,
        as_json=as_json,
    ))


# ─── shell ──────────────────────────────────────────────
@app.command()
def shell():
    """Интерактивная оболочка (REPL)."""
    typer.echo("🚧 Команда 'shell' ещё не реализована")
    raise typer.Exit(0)


# ─── trust ──────────────────────────────────────────────
@app.command()
def trust(
    repo_id: str = typer.Argument(..., help="HuggingFace repo ID, e.g. meta-llama/Llama-2-7b"),
    timeout: int = typer.Option(
        5, "--timeout",
        help="HTTP timeout в секундах",
        rich_help_panel="Output",
    ),
    as_json: bool = typer.Option(
        False, "--json",
        help="JSON output",
        rich_help_panel="Output",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Подробный вывод",
        rich_help_panel="Output",
    ),
):
    """Проверить репутацию репозитория на HuggingFace.

    Не проверяет содержимое файлов. Для аудита — команда audit.
    """
    result = check_trust(repo_id, timeout=timeout)

    if as_json:
        _print_trust_json(result)
    else:
        _print_trust_table(result)

    if not result.exists:
        raise typer.Exit(1)
    status = status_from_score(result.trust_score)
    if status == "fail":
        raise typer.Exit(2)
    if status == "warn":
        raise typer.Exit(1)
    raise typer.Exit(0)


def _print_trust_table(result):
    """Простой вывод trust-проверки."""
    print()
    print(f"🔍 Trust check: {result.repo_id}")
    print()

    if not result.exists:
        print(f"❌ {result.error}")
        print()
        return

    print(f"  Author:       {result.author}"
          + (" (official)" if result.author_official else ""))
    print(f"  Downloads:    {result.downloads:,}")
    print(f"  Likes:        {result.likes:,}")
    print(f"  Created:      {result.created_at[:10] if result.created_at else '?'}")
    print(f"  Last update:  {result.last_modified[:10] if result.last_modified else '?'}")
    print(f"  License:      {result.license or '—'}")
    print(f"  Model card:   {'✓' if result.has_model_card else '✗'}")
    print(f"  Files:        {result.files_count}")
    print(f"  Gated:        {result.gated}")
    print()

    print(f"  Trust score:  {result.trust_score}/100")
    print()

    for reason in result.reasons:
        sign = reason.get("sign", "0")
        marker = {"+": "✓", "-": "✗", "0": "○"}.get(sign, "·")
        print(f"    {marker} {reason['text']}")

    print()
    status = status_from_score(result.trust_score)
    label = {
        "pass": "✅ TRUSTED",
        "warn": "⚠️  CAUTION",
        "fail": "🚨 LOW TRUST",
    }.get(status, "?")
    print(f"  {label}")
    print()


def _print_trust_json(result):
    """JSON-вывод trust-проверки."""
    output = {
        "repo_id": result.repo_id,
        "exists": result.exists,
        "author": result.author,
        "author_official": result.author_official,
        "downloads": result.downloads,
        "likes": result.likes,
        "created_at": result.created_at,
        "last_modified": result.last_modified,
        "license": result.license,
        "has_model_card": result.has_model_card,
        "files_count": result.files_count,
        "trust_score": result.trust_score,
        "reasons": result.reasons,
        "duration_ms": result.duration_ms,
        "error": result.error,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


# if __name__ == "__main__":
#     app()
















