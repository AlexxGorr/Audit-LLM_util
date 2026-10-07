"""CLI-интерфейс audit-llm на основе typer."""
import logging
import sys
import typer

from pathlib import Path

from auditllm.config import load_secret_key, load_config, Config
from auditllm.logging_setup import setup_logger, suppress_console_logging
from auditllm.progress import ProgressReporter
from auditllm.core import cmd_audit, cmd_init, cmd_list, cmd_inbox, cmd_inspect

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
    # Ранняя проверка: явно указанный --config должен существовать
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
    """Создаёт ProgressReporter с авто-детектом TTY.

    Прогресс отключается, если:
    - явно указан --no-progress
    - stdout не является TTY (pipe, redirect)
    """
    if no_progress or not sys.stdout.isatty():
        return ProgressReporter(enabled=False)
    return ProgressReporter(enabled=True, use_tty=True)


@app.command()
def init(
    config_path: Path | None = typer.Option(None, "--config", help="Путь к config.toml"),
    models_dir: Path | None = typer.Option(None, "--models-dir", help="Переопределить папку моделей"),
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Переопределить папку данных"),
    quarantine_dir: Path | None = typer.Option(None, "--quarantine-dir", help="Переопределить карантин"),
    no_progress: bool = typer.Option(False, "--no-progress", help="Отключить прогресс-бар"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Подробный вывод"),
):
    """Создать эталон: запомнить хеши всех моделей в папке."""
    config, logger, key = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    progress = _make_progress(no_progress=no_progress)
    try:
        if progress.enabled and progress.use_tty:
            # Прогресс активен — подавляем консольные логи
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


@app.command()
def audit(
    config_path: Path | None = typer.Option(None, "--config", help="Путь к config.toml"),
    models_dir: Path | None = typer.Option(None, "--models-dir", help="Переопределить папку моделей"),
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Переопределить папку данных"),
    quarantine_dir: Path | None = typer.Option(None, "--quarantine-dir", help="Переопределить карантин"),
    update_etalon: bool = typer.Option(
        False, "--update-etalon",
        help="Обновить эталон: добавить новые, убрать удалённые "
             "(modified не обновляются!)"
    ),
    no_quarantine: bool = typer.Option(
        False, "--no-quarantine",
        help="Не перемещать подозрительные файлы в карантин"
    ),
    check: list[str] | None = typer.Option(
        None, "--check",
        help="Проверки для запуска (можно несколько: --check hash --check header). "
             "По умолчанию — все зарегистрированные.",
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Подробный вывод"),
    no_progress: bool = typer.Option(False, "--no-progress", help="Отключить прогресс-бар"),
):
    """Запустить аудит: сравнить модели с эталоном."""
    config, logger, key = _prepare(
        config_path, models_dir, data_dir, quarantine_dir, verbose
    )
    progress = _make_progress(no_progress=no_progress)
    try:
        if progress.enabled and progress.use_tty:
            # Прогресс активен — подавляем консольные логи
            with suppress_console_logging(logger):
                code = cmd_audit(config, logger, key,
                                 update_etalon=update_etalon,
                                 no_quarantine=no_quarantine,
                                 progress=progress,
                                 check_names=check
                                 )
        else:
            code = cmd_audit(config, logger, key,
                             update_etalon=update_etalon,
                             no_quarantine=no_quarantine,
                             progress=progress,
                             check_names=check
                             )
    except KeyboardInterrupt:
        progress.finish()
        typer.echo("\n🚫 Отменено пользователем", err=True)
        raise typer.Exit(130)
    if code != 0:
        typer.echo(f"⚠️  Аудит завершился с кодом {code}. "
                   f"Подробности: {config.log_path}", err=True)

    raise typer.Exit(code)


@app.command("list")
def list_models(
        config_path: Path | None = typer.Option(None, "--config", help="Путь к config.toml"),
        models_dir: Path | None = typer.Option(None, "--models-dir", help="Переопределить папку моделей"),
        data_dir: Path | None = typer.Option(None, "--data-dir", help="Переопределить папку данных"),
        quarantine_dir: Path | None = typer.Option(None, "--quarantine-dir", help="Переопределить карантин"),
        as_json: bool = typer.Option(False, "--json", help="Вывод в JSON (для CI/CD)"),
        verbose: bool = typer.Option(False, "-v", "--verbose", help="Подробный вывод"),
):
    """Показать реестр проверенных моделей.

        Источник — models_state.json. Показывает все модели, которые когда-либо
        проходили проверку, включая отсутствующие на диске сейчас.
        Для просмотра того, что лежит в папке сейчас — команда inbox.
    """
    config, logger, _ = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_list(config, logger, as_json=as_json))


@app.command()
def report(
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Подробный вывод"),
):
    """Показать последний отчёт аудита."""
    typer.echo("🚧 Команда 'report' ещё не реализована")
    raise typer.Exit(0)


@app.command()
def shell():
    """Интерактивная оболочка (REPL)."""
    typer.echo("🚧 Команда 'shell' ещё не реализована")
    raise typer.Exit(0)


@app.command("inbox")
def inbox(
    config_path: Path | None = typer.Option(None, "--config", help="Путь к config.toml"),
    models_dir: Path | None = typer.Option(None, "--models-dir", help="Переопределить папку моделей"),
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Переопределить папку данных"),
    quarantine_dir: Path | None = typer.Option(None, "--quarantine-dir", help="Переопределить карантин"),
    new_only: bool = typer.Option(False, "--new-only", help="Только непроверенные (новые)"),
    as_json: bool = typer.Option(False, "--json", help="Вывод в JSON (для CI/CD)"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Подробный вывод"),
):
    """Показать файлы в папке моделей (транзитная папка inbox).

    Источник — файловая система. Показывает, что лежит в папке сейчас,
    и связывает с реестром (models_state.json).
    """
    config, logger, _ = _prepare(config_path, models_dir, data_dir, quarantine_dir, verbose)
    raise typer.Exit(cmd_inbox(config, logger, as_json=as_json, new_only=new_only))


@app.command()
def inspect(
        paths: list[Path] = typer.Argument(
            None,
            help="Файлы для просмотра (можно несколько)",
        ),
        all_files: bool = typer.Option(
            False, "--all",
            help="Показать все файлы в папке моделей",
        ),
        show: list[str] | None = typer.Option(
            None, "--show",
            help="Показать только указанные проверки "
                 "(можно несколько: --show header --show hash)",
        ),
        as_json: bool = typer.Option(False, "--json", help="Вывод в JSON (для CI/CD)"),
        config_path: Path | None = typer.Option(None, "--config", help="Путь к config.toml"),
        models_dir: Path | None = typer.Option(None, "--models-dir", help="Переопределить папку моделей"),
        data_dir: Path | None = typer.Option(None, "--data-dir", help="Переопределить папку данных"),
        quarantine_dir: Path | None = typer.Option(None, "--quarantine-dir", help="Переопределить карантин"),
        verbose: bool = typer.Option(False, "-v", "--verbose", help="Подробный вывод"),
):
    """Показать содержимое файлов (без сохранения в реестр).

    Запускает проверки для указанных файлов и показывает результат.
    Не изменяет models_state.json, не перемещает в карантин.
    """
    # Проверка: хотя бы что-то указано
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


# if __name__ == "__main__":
#     app()

