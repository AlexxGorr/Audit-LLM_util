"""Интерактивная оболочка (REPL) для auditllm."""
import json
import logging
import shlex
import sys

from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, Completer, Completion
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import ANSI

from auditllm.config import Config
from auditllm.core import (
    cmd_audit, cmd_init, cmd_list, cmd_inbox, cmd_inspect,
    cmd_promote, cmd_report, cmd_reset,
)
from auditllm.trust import check_trust, status_from_score
from auditllm.progress import ProgressReporter


HISTORY_PATH = Path.home() / ".auditllm_history"

COMMANDS = [
    "audit", "init", "list", "inbox", "inspect", "promote",
    "report", "trust", "reset", "config", "help", "exit", "quit",
]

HELP_TEXT = """\
Доступные команды:
  init                                                      Создать эталон
  audit [--new-only] [--no-quarantine] [--update-etalon]   Запустить аудит
  list [--json]                                             Реестр моделей
  inbox [--new-only] [--json]                               Файлы в папке
  inspect <file> [--show hash,header,pickle] [--json]       Детали файла
  promote [<file>] [--force] [--dry-run]                    Добавить в эталон
  report [<file>] [--json]                                  Результат аудита
  trust <repo_id>                                           Репутация на HF
  reset [--yes]                                             Сбросить эталон
  config                                                    Текущие пути
  help                                                      Эта справка
  exit / quit                                               Выход

Горячие клавиши:
  Ctrl+C   Прервать ввод / очистить строку
  Ctrl+D   Выход из shell
  Ctrl+L   Очистить экран
  Ctrl+R   Поиск по истории команд
  Tab      Автодополнение команд и путей
"""


STYLE = Style.from_dict({
    "prompt": "ansiblue bold",
})


class ShellCompleter(Completer):
    """Дополняет команды и пути из models_dir."""

    def __init__(self, models_dir: Path):
        self.models_dir = models_dir
        self._commands = COMMANDS
        self._path_commands = {"inspect", "promote", "report"}

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        parts = text.split()

        # Первое слово — команда
        if len(parts) <= 1 and not text.endswith(" "):
            word = parts[0] if parts else ""
            for cmd in self._commands:
                if cmd.startswith(word):
                    yield Completion(cmd, start_position=-len(word))
            return

        # Если команда — path-команда, дополняем пути
        cmd = parts[0]
        if cmd in self._path_commands:
            # Последнее слово — префикс пути
            prefix = parts[-1] if not text.endswith(" ") else ""
            try:
                candidates = sorted(
                    p.relative_to(self.models_dir).as_posix()
                    for p in self.models_dir.rglob("*")
                    if p.is_file()
                )
            except OSError:
                return
            for cand in candidates:
                if cand.startswith(prefix):
                    yield Completion(cand, start_position=-len(prefix))


class AuditShell:
    """Интерактивная оболочка auditllm."""

    def __init__(self, config: Config, logger: logging.Logger, key: bytes):
        self.config = config
        self.logger = logger
        self.key = key
        self._use_tty = sys.stdin.isatty()
        self.session = self._make_session() if self._use_tty else None

    def _make_session(self) -> PromptSession:
        """Создаёт prompt_toolkit сессию с историей и автодополнением."""
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        return PromptSession(
            history=FileHistory(str(HISTORY_PATH)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=ShellCompleter(self.config.models_dir),
            key_bindings=self._make_key_bindings(),
            reserve_space_for_menu=0,
            style=STYLE,
        )

    @staticmethod
    def _make_key_bindings() -> KeyBindings:
        """Ctrl+C — прервать ввод, не выходить."""
        kb = KeyBindings()

        @kb.add("c-c")
        def _(event):
            event.app.current_buffer.reset()

        @kb.add("c-l")
        def _(event):
            event.app.renderer.clear()
            event.app.invalidate()

        return kb

    def run(self) -> int:
        """Главный цикл REPL."""
        print("auditllm shell — введи 'help' для справки, 'exit' для выхода")
        while True:
            try:
                if self._use_tty:
                    line = self.session.prompt(
                        ANSI("\x1b[34mauditllm>>> \x1b[0m")
                    ).strip()
                else:
                    line = input("auditllm>>> ").strip()
            except KeyboardInterrupt:
                # Ctrl+C в пустой строке — очистить, продолжить
                continue
            except EOFError:
                # Ctrl+D — выход
                print()
                return 0

            if not line:
                continue

            try:
                should_exit = self._dispatch(line)
            except Exception as e:
                print(f"🚨 Ошибка: {e}")
                self.logger.error("shell_command_failed", extra={"extra_data": {
                    "line": line, "error": str(e)
                }})
                continue

            if should_exit:
                return 0

    def _dispatch(self, line: str) -> bool:
        """Разбирает строку и вызывает команду. Возвращает True для выхода."""
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"🚨 Ошибка разбора: {e}")
            return False

        if not parts:
            return False

        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("exit", "quit"):
            print("До свидания.")
            return True
        if cmd == "help":
            print(HELP_TEXT)
            return False
        if cmd == "config":
            self._cmd_config()
            return False

        handler = getattr(self, f"_cmd_{cmd}", None)
        if handler is None:
            print(f"🚨 Неизвестная команда: {cmd!r}. Введи 'help'.")
            return False

        handler(args)
        return False

    # ─── Команды ────────────────────────────────────────────

    def _cmd_config(self) -> None:
        """Показать текущие пути."""
        print(f"  models_dir:     {self.config.models_dir}")
        print(f"  data_dir:       {self.config.data_dir}")
        print(f"  quarantine_dir: {self.config.quarantine_dir}")
        print(f"  etalon:         {self.config.etalon_path}")
        print(f"  state:          {self.config.state_path}")
        print(f"  log:            {self.config.log_path}")


    # ─── Read-only команды ─────────────────────────────────

    def _cmd_list(self, args: list[str]) -> None:
        """list [--json]"""
        as_json = "--json" in args
        code = cmd_list(self.config, self.logger, as_json=as_json)
        if code != 0:
            print(f"⚠️  list завершился с кодом {code}")

    def _cmd_inbox(self, args: list[str]) -> None:
        """inbox [--new-only] [--json]"""
        as_json = "--json" in args
        new_only = "--new-only" in args
        code = cmd_inbox(self.config, self.logger, as_json=as_json, new_only=new_only)
        if code != 0:
            print(f"⚠️  inbox завершился с кодом {code}")

    def _cmd_inspect(self, args: list[str]) -> None:
        """inspect <file> [--show hash,header,pickle] [--json] [--all]"""
        as_json = "--json" in args
        all_files = "--all" in args
        check_names = None
        paths = []
        i = 0
        while i < len(args):
            if args[i] == "--show" and i + 1 < len(args):
                check_names = args[i + 1].split(",")
                i += 2
            elif args[i].startswith("--"):
                i += 1
            else:
                paths.append(Path(args[i]))
                i += 1

        if not paths and not all_files:
            print("🚨 Укажи файлы или --all")
            return

        code = cmd_inspect(
            self.config, self.logger,
            paths=paths, all_files=all_files,
            check_names=check_names, as_json=as_json,
        )
        if code != 0:
            print(f"⚠️  inspect завершился с кодом {code}")

    def _cmd_report(self, args: list[str]) -> None:
        """report [<file>] [--json]"""
        as_json = "--json" in args
        paths = [Path(a) for a in args if not a.startswith("--")]
        code = cmd_report(self.config, self.logger, paths=paths or None, as_json=as_json)
        if code != 0:
            print(f"⚠️  report завершился с кодом {code}")

    def _cmd_trust(self, args: list[str]) -> None:
        """trust <repo_id> [--json] [--timeout N]"""
        if not args:
            print("🚨 Укажи repo_id: trust <author/model>")
            return
        repo_id = None
        as_json = False
        timeout = 5
        i = 0
        while i < len(args):
            if args[i] == "--json":
                as_json = True
                i += 1
            elif args[i] == "--timeout" and i + 1 < len(args):
                try:
                    timeout = int(args[i + 1])
                except ValueError:
                    print(f"🚨 --timeout: не число: {args[i + 1]}")
                    return
                i += 2
            elif not args[i].startswith("--"):
                repo_id = args[i]
                i += 1
            else:
                i += 1

        if not repo_id:
            print("🚨 Укажи repo_id: trust <author/model>")
            return

        from auditllm.cli import _print_trust_table, _print_trust_json
        result = check_trust(repo_id, timeout=timeout, show_spinner=not as_json)
        if as_json:
            _print_trust_json(result)
        else:
            _print_trust_table(result)

        if not result.exists:
            print(f"⚠️  Репозиторий не найден: {result.error}")
        else:
            status = status_from_score(result.trust_score)
            if status == "fail":
                print(f"🚨 Низкий trust: {result.trust_score}/100")
            elif status == "warn":
                print(f"⚠️  Средний trust: {result.trust_score}/100")


    # ─── Мутирующие команды ────────────────────────────────

    def _cmd_init(self, args: list[str]) -> None:
        """init — создать эталон."""
        progress = ProgressReporter(enabled=self._use_tty, use_tty=self._use_tty)
        code = cmd_init(self.config, self.logger, self.key, progress=progress)
        if code != 0:
            print(f"⚠️  init завершился с кодом {code}")

    def _cmd_audit(self, args: list[str]) -> None:
        """audit [--new-only] [--no-quarantine] [--update-etalon] [--allow-partial-update]"""
        new_only = "--new-only" in args
        no_quarantine = "--no-quarantine" in args
        update_etalon = "--update-etalon" in args
        allow_partial_update = "--allow-partial-update" in args

        if update_etalon and new_only and not allow_partial_update:
            print("🚨 --update-etalon с --new-only не удалит отсутствующие файлы.\n"
                  "   Используй полный audit или добавь --allow-partial-update.")
            return

        progress = ProgressReporter(enabled=self._use_tty, use_tty=self._use_tty)

        code = cmd_audit(
            self.config, self.logger, self.key,
            update_etalon=update_etalon,
            no_quarantine=no_quarantine,
            new_only=new_only,
            allow_partial_update=allow_partial_update,
            progress=progress,
        )
        if code != 0:
            print(f"⚠️  audit завершился с кодом {code}")

    def _cmd_promote(self, args: list[str]) -> None:
        """promote [<file>] [--force] [--dry-run] [--json]"""
        force = "--force" in args
        dry_run = "--dry-run" in args
        as_json = "--json" in args
        paths = [Path(a) for a in args if not a.startswith("--")]

        code = cmd_promote(
            self.config, self.logger, self.key,
            paths=paths or None,
            force=force,
            dry_run=dry_run,
            as_json=as_json,
        )
        if code != 0:
            print(f"⚠️  promote завершился с кодом {code}")

    def _cmd_reset(self, args: list[str]) -> None:
        """reset [--yes] [--no-backup]"""
        yes = "--yes" in args or "-y" in args
        no_backup = "--no-backup" in args

        code = cmd_reset(
            self.config, self.logger, self.key,
            no_backup=no_backup,
            yes=yes,
        )
        if code != 0:
            print(f"⚠️  reset завершился с кодом {code}")


def run_shell(config: Config, logger: logging.Logger, key: bytes) -> int:
    """Точка входа для cli.py:shell()."""
    shell = AuditShell(config, logger, key)
    return shell.run()




