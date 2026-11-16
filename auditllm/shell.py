"""Интерактивная оболочка (REPL) для auditllm."""
import logging
import shlex
from pathlib import Path
import sys

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings

from auditllm.config import Config
from auditllm.core import (
    cmd_audit, cmd_list, cmd_inbox, cmd_inspect,
    cmd_promote, cmd_report, cmd_reset,
)
from auditllm.trust import check_trust, status_from_score


HISTORY_PATH = Path.home() / ".auditllm_history"

COMMANDS = [
    "audit", "list", "inbox", "inspect", "promote",
    "report", "trust", "reset", "config", "help", "exit", "quit",
]

HELP_TEXT = """\
Доступные команды:
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
  exit / quit                                               Выход (Ctrl+D)
"""


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
            completer=WordCompleter(COMMANDS, ignore_case=True),
            key_bindings=self._make_key_bindings(),
        )

    @staticmethod
    def _make_key_bindings() -> KeyBindings:
        """Ctrl+C — прервать ввод, не выходить."""
        kb = KeyBindings()

        @kb.add("c-c")
        def _(event):
            event.app.current_buffer.reset()

        return kb

    def run(self) -> int:
        """Главный цикл REPL."""
        print("auditllm shell — введи 'help' для справки, 'exit' для выхода")
        while True:
            try:
                if self._use_tty:
                    line = self.session.prompt("auditllm>>>> ").strip()
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


def run_shell(config: Config, logger: logging.Logger, key: bytes) -> int:
    """Точка входа для cli.py:shell()."""
    shell = AuditShell(config, logger, key)
    return shell.run()




