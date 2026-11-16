"""Настройка логирования с ротацией и JSON-форматом."""
import json
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from contextlib import contextmanager


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "ts": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        if hasattr(record, "extra_data"):
            log_entry.update(record.extra_data)
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logger(log_path: Path, verbose: bool = False) -> logging.Logger:
    """Настраивает логгер с ротацией."""

    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("audit_llm")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)  # c8: чтобы check_done попадал в файл
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(console_handler)

    return logger


@contextmanager
def suppress_console_logging(logger: logging.Logger):
    """Временно отключает консольные handlers, оставляя файловые.

    Используется во время активного прогресс-бара, чтобы логи
    не перемешивались со строками прогресса.
    """
    # Отключаем все StreamHandler, которые пишут в консоль
    # (RotatingFileHandler — это FileHandler, а не StreamHandler, но он
    #  может быть подклассом; проверим точнее)
    console_handlers = []
    for h in logger.handlers[:]:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler):
            console_handlers.append(h)
            logger.removeHandler(h)

    try:
        yield
    finally:
        for h in console_handlers:
            logger.addHandler(h)





