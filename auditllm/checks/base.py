"""Базовые классы для проверок моделей."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


CheckStatus = Literal["pass", "fail", "warn", "skip"]

@dataclass
class CheckResult:
    """Результат выполнения проверки."""
    status: CheckStatus
    message: str
    details: dict = field(default_factory=dict)
    duration_ms: int = 0
    severity: str = "critical"   # C1: critical/major/minor
    suggestion: str = ""          # C6: подсказка


class Check(ABC):
    """Базовый класс для всех проверок."""
    name: str = 'base'
    description: str = 'Base check'
    # d1: контракт — какие расширения поддерживает проверка.
    # Пустое множество = проверка не ограничивает расширения (например, hash).
    SUPPORTED: set[str] = set()

    def supports(self, file_path: Path) -> bool:
        """Применима ли проверка к файлу. По умолчанию — да."""
        return True

    @abstractmethod
    def run(
            self,
            file_path: Path,
            context: dict | None = None,
            progress: 'ProgressReporter | None' = None,
            cancel_check: 'Callable[[], bool] | None' = None,
    ) -> CheckResult:
        """Запускает проверку.

        Args:
            file_path: путь к файлу
            context: эталонные данные (например, {hash, size})
            progress: репортер прогресса
            cancel_check: если возвращает True — прервать проверку
        """
        pass




















