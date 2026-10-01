"""Базовые классы для проверок моделей."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TYPE_CHECKING

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


class Check(ABC):
    """Базовый класс для всех проверок."""
    name: str = 'base'
    description: str = 'Base check'

    def supports(self, file_path: Path) -> bool:
        """Применима ли проверка к файлу. По умолчанию — да."""
        return True

    @abstractmethod
    def run(
            self,
            file_path: Path,
            context: dict | None = None,
            progress: 'ProgressReporter | None' = None,
    ) -> CheckResult:
        """Запускает проверку."""
        pass




















