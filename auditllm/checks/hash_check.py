"""Проверка SHA-256 хеша файла."""
from auditllm.checks.base import CheckResult, Check
from auditllm.hashing import get_file_hash
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter



class HashCheck(Check):
    """Проверка SHA-256 хеша."""

    name = "hash"
    description = "SHA-256 hash verification"

    def supports(self, file_path: Path) -> bool:
        """Применима ко всем файлам моделей."""
        return True

    def run(
            self,
            file_path: Path,
            context: dict | None = None,
            progress: "ProgressReporter | None" = None,
            cancel_check: "Callable[[], bool] | None" = None,
    ) -> CheckResult:
        """Считает хеш и сравнивает с эталоном (если есть)."""
        start = time.monotonic()

        # Callback для прогресса
        def chunk_cb(n_bytes: int) -> None:
            if progress:
                progress.advance(n_bytes)

        def cancel_cb() -> bool:
            # d2: приоритет — внешний cancel_check, fallback на progress
            if cancel_check is not None:
                return cancel_check()
            return progress.is_cancelled if progress else False

        try:
            actual_hash, actual_size = get_file_hash(
                file_path,
                progress_callback=chunk_cb,
                cancel_check=cancel_cb,
            )
        except FileNotFoundError as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            return CheckResult(
                status="fail",
                message=f"File not found: {e}",
                details={"error": str(e)},
                duration_ms=duration_ms,
            )
        except InterruptedError as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            return CheckResult(
                status="skip",
                message="Cancelled by user",
                details={"cancelled": True, "error": str(e)},
                duration_ms=duration_ms,
            )

        duration_ms = int((time.monotonic() - start) * 1000)

        # Нет эталона — только посчитали
        if context is None:
            return CheckResult(
                status="warn",
                message="Hash calculated, no etalon to compare",
                details={"hash": actual_hash, "size": actual_size},
                duration_ms=duration_ms,
            )

        # Есть эталон — сравниваем
        expected_hash = context.get("hash")
        expected_size = context.get("size")

        if expected_size != actual_size:
            return CheckResult(
                status="fail",
                message="Size mismatch",
                details={
                    "reason": "size_mismatch",
                    "expected": {"hash": expected_hash, "size": expected_size},
                    "actual": {"hash": actual_hash, "size": actual_size},
                },
                duration_ms=duration_ms,
            )

        if expected_hash != actual_hash:
            return CheckResult(
                status="fail",
                message="Hash mismatch",
                details={
                    "reason": "hash_mismatch",
                    "expected": {"hash": expected_hash, "size": expected_size},
                    "actual": {"hash": actual_hash, "size": actual_size},
                },
                duration_ms=duration_ms,
            )

        return CheckResult(
            status="pass",
            message="Hash matches etalon",
            details={"hash": actual_hash, "size": actual_size},
            duration_ms=duration_ms,
        )









