"""Поиск файлов моделей в директории."""
from pathlib import Path

from auditllm.checks import all_supported_extensions


def find_model_files(
    directory: Path,
    exclude_dirs: list[Path] | None = None,
) -> list[Path]:
    """Рекурсивно находит все файлы моделей в директории.

    Args:
        directory: корневая папка для поиска
        exclude_dirs: папки, которые нужно исключить (например, quarantine)

    Returns:
        Отсортированный список путей к файлам моделей.
    """
    if not directory.is_dir():
        return []

    extensions = all_supported_extensions()
    exclude_dirs = exclude_dirs or []
    exclude_resolved = {d.resolve() for d in exclude_dirs if d.is_dir()}

    results: list[Path] = []
    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue

        # Расширение
        if file_path.suffix.lower() not in extensions:
            continue

        # Исключённые директории
        try:
            file_resolved = file_path.resolve()
        except OSError:
            continue

        # Проверяем, не в исключённой ли папке
        if any(excl in file_resolved.parents for excl in exclude_resolved):
            continue

        # Fallback: исключаем по имени "quarantine"
        if "quarantine" in file_path.parts:
            continue

        results.append(file_path)

    return sorted(results)





