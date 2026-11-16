"""Поиск файлов моделей в директории."""
from pathlib import Path

from auditllm.checks import all_supported_extensions


# b4: служебные директории, которые не сканируем
EXCLUDE_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".venv",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}


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

    # b3: резолвим без is_dir() — карантин может ещё не существовать
    exclude_resolved: set[Path] = set()
    for d in exclude_dirs:
        try:
            exclude_resolved.add(d.resolve())
        except OSError:
            continue

    results: list[Path] = []
    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in extensions:
            continue

        # b4: пропускаем служебные директории по имени
        rel_parts = file_path.relative_to(directory).parts
        if any(part in EXCLUDE_DIR_NAMES for part in rel_parts):
            continue

        # b3: проверяем exclude_dirs через is_relative_to
        if exclude_resolved:
            try:
                file_resolved = file_path.resolve()
            except OSError:
                continue
            if any(file_resolved.is_relative_to(excl) for excl in exclude_resolved):
                continue

        results.append(file_path)

    return sorted(results)




