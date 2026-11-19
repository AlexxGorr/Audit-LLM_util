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

EXCLUDE_PATTERNS = {".git", "__pycache__", ".venv", "node_modules",
                    ".mypy_cache", ".pytest_cache", ".ruff_cache"}
EXCLUDE_GLOBS = {"*.tmp", "*.lock", "*.log", "*.pyc", "*.pyo"}

MIN_SIZE = 1 * 1024 * 1024  # H3: 1 МБ


def find_model_files(
    directory: Path,
    exclude_dirs: list[Path] | None = None,
    min_size: int = MIN_SIZE,
    include_ext: set[str] | None = None,
    exclude_ext: set[str] | None = None,
) -> list[Path]:
    """Рекурсивно находит все файлы моделей в директории.

    Args:
        directory: корневая папка для поиска
        exclude_dirs: папки, которые нужно исключить (например, quarantine)
        min_size: минимальный размер файла в байтах (H3, по умолчанию 1 МБ)

    Returns:
        Отсортированный список путей к файлам моделей.
    """
    if not directory.is_dir():
        return []

    # H1: расширения, которые сканируем (даже если нет header-проверки)
    EXTRA_EXTENSIONS = {".onnx", ".h5", ".ggml", ".tflite", ".msgpack"}
    extensions = all_supported_extensions() | EXTRA_EXTENSIONS
    if include_ext:
        extensions = extensions & include_ext
    if exclude_ext:
        extensions = extensions - exclude_ext

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

        # H3: отсекаем мелкие файлы
        try:
            if file_path.stat().st_size < min_size:
                continue
        except OSError:
            continue

        # H4: отсекаем по glob-паттернам
        if any(file_path.match(pat) for pat in EXCLUDE_GLOBS):
            continue

        results.append(file_path)

    return sorted(results)




