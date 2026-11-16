"""Подсчёт SHA-256 хеша файла по чанкам."""
import hashlib
from pathlib import Path
from typing import Callable


def get_file_hash(
    file_path: Path,
    chunk_size: int = 8192,
    progress_callback: Callable[[int], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[str, int]:
    """Считает SHA-256 хеш файла, читая его по чанкам.

    Args:
        file_path: путь к файлу
        chunk_size: размер чанка в байтах
        progress_callback: вызывается после каждого чанка с числом
                           обработанных байт (длина чанка)
        cancel_check: если возвращает True — прервать хеширование

    Returns:
        Кортеж (hex_digest, file_size_bytes)

    Raises:
        FileNotFoundError: если файл не существует
        InterruptedError: если cancel_check вернул True
        RuntimeError: если файл изменился во время хеширования
    """
    if not file_path.is_file():
        raise FileNotFoundError(f"Файл не найден: {file_path}")

    # b6: фиксируем размер ДО чтения
    try:
        file_size = file_path.stat().st_size
    except OSError as e:
        raise FileNotFoundError(f"Файл недоступен: {file_path}") from e

    hash_obj = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            if cancel_check and cancel_check():
                raise InterruptedError(f"Хеширование отменено: {file_path}")
            hash_obj.update(chunk)
            if progress_callback:
                progress_callback(len(chunk))

    # b6: проверяем, что файл не изменился
    try:
        actual_size = file_path.stat().st_size
    except OSError as e:
        raise FileNotFoundError(f"Файл исчез во время хеширования: {file_path}") from e

    if actual_size != file_size:
        raise RuntimeError(
            f"Файл изменился во время хеширования: {file_path} "
            f"(было {file_size}, стало {actual_size})"
        )

    return hash_obj.hexdigest(), file_size



