"""Обход контейнеров (ZIP/TAR/GZIP/7z/NPY/NPZ) для поиска pickle-потоков.

Классификация — по magic bytes, а не по расширению.
Защита от Zip Bomb — через бюджет распаковки.
Рекурсия — с ограничением глубины (флаг pickle_max_depth).
"""
from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable


# ── magic bytes ────────────────────────────────────────────────
ZIP_MAGIC = b"PK\x03\x04"
ZIP_MAGIC_EMPTY = b"PK\x05\x06"      # пустой архив
ZIP_MAGIC_SPANNED = b"PK\x07\x08"    # spanned
GZIP_MAGIC = b"\x1f\x8b"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
NPY_MAGIC = b"\x93NUMPY"
PICKLE_MAGIC = b"\x80"

# Признаки pickle-протоколов 0/1 (без 0x80):
# protocol 0: начинается с одного из этих опкодов-«начал»
PICKLE_V0_STARTS = (b"(", b"c", b"I", b"F", b"L", b"S", b"V", b"d", b"l", b"p", b"g")
# protocol 1: начинается с этих опкодов
PICKLE_V1_STARTS = (b"}", b"]", b")", b"K", b"G", b"J", b"T", b"U", b"X", b"q", b"h", b"B")

# Имена, которые почти наверняка являются pickle внутри контейнера
PICKLE_NAME_HINTS = (".pkl", ".pickle", ".joblib", ".dill", "data.pkl")


@dataclass
class StreamRef:
    """Ссылка на поток внутри контейнера."""
    inner_path: str                    # полный путь внутри контейнера
    data: bytes                        # содержимое (уже распакованное)
    container_chain: list[str] = field(default_factory=list)  # [внешний, ..., внутренний]


@dataclass
class WalkResult:
    """Результат обхода контейнера."""
    streams: list[StreamRef] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    inner_files: list[str] = field(default_factory=list)  # первые N имён для details
    truncated: bool = False


class ContainerWalker:
    """Рекурсивный обход контейнеров с бюджетом распаковки."""

    MAX_INNER_FILES_IN_DETAILS = 10

    def __init__(
        self,
        max_depth: int = 3,
        budget_mb: int = 200,
        max_stream_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self.max_depth = max_depth
        self.budget_bytes = budget_mb * 1024 * 1024
        self.max_stream_bytes = max_stream_bytes
        self._consumed = 0  # сколько уже распаковано в текущем обходе

    def walk(
        self,
        file_path: Path,
        cancel_check: Callable[[], bool] | None = None,
    ) -> WalkResult:
        """Обойти файл как контейнер (или как одиночный поток)."""
        self._consumed = 0
        result = WalkResult()
        try:
            with open(file_path, "rb") as f:
                head = f.read(512)
                f.seek(0)
                self._walk_stream(
                    f, file_path.name, [file_path.name],
                    result, cancel_check, depth=0,
                )
        except Exception as e:  # noqa: BLE001
            result.warnings.append({
                "type": "container_error",
                "message": f"{type(e).__name__}: {e}",
                "pos": -1,
            })
        return result

    # ── рекурсивный обход ──────────────────────────────────────
    def _walk_stream(
        self,
        stream: BinaryIO,
        inner_path: str,
        chain: list[str],
        result: WalkResult,
        cancel_check: Callable[[], bool] | None,
        depth: int,
    ) -> None:
        if cancel_check and cancel_check():
            result.warnings.append({
                "type": "cancelled", "message": "walk cancelled", "pos": -1,
            })
            return

        head = stream.read(512)
        stream.seek(0)

        # 1. ZIP
        if head.startswith(ZIP_MAGIC) or head.startswith(ZIP_MAGIC_EMPTY) or head.startswith(ZIP_MAGIC_SPANNED):
            self._walk_zip(stream, inner_path, chain, result, cancel_check, depth)
            return

        # 2. GZIP (может быть tar.gz)
        if head.startswith(GZIP_MAGIC):
            self._walk_gzip(stream, inner_path, chain, result, cancel_check, depth)
            return

        # 3. TAR (ustar на offset 257)
        if len(head) > 262 and head[257:262] == b"ustar":
            self._walk_tar(stream, inner_path, chain, result, cancel_check, depth)
            return

        # 4. 7z — пока не поддерживаем распаковку (нет stdlib), только предупреждение
        if head.startswith(SEVENZ_MAGIC):
            result.warnings.append({
                "type": "7z_not_supported",
                "message": f"7z container {inner_path} not scanned (install py7zr for support)",
                "pos": -1,
            })
            return

        # 5. NPY — проверить dtype='O'
        if head.startswith(NPY_MAGIC):
            self._walk_npy(stream, inner_path, chain, result)
            return

        # 6. Одиночный pickle (0x80 или protocol 0/1)
        if self._looks_like_pickle(head, inner_path):
            data = self._read_budgeted(stream, result)
            if data is not None:
                result.streams.append(StreamRef(
                    inner_path=inner_path, data=data, container_chain=list(chain),
                ))
            return

        # 7. Неизвестный формат — если имя намекает на pickle, всё равно сканируем
        if any(inner_path.endswith(h) for h in PICKLE_NAME_HINTS):
            data = self._read_budgeted(stream, result)
            if data is not None:
                result.streams.append(StreamRef(
                    inner_path=inner_path, data=data, container_chain=list(chain),
                ))

    # ── ZIP ────────────────────────────────────────────────────
    def _walk_zip(
        self, stream: BinaryIO, inner_path: str, chain: list[str],
        result: WalkResult, cancel_check: Callable[[], bool] | None, depth: int,
    ) -> None:
        if depth >= self.max_depth:
            result.warnings.append({
                "type": "max_depth_reached",
                "message": f"max container depth {self.max_depth} reached at {inner_path}",
                "pos": -1,
            })
            return
        try:
            stream.seek(0)
            with zipfile.ZipFile(stream) as zf:
                names = zf.namelist()
                self._record_inner_files(result, names)
                for name in names:
                    if cancel_check and cancel_check():
                        result.warnings.append({
                            "type": "cancelled", "message": "zip walk cancelled", "pos": -1,
                        })
                        return
                    if name.endswith("/"):
                        continue
                    try:
                        with zf.open(name) as inner:
                            inner_data = self._read_budgeted(inner, result)
                        if inner_data is None:
                            continue
                        self._walk_bytes(
                            inner_data, f"{inner_path}!{name}",
                            chain + [name], result, cancel_check, depth + 1,
                        )
                    except Exception as e:  # noqa: BLE001
                        result.warnings.append({
                            "type": "inner_read_error",
                            "message": f"{inner_path}!{name}: {type(e).__name__}: {e}",
                            "pos": -1,
                        })
        except zipfile.BadZipFile as e:
            result.warnings.append({
                "type": "bad_zip",
                "message": f"{inner_path}: BadZipFile: {e}",
                "pos": -1,
            })

    # ── GZIP ───────────────────────────────────────────────────
    def _walk_gzip(
        self, stream: BinaryIO, inner_path: str, chain: list[str],
        result: WalkResult, cancel_check: Callable[[], bool] | None, depth: int,
    ) -> None:
        import gzip
        try:
            stream.seek(0)
            with gzip.GzipFile(fileobj=stream, mode="rb") as gz:
                data = self._read_budgeted(gz, result)
            if data is None:
                return
            # .tar.gz → TAR внутри
            if len(data) > 262 and data[257:262] == b"ustar":
                self._walk_bytes(
                    data, f"{inner_path}!<tar>", chain + ["<tar>"],
                    result, cancel_check, depth + 1,
                )
            else:
                self._walk_bytes(
                    data, inner_path, chain, result, cancel_check, depth + 1,
                )
        except OSError as e:
            result.warnings.append({
                "type": "bad_gzip",
                "message": f"{inner_path}: {e}",
                "pos": -1,
            })

    # ── TAR ────────────────────────────────────────────────────
    def _walk_tar(
        self, stream: BinaryIO, inner_path: str, chain: list[str],
        result: WalkResult, cancel_check: Callable[[], bool] | None, depth: int,
    ) -> None:
        if depth >= self.max_depth:
            result.warnings.append({
                "type": "max_depth_reached",
                "message": f"max container depth {self.max_depth} reached at {inner_path}",
                "pos": -1,
            })
            return
        try:
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode="r:*") as tf:
                names = tf.getnames()
                self._record_inner_files(result, names)
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    if cancel_check and cancel_check():
                        result.warnings.append({
                            "type": "cancelled", "message": "tar walk cancelled", "pos": -1,
                        })
                        return
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    with f:
                        inner_data = self._read_budgeted(f, result)
                    if inner_data is None:
                        continue
                    self._walk_bytes(
                        inner_data, f"{inner_path}!{member.name}",
                        chain + [member.name], result, cancel_check, depth + 1,
                    )
        except tarfile.TarError as e:
            result.warnings.append({
                "type": "bad_tar",
                "message": f"{inner_path}: {e}",
                "pos": -1,
            })

    # ── NPY ────────────────────────────────────────────────────
    def _walk_npy(
        self, stream: BinaryIO, inner_path: str, chain: list[str], result: WalkResult,
    ) -> None:
        stream.seek(0)
        data = self._read_budgeted(stream, result)
        if data is None:
            return
        try:
            import numpy as np
            arr = np.load(io.BytesIO(data), allow_pickle=True)
            if hasattr(arr, "dtype") and arr.dtype == object:
                result.warnings.append({
                    "type": "npy_object_dtype",
                    "message": f"{inner_path}: dtype='O' — object array may contain pickle",
                    "pos": -1,
                })
                # Попытка пройти по элементам: если pickle-байты, отдаём в сканер
                for item in arr.flat:
                    if isinstance(item, bytes) and item[:1] == PICKLE_MAGIC:
                        result.streams.append(StreamRef(
                            inner_path=f"{inner_path}!<item>",
                            data=item,
                            container_chain=list(chain),
                        ))
                        break
        except ImportError:
            result.warnings.append({
                "type": "npy_no_numpy",
                "message": f"{inner_path}: numpy not installed, cannot inspect .npy",
                "pos": -1,
            })
        except Exception as e:  # noqa: BLE001
            result.warnings.append({
                "type": "npy_parse_error",
                "message": f"{inner_path}: {type(e).__name__}: {e}",
                "pos": -1,
            })

    # ── байтовый вход для рекурсии ─────────────────────────────
    def _walk_bytes(
        self, data: bytes, inner_path: str, chain: list[str],
        result: WalkResult, cancel_check: Callable[[], bool] | None, depth: int,
    ) -> None:
        self._walk_stream(
            io.BytesIO(data), inner_path, chain, result, cancel_check, depth,
        )

    # ── бюджет / лимиты ────────────────────────────────────────
    def _read_budgeted(
        self, stream: BinaryIO, result: WalkResult,
    ) -> bytes | None:
        try:
            data = stream.read(self.max_stream_bytes + 1)
        except Exception as e:  # noqa: BLE001
            result.warnings.append({
                "type": "stream_read_error",
                "message": f"{type(e).__name__}: {e}",
                "pos": -1,
            })
            return None
        if len(data) > self.max_stream_bytes:
            result.truncated = True
            result.warnings.append({
                "type": "truncated_stream",
                "message": f"stream > {self.max_stream_bytes} bytes, truncated",
                "pos": -1,
            })
            data = data[: self.max_stream_bytes]
        self._consumed += len(data)
        if self._consumed > self.budget_bytes:
            result.truncated = True
            result.warnings.append({
                "type": "budget_exceeded",
                "message": (
                    f"unpack budget {self.budget_bytes // (1024 * 1024)} MB exceeded, "
                    f"stopped at {self._consumed // (1024 * 1024)} MB"
                ),
                "pos": -1,
            })
            return None
        return data

    def _record_inner_files(self, result: WalkResult, names: list[str]) -> None:
        for n in names[: self.MAX_INNER_FILES_IN_DETAILS]:
            result.inner_files.append(n)

    # ── эвристика «похоже на pickle» ───────────────────────────
    def _looks_like_pickle(self, head: bytes, inner_path: str) -> bool:
        if not head:
            return False
        if head.startswith(PICKLE_MAGIC):
            return True
        # протоколы 0/1: эвристика по первому байту, но только если имя намекает
        if any(inner_path.endswith(h) for h in PICKLE_NAME_HINTS):
            if head[:1] in PICKLE_V0_STARTS or head[:1] in PICKLE_V1_STARTS:
                return True
        return False





