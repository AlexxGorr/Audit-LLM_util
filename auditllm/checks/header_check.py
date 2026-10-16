"""Проверка заголовка файла модели (GGUF, safetensors)."""
import json
import struct
import time
from pathlib import Path
from typing import TYPE_CHECKING

from auditllm.checks.base import Check, CheckResult

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


class HeaderCheck(Check):
    name = "header"
    description = "Model header validation (GGUF, safetensors)"

    SUPPORTED = {".gguf", ".safetensors"}

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.SUPPORTED

    def run(self, file_path, context=None, progress=None) -> CheckResult:
        start = time.monotonic()
        suffix = file_path.suffix.lower()

        try:
            if suffix == ".gguf":
                details = self._check_gguf(file_path)
            elif suffix == ".safetensors":
                details = self._check_safetensors(file_path)
            else:
                return CheckResult(
                    status="skip",
                    message=f"Unsupported format: {suffix}",
                    duration_ms=0,
                )
        except Exception as e:
            return CheckResult(
                status="fail",
                message=f"Header check failed: {e}",
                details={"error": str(e)},
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        # Проверка sanity: если что-то не так — warn, не pass
        sanity = details.get("sanity", {})
        failed_sanity = [k for k, v in sanity.items() if not v]

        if failed_sanity:
            return CheckResult(
                status="warn",
                message=f"Header valid but sanity checks failed: {', '.join(failed_sanity)}",
                details=details,
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        return CheckResult(
            status="pass",
            message=f"Valid {suffix} header",
            details=details,
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    def _check_gguf(self, file_path: Path) -> dict:
        """Читает заголовок и метаданные GGUF."""
        # 1. Быстрая проверка magic (как было)
        with open(file_path, "rb") as f:
            header = f.read(24)
        if len(header) < 24:
            raise ValueError(f"File too small for GGUF: {len(header)} bytes")
        magic = header[0:4]
        if magic != b"GGUF":
            raise ValueError(f"Invalid GGUF magic: {magic!r}")

        version, tensor_count, metadata_kv_count = struct.unpack("<IQQ", header[4:24])

        # 2. Sanity checks
        KNOWN_VERSIONS = {1, 2, 3}
        version_known = version in KNOWN_VERSIONS
        tensor_count_ok = 1 <= tensor_count <= 100_000
        metadata_kv_ok = 0 <= metadata_kv_count <= 100_000

        result = {
            "format": "GGUF",
            "version": version,
            "version_str": f"GGUF v{version}",
            "tensor_count": tensor_count,
            "metadata_kv_count": metadata_kv_count,
            "sanity": {
                "version_known": version_known,
                "tensor_count_ok": tensor_count_ok,
                "metadata_kv_ok": metadata_kv_ok,
            },
        }

        # 3. Читаем метаданные через gguf (опционально)
        try:
            from gguf import GGUFReader
            reader = GGUFReader(str(file_path))

            # Извлекаем ключевые поля
            metadata = self._extract_gguf_metadata(reader)
            if metadata:
                result["metadata"] = metadata
        except ImportError:
            result["metadata_error"] = "gguf library not installed"
        except Exception as e:
            result["metadata_error"] = str(e)

        return result

    def _extract_gguf_metadata(self, reader) -> dict:
        """Извлекает ключевые метаданные из GGUFReader.

        Динамически определяет архитектуру и извлекает поля <arch>.*
        """
        metadata = {}

        # 1. Общие поля (general.*)
        GENERAL_FIELDS = {
            "general.architecture": "architecture",
            "general.name": "name",
            "general.author": "author",
            "general.license": "license",
            "general.description": "description",
            "general.file_type": "file_type",
            "general.basename": "basename",
            "general.size_label": "size_label",
            "general.quantization_version": "quantization_version",
        }

        # 2. Определяем архитектуру (для динамического поиска <arch>.*)
        architecture = None
        if "general.architecture" in reader.fields:
            field_obj = reader.fields["general.architecture"]
            arch_value = self._gguf_value_to_python(field_obj)
            if arch_value:
                architecture = arch_value
                metadata["architecture"] = arch_value

        # 3. Извлекаем общие поля
        for field_name, short_name in GENERAL_FIELDS.items():
            if field_name == "general.architecture":
                continue  # уже извлекли
            if field_name in reader.fields:
                value = self._gguf_value_to_python(reader.fields[field_name])
                if value is not None:
                    metadata[short_name] = value

        # 4. Извлекаем архитектурно-специфичные поля: <arch>.context_length и т.д.
        if architecture:
            ARCH_FIELDS = [
                "context_length",
                "embedding_length",
                "block_count",
                "feed_forward_length",
                "attention.head_count",
                "attention.head_count_kv",
                "attention.layer_norm_rms_epsilon",
                "rope.freq_base",
                "vocab_size",
            ]

            for arch_field in ARCH_FIELDS:
                full_name = f"{architecture}.{arch_field}"
                if full_name in reader.fields:
                    value = self._gguf_value_to_python(reader.fields[full_name])
                    if value is not None:
                        metadata[arch_field] = value

        return metadata

    def _gguf_value_to_python(self, field_obj):
        """Конвертирует значение поля GGUF в Python.

        Структура parts (GGUFReader):
        - parts[0] — длина ключа
        - parts[1] — байты ключа
        - parts[2] — тип значения (uint32)
        - parts[3] — длина значения (uint64) — опционально
        - parts[-1] — само значение

        Значение всегда в parts[-1].
        """
        try:
            if not hasattr(field_obj, "parts") or not field_obj.parts:
                return None

            value_part = field_obj.parts[-1]

            # Строка: dtype uint8
            if hasattr(value_part, "dtype") and value_part.dtype == "uint8":
                try:
                    raw = value_part.tobytes().rstrip(b"\x00")
                    decoded = raw.decode("utf-8")
                    if decoded.isprintable():
                        return decoded
                except (UnicodeDecodeError, AttributeError):
                    pass

            # Число/массив: tolist()
            if hasattr(value_part, "tolist"):
                value = value_part.tolist()
                if isinstance(value, list) and len(value) == 1:
                    return value[0]
                return value

            return None
        except Exception:
            return None


    def _check_safetensors(self, file_path: Path) -> dict:
        """Читает длину и JSON-заголовок safetensors."""
        with open(file_path, "rb") as f:
            header_size_bytes = f.read(8)
            if len(header_size_bytes) < 8:
                raise ValueError("File too small for safetensors")

            header_size = struct.unpack("<Q", header_size_bytes)[0]

            if header_size > 100 * 1024 * 1024:
                raise ValueError(f"Header too large: {header_size} bytes")

            json_bytes = f.read(header_size)
            if len(json_bytes) < header_size:
                raise ValueError("Truncated header")

        try:
            header_data = json.loads(json_bytes)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON header: {e}")

        # Метаданные и тензоры
        metadata = header_data.get("__metadata__", {})
        tensor_names = [k for k in header_data.keys() if k != "__metadata__"]

        # Распределение по dtype
        dtype_distribution: dict[str, int] = {}
        for name in tensor_names:
            entry = header_data.get(name, {})
            if isinstance(entry, dict):
                dtype = entry.get("dtype", "unknown")
                dtype_distribution[dtype] = dtype_distribution.get(dtype, 0) + 1

        # Первые 5 тензоров (для контекста)
        sample_tensors = sorted(tensor_names)[:5]

        return {
            "format": "safetensors",
            "header_size": header_size,
            "tensor_count": len(tensor_names),
            "metadata": metadata,
            "dtype_distribution": dtype_distribution,
            "sample_tensors": sample_tensors,
        }









