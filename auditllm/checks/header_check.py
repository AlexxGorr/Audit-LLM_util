"""Проверка заголовка файла модели (GGUF, safetensors)."""
import json
import struct
import time
from pathlib import Path
from typing import TYPE_CHECKING

from auditllm.checks.base import Check, CheckResult

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


GGUF_VALUE_SIZES = {
    0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
    10: 8, 11: 8, 12: 8,
}


class HeaderCheck(Check):
    name = "header"
    description = "Model header validation (GGUF, safetensors)"

    SUPPORTED = {".gguf", ".safetensors"}
    # H1: дополнительные форматы (без header-проверки, но находятся сканером)
    # header-проверка для них — skip, но hash/pickle/magic — работают

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
                severity="major",
                suggestion=f"Проверь формат файла ({suffix}) — возможно, он повреждён или это не модель",
                details={"error": str(e)},
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        sanity = details.get("sanity", {})
        failed_sanity = [k for k, v in sanity.items() if not v]

        if failed_sanity:
            return CheckResult(
                status="warn",
                message=f"Header valid but sanity checks failed: {', '.join(failed_sanity)}",
                severity="minor",
                suggestion=f"Проверь поля: {', '.join(failed_sanity)} — возможна порча заголовка",
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
        """Читает заголовок и ключевые метаданные GGUF (быстро)."""
        with open(file_path, "rb") as f:
            header = f.read(24)
        if len(header) < 24:
            raise ValueError(f"File too small for GGUF: {len(header)} bytes")
        magic = header[0:4]
        if magic != b"GGUF":
            raise ValueError(f"Invalid GGUF magic: {magic!r}")

        version, tensor_count, metadata_kv_count = struct.unpack("<IQQ", header[4:24])

        KNOWN_VERSIONS = {1, 2, 3}
        result = {
            "format": "GGUF",
            "version": version,
            "version_str": f"GGUF v{version}",
            "tensor_count": tensor_count,
            "metadata_kv_count": metadata_kv_count,
            "sanity": {
                "version_known": version in KNOWN_VERSIONS,
                "tensor_count_ok": 1 <= tensor_count <= 100_000,
                "metadata_kv_ok": 0 <= metadata_kv_count <= 100_000,
            },
        }

        metadata = self._read_gguf_metadata_fast(file_path, max_pairs=50)
        if metadata:
            result["metadata"] = metadata

        return result

    def _read_gguf_metadata_fast(self, file_path: Path, max_pairs: int = 50) -> dict:
        """Ручной парсер ключевых метаданных GGUF."""
        metadata = {}
        KEY_PREFIXES = (
            "general.", "llama.", "phi3.", "qwen2.", "mistral.",
            "gemma.", "bert.", "falcon.", "mpt.", "starcoder.",
        )

        try:
            with open(file_path, "rb") as f:
                f.seek(24)

                for _ in range(max_pairs):
                    key_len_bytes = f.read(8)
                    if len(key_len_bytes) < 8:
                        break
                    key_len = struct.unpack("<Q", key_len_bytes)[0]
                    if key_len > 1000:
                        break

                    key_bytes = f.read(key_len)
                    if len(key_bytes) < key_len:
                        break
                    key = key_bytes.decode("utf-8", errors="replace")

                    type_bytes = f.read(4)
                    if len(type_bytes) < 4:
                        break
                    value_type = struct.unpack("<I", type_bytes)[0]

                    value = self._read_gguf_value(f, value_type)
                    if value is _SENTINEL_ERROR:
                        break

                    if any(key.startswith(p) for p in KEY_PREFIXES) and value is not None:
                        short_name = key.split(".", 1)[1] if "." in key else key
                        metadata[short_name] = value
        except Exception:
            return metadata

        return metadata

    def _read_gguf_value(self, f, value_type: int):
        """Читает значение KV-пары. Возвращает значение или None (пропуск)."""
        try:
            if value_type == 8:  # string
                len_bytes = f.read(8)
                if len(len_bytes) < 8:
                    return _SENTINEL_ERROR
                str_len = struct.unpack("<Q", len_bytes)[0]
                if str_len > 1_000_000:
                    return _SENTINEL_ERROR
                data = f.read(str_len)
                if len(data) < str_len:
                    return _SENTINEL_ERROR
                return data.decode("utf-8", errors="replace")

            elif value_type == 9:  # array
                inner_bytes = f.read(4)
                if len(inner_bytes) < 4:
                    return _SENTINEL_ERROR
                inner_type = struct.unpack("<I", inner_bytes)[0]

                len_bytes = f.read(8)
                if len(len_bytes) < 8:
                    return _SENTINEL_ERROR
                arr_len = struct.unpack("<Q", len_bytes)[0]
                if arr_len > 1_000_000:
                    return _SENTINEL_ERROR

                if inner_type == 8:
                    for _ in range(arr_len):
                        slen_bytes = f.read(8)
                        if len(slen_bytes) < 8:
                            return _SENTINEL_ERROR
                        slen = struct.unpack("<Q", slen_bytes)[0]
                        f.seek(slen, 1)
                else:
                    size = GGUF_VALUE_SIZES.get(inner_type, 0)
                    if size == 0:
                        return _SENTINEL_ERROR
                    f.seek(arr_len * size, 1)

                return None

            else:
                size = GGUF_VALUE_SIZES.get(value_type, 0)
                if size == 0:
                    return _SENTINEL_ERROR
                data = f.read(size)
                if len(data) < size:
                    return _SENTINEL_ERROR

                if value_type in (0, 2, 4, 10):
                    fmt = {0: "B", 2: "H", 4: "I", 10: "Q"}[value_type]
                    return struct.unpack(f"<{fmt}", data)[0]
                elif value_type in (1, 3, 5, 11):
                    fmt = {1: "b", 3: "h", 5: "i", 11: "q"}[value_type]
                    return struct.unpack(f"<{fmt}", data)[0]
                elif value_type == 6:
                    return struct.unpack("<f", data)[0]
                elif value_type == 12:
                    return struct.unpack("<d", data)[0]
                elif value_type == 7:
                    return bool(data[0])
        except Exception:
            return _SENTINEL_ERROR

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

        metadata = header_data.get("__metadata__", {})
        tensor_names = [k for k in header_data.keys() if k != "__metadata__"]

        dtype_distribution: dict[str, int] = {}
        for name in tensor_names:
            entry = header_data.get(name, {})
            if isinstance(entry, dict):
                dtype = entry.get("dtype", "unknown")
                dtype_distribution[dtype] = dtype_distribution.get(dtype, 0) + 1

        sample_tensors = sorted(tensor_names)[:5]

        return {
            "format": "safetensors",
            "header_size": header_size,
            "tensor_count": len(tensor_names),
            "metadata": metadata,
            "dtype_distribution": dtype_distribution,
            "sample_tensors": sample_tensors,
        }


_SENTINEL_ERROR = object()




