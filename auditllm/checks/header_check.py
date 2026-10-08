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
        """Читает 24-байтовый заголовок GGUF."""
        with open(file_path, "rb") as f:
            header = f.read(24)

        if len(header) < 24:
            raise ValueError(f"File too small for GGUF: {len(header)} bytes")

        magic = header[0:4]
        if magic != b"GGUF":
            raise ValueError(f"Invalid GGUF magic: {magic!r}")

        version, tensor_count, metadata_kv_count = struct.unpack("<IQQ", header[4:24])

        # Sanity checks
        KNOWN_VERSIONS = {1, 2, 3}
        version_known = version in KNOWN_VERSIONS
        tensor_count_ok = 1 <= tensor_count <= 100_000
        metadata_kv_ok = 0 <= metadata_kv_count <= 100_000

        return {
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









