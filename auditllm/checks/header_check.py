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

        return {
            "format": "GGUF",
            "version": version,
            "tensor_count": tensor_count,
            "metadata_kv_count": metadata_kv_count,
        }

    def _check_safetensors(self, file_path: Path) -> dict:
        """Читает длину и JSON-заголовок safetensors."""
        with open(file_path, "rb") as f:
            header_size_bytes = f.read(8)
            if len(header_size_bytes) < 8:
                raise ValueError("File too small for safetensors")

            header_size = struct.unpack("<Q", header_size_bytes)[0]

            if header_size > 100 * 1024 * 1024:  # 100 МБ — sanity check
                raise ValueError(f"Header too large: {header_size} bytes")

            json_bytes = f.read(header_size)
            if len(json_bytes) < header_size:
                raise ValueError("Truncated header")

        try:
            header_data = json.loads(json_bytes)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON header: {e}")

        tensor_names = [k for k in header_data.keys() if k != "__metadata__"]

        return {
            "format": "safetensors",
            "header_size": header_size,
            "tensor_count": len(tensor_names),
            "metadata": header_data.get("__metadata__", {}),
        }









