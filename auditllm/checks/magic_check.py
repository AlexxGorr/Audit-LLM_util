"""Проверка magic bytes — быстрая классификация формата."""
import time
from pathlib import Path
from typing import TYPE_CHECKING

from auditllm.checks.base import Check, CheckResult

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


class MagicCheck(Check):
    """Проверка magic bytes (быстро, до hash)."""

    name = "magic"
    description = "Magic bytes detection (GGUF, safetensors, ONNX, HDF5, TFLite, GGML)"

    # H1: поддерживаемые расширения (те же, что в scanner)
    SUPPORTED = {".gguf", ".safetensors", ".onnx", ".h5", ".ggml", ".tflite", ".msgpack",
                 ".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dill"}

    # magic bytes → (формат, описание)
    MAGIC_MAP = {
        b"GGUF": "GGUF",
        b"\x93NUMPY": "numpy",       # не модель, но полезно
        b"\x89HDF\r\n\x1a\n": "HDF5",
        b"TFL3": "TFLite",
        b"ggml": "GGML",
        b"PK\x03\x04": "ZIP",         # .pt/.bin могут быть zip
        b"\x80": "pickle",            # protocol 2+
    }

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.SUPPORTED

    def run(
        self,
        file_path: Path,
        context: dict | None = None,
        progress: "ProgressReporter | None" = None,
        cancel_check=None,
    ) -> CheckResult:
        start = time.monotonic()
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
        except OSError as e:
            return CheckResult(
                status="fail",
                message=f"Cannot read file: {e}",
                details={"error": str(e)},
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        detected = None
        for magic, fmt in self.MAGIC_MAP.items():
            if header.startswith(magic):
                detected = fmt
                break

        duration_ms = int((time.monotonic() - start) * 1000)

        if detected:
            return CheckResult(
                status="pass",
                message=f"Detected: {detected}",
                details={"format": detected, "magic": header[:8].hex()},
                duration_ms=duration_ms,
            )
        return CheckResult(
            status="warn",
            message=f"Unknown magic bytes: {header[:8].hex()}",
            details={"magic": header[:8].hex()},
            duration_ms=duration_ms,
        )



