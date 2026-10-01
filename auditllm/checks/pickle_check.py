"""Статический анализ pickle-файлов (без выполнения)."""
import io
import pickletools
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditllm.checks.base import Check, CheckResult

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


class PickleCheck(Check):
    name = "pickle"
    description = "Static pickle safety scan (no execution)"

    # Форматы, которые могут содержать pickle
    SUPPORTED = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dill"}

    # Опасные модули (blocklist — НЕ полный!)
    DANGEROUS_MODULES = {
        "os", "subprocess", "sys", "builtins", "__builtin__",
        "posix", "nt", "shutil", "socket", "pty",
        "runpy", "importlib", "code", "codeop",
        "commands", "popen2", "platform",
    }

    # Pickle magic byte (protocol 2+)
    PICKLE_MAGIC = 0x80

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.SUPPORTED

    def run(self,
            file_path: Path,
            context: dict[Any, Any] | None=None,
            progress: ProgressReporter | None=None) -> CheckResult:
        start = time.monotonic()

        try:
            findings = self._scan_file(file_path)
        except Exception as e:
            return CheckResult(
                status="fail",
                message=f"Pickle scan failed: {e}",
                details={"error": str(e)},
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        duration_ms = int((time.monotonic() - start) * 1000)

        if findings is None:
            return CheckResult(
                status="skip",
                message="Not a pickle file (magic bytes not recognized)",
                duration_ms=duration_ms,
            )

        dangerous = findings.get("dangerous", [])
        warnings = findings.get("warnings", [])

        if dangerous:
            return CheckResult(
                status="fail",
                message=f"Pickle safety issues: {len(dangerous)} dangerous, {len(warnings)} warnings",
                details={"dangerous": dangerous, "warnings": warnings},
                duration_ms=duration_ms,
            )

        if warnings:
            return CheckResult(
                status="warn",
                message=f"Pickle parsed, {len(warnings)} warnings (but pickle is never fully safe)",
                details={"warnings": warnings},
                duration_ms=duration_ms,
            )

        return CheckResult(
            status="warn",
            message="Pickle parsed, no known dangerous globals (pickle is never fully safe)",
            details={"note": "Static scan is best-effort."},
            duration_ms=duration_ms,
        )

    def _scan_file(self, file_path: Path) -> dict | None:
        """Возвращает {"dangerous": [...], "warnings": [...]} или None (skip)."""
        with open(file_path, "rb") as f:
            magic = f.read(4)

        if magic[:2] == b"PK":
            return self._scan_zip(file_path)

        if magic[:1] == bytes([self.PICKLE_MAGIC]):
            return self._scan_pickle_file(file_path)

        return None  # не pickle — skip

    def _scan_pickle_file(self, file_path: Path) -> dict:
        with open(file_path, "rb") as f:
            return self._scan_pickle_stream(f)

    def _scan_pickle_stream(self, f) -> dict:
        result = {"dangerous": [], "warnings": []}

        # Мини-стек для строковых значений (для STACK_GLOBAL)
        string_stack: list[str] = []

        # Опкоды, которые кладут строку на стек
        STRING_OPCODES = {
            "SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
            "BINUNICODE8", "SHORT_BINSTRING", "BINSTRING", "STRING",
        }

        try:
            for opcode, arg, pos in pickletools.genops(f):
                name = opcode.name

                if name in STRING_OPCODES and isinstance(arg, str):
                    string_stack.append(arg)
                    if len(string_stack) > 10:
                        string_stack.pop(0)  # ограничиваем размер

                elif name == "GLOBAL":
                    # Старый формат: arg = "module.name"
                    if arg:
                        module = arg.split(".")[0]
                        if module in self.DANGEROUS_MODULES:
                            result["dangerous"].append(arg)

                elif name == "STACK_GLOBAL":
                    # Новый формат (protocol 4+): module и name — на стеке
                    if len(string_stack) >= 2:
                        module = string_stack[-2]
                        attr = string_stack[-1]
                        full = f"{module}.{attr}"
                        if module in self.DANGEROUS_MODULES:
                            result["dangerous"].append(full)
                        else:
                            # не опасный, но полезно знать, что импортируется
                            result["warnings"].append(f"imports {full} (pos {pos})")
                        string_stack = string_stack[:-2]  # снимаем со стека
                    else:
                        result["warnings"].append(
                            f"STACK_GLOBAL at pos {pos} — cannot resolve (empty string stack)"
                        )

                elif name in ("POP", "POP_MARK"):
                    # грубо: очищаем наш стек
                    string_stack = string_stack[:-1] if string_stack else []

        except Exception as e:
            result["warnings"].append(f"pickle parse error: {e}")

        return result

    def _scan_zip(self, file_path: Path) -> dict:
        result = {"dangerous": [], "warnings": []}

        with zipfile.ZipFile(file_path, "r") as zf:
            pkl_names = [n for n in zf.namelist() if n.endswith(".pkl")]

            if not pkl_names:
                result["warnings"].append(
                    f"ZIP container, no .pkl found (names: {zf.namelist()[:5]})"
                )
                return result

            for name in pkl_names:
                with zf.open(name) as pkl_file:
                    sub = self._scan_pickle_stream(pkl_file)
                    result["dangerous"].extend(f"{name}: {f}" for f in sub["dangerous"])
                    result["warnings"].extend(f"{name}: {f}" for f in sub["warnings"])

        return result











