"""Статический анализ pickle-файлов (без выполнения)."""
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from auditllm.checks.base import Check, CheckResult
from auditllm.checks.pickle_scan.opcode_emulator import OpcodeEmulator

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


class PickleCheck(Check):
    name = "pickle"
    description = "Static pickle safety scan (no execution)"

    # Форматы, которые могут содержать pickle
    SUPPORTED = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dill"}

    # Pickle magic byte (protocol 2+)
    PICKLE_MAGIC = 0x80

    # Ограничение чтения одного потока (защита от раздутых data.pkl)
    MAX_PICKLE_STREAM_BYTES = 50 * 1024 * 1024  # 50 MB

    # Точные опасные module.attr — fail
    DANGEROUS_EXACT: dict[str, str] = {
        # ─── System calls ────────────────────────────────
        "os.system": "system calls",
        "os.popen": "system calls",
        "os.spawn": "process spawn",
        "os.spawnl": "process spawn",
        "os.spawnv": "process spawn",
        "posix.system": "system calls",
        "posix.popen": "system calls",
        "nt.system": "system calls",
        # ─── Process spawn ───────────────────────────────
        "subprocess.Popen": "process spawn",
        "subprocess.call": "process spawn",
        "subprocess.run": "process spawn",
        "subprocess.check_call": "process spawn",
        "subprocess.check_output": "process spawn",
        # ─── Code execution ──────────────────────────────
        "builtins.eval": "arbitrary eval",
        "builtins.exec": "arbitrary exec",
        "builtins.compile": "code compilation",
        "builtins.__import__": "dynamic import",
        "builtins.open": "file manipulation",
        # ─── Trampolines ─────────────────────────────────
        "operator.attrgetter": "attribute access",
        "operator.methodcaller": "method call",
        "operator.itemgetter": "item access",
        "functools.partial": "partial call",
        "types.FunctionType": "dynamic code",
        "types.CodeType": "dynamic code",
        "types.LambdaType": "dynamic code",
        # ─── Dynamic import ──────────────────────────────
        "importlib.import_module": "dynamic import",
        "importlib.__import__": "dynamic import",
        # ─── Torch ───────────────────────────────────────
        "torch.hub.load": "external load",
        "torch.serialization._load": "external load",
        "torch.jit.load": "external load",
        "torch.utils.bottleneck.__main__": "code execution",
        # ─── Modelscan bypass ────────────────────────────
        "distutils.spawn": "process spawn",
    }

    # Модули, у которых опасен ЛЮБОЙ атрибут — fail
    DANGEROUS_MODULES: dict[str, str] = {
        # System calls
        "os": "system calls",
        "posix": "system calls",
        "nt": "system calls",
        "subprocess": "process spawn",
        "commands": "shell commands",
        "popen2": "process spawn",
        # Code execution
        "builtins": "arbitrary eval/exec",
        "__builtin__": "arbitrary eval/exec",
        "eval": "arbitrary eval",
        "exec": "arbitrary exec",
        "runpy": "code execution",
        "importlib": "dynamic import",
        "code": "interactive interpreter",
        "codeop": "code compilation",
        "compile": "code compilation",
        "compileall": "code compilation",
        # Network
        "socket": "network access",
        "urllib": "network access",
        "http": "network access",
        "ftplib": "network access",
        "telnetlib": "network access",
        "smtplib": "network access",
        "requests": "network access",
        # File system
        "shutil": "file manipulation",
        "fileinput": "file manipulation",
        "tempfile": "file manipulation",
        "pathlib": "file manipulation",
        "glob": "file manipulation",
        # Process/terminal
        "pty": "terminal control",
        "tty": "terminal control",
        "termios": "terminal control",
        "platform": "system info",
        "sys": "interpreter internals",
        "gc": "interpreter internals",
        # Serialization (recursive)
        "pickle": "recursive pickle",
        "dill": "recursive pickle",
        "joblib": "recursive pickle",
        "marshal": "serialization internals",
        # Misc dangerous
        "webbrowser": "browser control",
        "ctypes": "native code",
        "cffi": "native code",
        "multiprocessing": "process spawn",
        "threading": "thread manipulation",
        "signal": "signal manipulation",
        "resource": "resource manipulation",
        # Distutils
        "distutils": "process spawn",
    }

    def __init__(self) -> None:
        self._emulator = OpcodeEmulator()

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.SUPPORTED

    def run(
        self,
        file_path: Path,
        context: dict[Any, Any] | None = None,
        progress: "ProgressReporter | None" = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> CheckResult:
        start = time.monotonic()

        try:
            findings = self._scan_file(file_path, cancel_check)
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
        reduce_count = findings.get("reduce_count", 0)
        inner_files = findings.get("inner_files", [])
        disassembly = findings.get("disassembly", [])
        stream_count = findings.get("stream_count", 0)

        base_details = {
            "reduce_count": reduce_count,
            "stream_count": stream_count,
            "inner_files": inner_files,
            "disassembly": disassembly,
        }

        if dangerous:
            return CheckResult(
                status="fail",
                message=f"Pickle safety issues: {len(dangerous)} dangerous, {len(warnings)} warnings",
                severity="critical",
                suggestion="⚠️ НЕ загружай файл: возможна RCE. Удали или проверь в песочнице (inspect --search)",
                details={**base_details, "dangerous": dangerous, "warnings": warnings},
                duration_ms=duration_ms,
            )

        if warnings:
            return CheckResult(
                status="warn",
                message=f"Pickle parsed, {len(warnings)} warnings (but pickle is never fully safe)",
                severity="minor",
                suggestion="Проверь warnings вручную (inspect --search) — возможна обфускация",
                details={**base_details, "warnings": warnings},
                duration_ms=duration_ms,
            )

        return CheckResult(
            status="warn",
            message="Pickle parsed, no known dangerous globals (pickle is never fully safe)",
            details={**base_details, "note": "Static scan is best-effort."},
            duration_ms=duration_ms,
        )

    # ── классификация контейнера ────────────────────────────────
    def _scan_file(
        self, file_path: Path, cancel_check: Callable[[], bool] | None
    ) -> dict | None:
        with open(file_path, "rb") as f:
            magic = f.read(4)

        if magic[:2] == b"PK":
            return self._scan_zip(file_path, cancel_check)

        if magic[:1] == bytes([self.PICKLE_MAGIC]):
            return self._scan_pickle_file(file_path)

        # FIX B1: протоколы 0/1 не имеют magic 0x80 — доверяем расширению
        if file_path.suffix.lower() in self.SUPPORTED:
            return self._scan_pickle_file(file_path)

        return None  # не pickle — skip

    def _scan_pickle_file(self, file_path: Path) -> dict:
        with open(file_path, "rb") as f:
            return self._scan_pickle_stream(f)

    # ── один поток → эмулятор → findings ────────────────────────
    def _scan_pickle_stream(self, f) -> dict:
        data = f.read(self.MAX_PICKLE_STREAM_BYTES + 1)
        truncated = len(data) > self.MAX_PICKLE_STREAM_BYTES
        if truncated:
            data = data[: self.MAX_PICKLE_STREAM_BYTES]

        emu = self._emulator.run(data, truncated=truncated)
        result: dict[str, Any] = {
            "dangerous": [],
            "warnings": [],
            "reduce_count": emu.reduce_count,
            "stream_count": emu.stream_count,
            "disassembly": emu.disassembly,
        }

        if truncated:
            result["warnings"].append({
                "type": "truncated_stream",
                "message": f"stream > {self.MAX_PICKLE_STREAM_BYTES} bytes, scan truncated",
                "pos": -1,
            })

        for ev in emu.events:
            if ev.anomaly:
                result["warnings"].append({
                    "type": ev.anomaly,
                    "message": f"{ev.opcode}: {ev.anomaly}",
                    "pos": ev.pos,
                })
                continue
            if ev.module_attr:
                category = self._match_category(ev.module_attr)
                if category:
                    result["dangerous"].append({
                        "module": ev.module_attr,
                        "category": category,
                        "pos": ev.pos,
                        "opcode": ev.opcode,
                    })
                else:
                    result["warnings"].append({
                        "type": "import",
                        "message": f"imports {ev.module_attr}",
                        "pos": ev.pos,
                    })

        for err in emu.parse_errors:
            result["warnings"].append({"type": "parse_error", "message": err, "pos": -1})

        # REDUCE → BUILD подряд (эвристика сохранена, до RuleEngine в Шаге 3)
        for i in range(len(emu.events) - 1):
            if emu.events[i].opcode == "REDUCE" and emu.events[i + 1].opcode == "BUILD":
                result["warnings"].append({
                    "type": "reduce_build",
                    "message": "BUILD after REDUCE (possible bypass)",
                    "pos": emu.events[i + 1].pos,
                })

        return result

    # ── матчинг: exact-first, module-fallback ──────────────────
    def _match_category(self, full: str) -> str | None:
        if full in self.DANGEROUS_EXACT:
            return self.DANGEROUS_EXACT[full]
        module = full.split(".")[0]
        return self.DANGEROUS_MODULES.get(module)

    # ── ZIP-контейнер ──────────────────────────────────────────
    def _scan_zip(
        self, file_path: Path, cancel_check: Callable[[], bool] | None
    ) -> dict:
        result: dict[str, Any] = {
            "dangerous": [], "warnings": [],
            "reduce_count": 0, "stream_count": 0,
            "inner_files": [], "disassembly": [],
        }

        with zipfile.ZipFile(file_path, "r") as zf:
            pkl_names = [n for n in zf.namelist() if n.endswith(".pkl")]
            result["inner_files"] = zf.namelist()[:10]

            if not pkl_names:
                result["warnings"].append({
                    "type": "no_pickle",
                    "message": "ZIP container, no .pkl found",
                    "pos": -1,
                })
                return result

            for name in pkl_names:
                if cancel_check and cancel_check():
                    result["warnings"].append({
                        "type": "cancelled",
                        "message": "scan cancelled by caller",
                        "pos": -1,
                    })
                    break

                with zf.open(name) as pkl_file:
                    sub = self._scan_pickle_stream(pkl_file)
                for d in sub["dangerous"]:
                    d["inner_file"] = name
                    result["dangerous"].append(d)
                for w in sub["warnings"]:
                    w["inner_file"] = name
                    result["warnings"].append(w)
                for item in sub.get("disassembly", []):
                    item["inner_file"] = name
                    result["disassembly"].append(item)
                result["reduce_count"] += sub["reduce_count"]
                result["stream_count"] += sub["stream_count"]

        return result