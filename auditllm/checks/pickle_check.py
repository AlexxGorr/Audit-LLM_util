"""Статический анализ pickle-файлов (без выполнения)."""
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from auditllm.checks.base import Check, CheckResult
from auditllm.checks.pickle_scan.container_walker import ContainerWalker
from auditllm.checks.pickle_scan.opcode_emulator import OpcodeEmulator

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


class PickleCheck(Check):
    name = "pickle"
    description = "Static pickle safety scan (no execution)"

    # Форматы, которые могут содержать pickle
    SUPPORTED = {
        # «сырой» pickle
        ".pkl", ".pickle", ".joblib", ".dill",
        # PyTorch / чекпоинты (ZIP)
        ".pt", ".pth", ".bin", ".ckpt",
        # Контейнеры (ContainerWalker)
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
        # NumPy
        ".npy", ".npz",
    }

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
        "os": "system calls",
        "posix": "system calls",
        "nt": "system calls",
        "subprocess": "process spawn",
        "commands": "shell commands",
        "popen2": "process spawn",
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
        "socket": "network access",
        "urllib": "network access",
        "http": "network access",
        "ftplib": "network access",
        "telnetlib": "network access",
        "smtplib": "network access",
        "requests": "network access",
        "shutil": "file manipulation",
        "fileinput": "file manipulation",
        "tempfile": "file manipulation",
        "pathlib": "file manipulation",
        "glob": "file manipulation",
        "pty": "terminal control",
        "tty": "terminal control",
        "termios": "terminal control",
        "platform": "system info",
        "sys": "interpreter internals",
        "gc": "interpreter internals",
        "pickle": "recursive pickle",
        "dill": "recursive pickle",
        "joblib": "recursive pickle",
        "marshal": "serialization internals",
        "webbrowser": "browser control",
        "ctypes": "native code",
        "cffi": "native code",
        "multiprocessing": "process spawn",
        "threading": "thread manipulation",
        "signal": "signal manipulation",
        "resource": "resource manipulation",
        "distutils": "process spawn",
    }

    def __init__(self) -> None:
        self._emulator = OpcodeEmulator()

    def supports(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return any(name.endswith(ext) for ext in self.SUPPORTED)

    def run(
        self,
        file_path: Path,
        context: dict[Any, Any] | None = None,
        progress: "ProgressReporter | None" = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> CheckResult:
        start = time.monotonic()
        ctx = context or {}

        max_depth = int(ctx.get("pickle_max_depth", 3))
        budget_mb = int(ctx.get("pickle_unpack_budget_mb", 200))

        walker = ContainerWalker(
            max_depth=max_depth,
            budget_mb=budget_mb,
            max_stream_bytes=self.MAX_PICKLE_STREAM_BYTES,
        )

        try:
            walk = walker.walk(file_path, cancel_check=cancel_check)
        except Exception as e:  # noqa: BLE001
            return CheckResult(
                status="fail",
                message=f"Pickle scan failed: {e}",
                details={"error": str(e)},
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        duration_ms = int((time.monotonic() - start) * 1000)

        if not walk.streams:
            warnings = list(walk.warnings)
            if not warnings:
                warnings.append({
                    "type": "no_pickle_stream",
                    "message": "no pickle-like stream found in container",
                    "pos": -1,
                })
            return CheckResult(
                status="warn",
                message=f"No pickle stream scanned, {len(warnings)} warnings",
                severity="minor",
                details={
                    "warnings": warnings,
                    "inner_files": walk.inner_files,
                    "container_truncated": walk.truncated,
                },
                duration_ms=duration_ms,
            )

        aggregated = {
            "dangerous": [],
            "warnings": list(walk.warnings),
            "reduce_count": 0,
            "stream_count": 0,
            "inner_files": walk.inner_files,
            "disassembly": [],
        }

        for ref in walk.streams:
            if cancel_check and cancel_check():
                aggregated["warnings"].append({
                    "type": "cancelled", "message": "scan cancelled", "pos": -1,
                })
                break
            sub = self._scan_pickle_bytes(ref.data)
            for d in sub["dangerous"]:
                d["inner_file"] = ref.inner_path
                aggregated["dangerous"].append(d)
            for w in sub["warnings"]:
                w["inner_file"] = ref.inner_path
                aggregated["warnings"].append(w)
            for item in sub["disassembly"]:
                item["inner_file"] = ref.inner_path
                aggregated["disassembly"].append(item)
            aggregated["reduce_count"] += sub["reduce_count"]
            aggregated["stream_count"] += sub["stream_count"]

        base_details = {
            "reduce_count": aggregated["reduce_count"],
            "stream_count": aggregated["stream_count"],
            "inner_files": aggregated["inner_files"],
            "disassembly": aggregated["disassembly"],
            "container_truncated": walk.truncated,
        }

        if aggregated["dangerous"]:
            return CheckResult(
                status="fail",
                message=(
                    f"Pickle safety issues: {len(aggregated['dangerous'])} dangerous, "
                    f"{len(aggregated['warnings'])} warnings"
                ),
                severity="critical",
                suggestion="⚠️ НЕ загружай файл: возможна RCE. Удали или проверь в песочнице (inspect --search)",
                details={**base_details, "dangerous": aggregated["dangerous"], "warnings": aggregated["warnings"]},
                duration_ms=duration_ms,
            )

        if aggregated["warnings"]:
            return CheckResult(
                status="warn",
                message=f"Pickle parsed, {len(aggregated['warnings'])} warnings (but pickle is never fully safe)",
                severity="minor",
                suggestion="Проверь warnings вручную (inspect --search) — возможна обфускация",
                details={**base_details, "warnings": aggregated["warnings"]},
                duration_ms=duration_ms,
            )

        return CheckResult(
            status="warn",
            message="Pickle parsed, no known dangerous globals (pickle is never fully safe)",
            details={**base_details, "note": "Static scan is best-effort."},
            duration_ms=duration_ms,
        )

    # ── один поток → эмулятор → findings ────────────────────────
    def _scan_pickle_bytes(self, data: bytes) -> dict:
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



