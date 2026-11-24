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
    DANGEROUS_CATEGORIES = {
        # ─── System calls ────────────────────────────────
        "os": "system calls",
        "posix": "system calls",
        "nt": "system calls",
        "subprocess": "process spawn",
        "commands": "shell commands",
        "popen2": "process spawn",

        # ─── Code execution ──────────────────────────────
        "builtins": "arbitrary eval/exec",
        "__builtin__": "arbitrary eval/exec",  # ← NEW (Python 2)
        "eval": "arbitrary eval",
        "exec": "arbitrary exec",
        "runpy": "code execution",
        "importlib": "dynamic import",
        "code": "interactive interpreter",
        "codeop": "code compilation",
        "compile": "code compilation",
        "compileall": "code compilation",

        # ─── Network ─────────────────────────────────────
        "socket": "network access",
        "urllib": "network access",
        "http": "network access",
        "ftplib": "network access",
        "telnetlib": "network access",
        "smtplib": "network access",
        "requests": "network access",

        # ─── File system ─────────────────────────────────
        "shutil": "file manipulation",
        "fileinput": "file manipulation",
        "tempfile": "file manipulation",
        "pathlib": "file manipulation",
        "glob": "file manipulation",

        # ─── Process/terminal ────────────────────────────
        "pty": "terminal control",
        "tty": "terminal control",
        "termios": "terminal control",
        "platform": "system info",
        "sys": "interpreter internals",
        "gc": "interpreter internals",

        # ─── Serialization (recursive) ───────────────────
        "pickle": "recursive pickle",
        "dill": "recursive pickle",
        "joblib": "recursive pickle",
        "marshal": "serialization internals",  # ← NEW

        # ─── Misc dangerous ──────────────────────────────
        "webbrowser": "browser control",
        "ctypes": "native code",
        "cffi": "native code",
        "multiprocessing": "process spawn",
        "threading": "thread manipulation",
        "signal": "signal manipulation",
        "resource": "resource manipulation",

        # ─── CVE-2025-71366: torch bottleneck ───────────
        "torch.utils.bottleneck.__main__": "code execution",  # ← NEW

        # ─── modelscan bypass: distutils.spawn ───────────
        "distutils": "process spawn",  # ← NEW
        "distutils.spawn": "process spawn",  # ← NEW
    }

    # Pickle magic byte (protocol 2+)
    PICKLE_MAGIC = 0x80

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.SUPPORTED

    def run(self,
            file_path: Path,
            context: dict[Any, Any] | None = None,
            progress: ProgressReporter | None = None) -> CheckResult:
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
        reduce_count = findings.get("reduce_count", 0)
        inner_files = findings.get("inner_files", [])
        disassembly = findings.get("disassembly", [])

        if dangerous:
            return CheckResult(
                status="fail",
                message=f"Pickle safety issues: {len(dangerous)} dangerous, {len(warnings)} warnings",
                severity="critical",
                suggestion="⚠️ НЕ загружай файл: возможна RCE. Удали или проверь в песочнице (inspect --search)",
                details={
                    "dangerous": dangerous,
                    "warnings": warnings,
                    "reduce_count": reduce_count,
                    "inner_files": inner_files,
                    "disassembly": disassembly,
                },
                duration_ms=duration_ms,
            )

        if warnings:
            return CheckResult(
                status="warn",
                message=f"Pickle parsed, {len(warnings)} warnings (but pickle is never fully safe)",
                severity="minor",
                suggestion="Проверь warnings вручную (inspect --search) — возможна обфускация",
                details={
                    "warnings": warnings,
                    "reduce_count": reduce_count,
                    "inner_files": inner_files,
                    "disassembly": disassembly,
                },
                duration_ms=duration_ms,
            )

        return CheckResult(
            status="warn",
            message="Pickle parsed, no known dangerous globals (pickle is never fully safe)",
            details={
                "note": "Static scan is best-effort.",
                "reduce_count": reduce_count,
                "inner_files": inner_files,
                "disassembly": disassembly,
            },
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
        result = {"dangerous": [], "warnings": [], "reduce_count": 0, "disassembly": []}

        string_stack: list[str] = []
        STRING_OPCODES = {
            "SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
            "BINUNICODE8", "SHORT_BINSTRING", "BINSTRING", "STRING",
        }
        last_was_reduce = False

        try:
            for opcode, arg, pos in pickletools.genops(f):
                name = opcode.name

                # Добавить в disassembly (c6: лимит 1000)
                arg_repr = repr(arg) if arg is not None else ""
                if len(result["disassembly"]) < 1000:
                    result["disassembly"].append({
                        "pos": pos,
                        "opcode": name,
                        "arg": arg_repr[:80],
                    })

                if name in STRING_OPCODES and isinstance(arg, str):
                    string_stack.append(arg)
                    if len(string_stack) > 10:
                        string_stack.pop(0)


                elif name == "GLOBAL":
                    if arg:
                        # pickletools возвращает "module name" (с пробелом) или (module, name)
                        if isinstance(arg, tuple):
                            module, name_attr = arg
                            full = f"{module}.{name_attr}"
                        else:
                            # строка "module name" → "module.name"
                            full = arg.replace(" ", ".")
                        matched = False
                        for key, category in self.DANGEROUS_CATEGORIES.items():
                            if full == key or full.startswith(key + "."):
                                result["dangerous"].append({
                                    "module": full,
                                    "category": category,
                                    "pos": pos,
                                })
                                matched = True
                                break
                        if not matched:
                            module = full.split(".")[0]
                            if module in self.DANGEROUS_CATEGORIES:
                                result["dangerous"].append({
                                    "module": full,
                                    "category": self.DANGEROUS_CATEGORIES[module],
                                    "pos": pos,
                                })

                elif name == "STACK_GLOBAL":
                    if len(string_stack) >= 2:
                        module = string_stack[-2]
                        attr = string_stack[-1]
                        full = f"{module}.{attr}"
                        matched = False
                        for key, category in self.DANGEROUS_CATEGORIES.items():
                            if full == key or full.startswith(key + "."):
                                result["dangerous"].append({
                                    "module": full,
                                    "category": category,
                                    "pos": pos,
                                })
                                matched = True
                                break
                        if not matched:
                            if module in self.DANGEROUS_CATEGORIES:
                                result["dangerous"].append({
                                    "module": full,
                                    "category": self.DANGEROUS_CATEGORIES[module],
                                    "pos": pos,
                                })
                            else:
                                result["warnings"].append({
                                    "type": "import",
                                    "message": f"imports {full}",
                                    "pos": pos,
                                })
                        string_stack = string_stack[:-2]
                    else:
                        # STACK_GLOBAL без резолва — подозрительно (obfuscation),
                        # но protocol 4+ может использовать memo (ложный warn)
                        result["warnings"].append({
                            "type": "obfuscated_import",
                            "message": "STACK_GLOBAL without resolvable stack (possible obfuscation)",
                            "pos": pos,
                        })

                elif name == "REDUCE":
                    result["reduce_count"] += 1
                    last_was_reduce = True

                elif name == "BUILD" and last_was_reduce:
                    result["warnings"].append({
                        "type": "reduce_build",
                        "message": "BUILD after REDUCE (possible bypass)",
                        "pos": pos,
                    })
                    last_was_reduce = False

                elif name in ("POP", "POP_MARK"):
                    string_stack = string_stack[:-1] if string_stack else []

                # Сброс last_was_reduce после любого другого opcode
                if name not in ("REDUCE", "BUILD"):
                    last_was_reduce = False

        except Exception as e:
            result["warnings"].append({
                "type": "parse_error",
                "message": str(e),
                "pos": -1,
            })

        return result

    def _scan_zip(self, file_path: Path) -> dict:
        result = {"dangerous": [], "warnings": [], "reduce_count": 0, "inner_files": [], "disassembly": []}

        with zipfile.ZipFile(file_path, "r") as zf:
            pkl_names = [n for n in zf.namelist() if n.endswith(".pkl")]
            result["inner_files"] = zf.namelist()[:10]  # первые 10

            if not pkl_names:
                result["warnings"].append({
                    "type": "no_pickle",
                    "message": f"ZIP container, no .pkl found",
                    "pos": -1,
                })
                return result

            for name in pkl_names:
                with zf.open(name) as pkl_file:
                    sub = self._scan_pickle_stream(pkl_file)
                    # добавляем префикс с именем файла
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

        return result











