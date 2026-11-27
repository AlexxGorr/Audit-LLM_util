"""Статический анализ pickle-файлов (без выполнения)."""
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from auditllm.checks.base import Check, CheckResult
from auditllm.checks.pickle_scan.container_walker import ContainerWalker
from auditllm.checks.pickle_scan.opcode_emulator import OpcodeEmulator
from auditllm.checks.pickle_scan.rules import RuleContext, RuleEngine

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


class PickleCheck(Check):
    name = "pickle"
    description = "Static pickle safety scan (no execution)"

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

    MAX_PICKLE_STREAM_BYTES = 50 * 1024 * 1024
    DEFAULT_POLICY = "balanced"

    def __init__(self) -> None:
        self._emulator = OpcodeEmulator()
        self._rules = RuleEngine()

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
        policy = ctx.get("pickle_policy", self.DEFAULT_POLICY)

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

        all_findings: list = []
        parse_warnings: list[dict] = list(walk.warnings)
        reduce_total = 0
        stream_total = 0
        disassembly: list[dict] = []

        for ref in walk.streams:
            if cancel_check and cancel_check():
                parse_warnings.append({
                    "type": "cancelled", "message": "scan cancelled", "pos": -1,
                })
                break
            emu = self._emulator.run(ref.data, truncated=False)
            reduce_total += emu.reduce_count
            stream_total += emu.stream_count
            for d in emu.disassembly:
                d["inner_file"] = ref.inner_path
                disassembly.append(d)
            for err in emu.parse_errors:
                parse_warnings.append({
                    "type": "parse_error",
                    "message": err,
                    "pos": -1,
                    "inner_file": ref.inner_path,
                })

            rctx = RuleContext(
                policy=policy,
                reduce_count=emu.reduce_count,
                stream_count=emu.stream_count,
                inner_file=ref.inner_path,
            )
            for f in self._rules.evaluate(emu.events, rctx):
                all_findings.append(f)

        dangerous = [
            {
                "module": f.module_attr,
                "category": f.code,
                "severity": f.severity,
                "message": f.message,
                "pos": f.pos,
                "inner_file": f.inner_file,
            }
            for f in all_findings if f.severity == "critical"
        ]
        warnings = [
            {
                "type": f.code,
                "message": f.message,
                "severity": f.severity,
                "pos": f.pos,
                "inner_file": f.inner_file,
            }
            for f in all_findings if f.severity != "critical"
        ] + parse_warnings

        base_details = {
            "reduce_count": reduce_total,
            "stream_count": stream_total,
            "inner_files": walk.inner_files,
            "disassembly": disassembly,
            "container_truncated": walk.truncated,
            "policy": policy,
            "findings_count": len(all_findings),
        }

        if dangerous:
            return CheckResult(
                status="fail",
                message=(
                    f"Pickle safety issues: {len(dangerous)} critical, "
                    f"{len(warnings)} warnings"
                ),
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



