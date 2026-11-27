"""Статический анализ pickle-файлов (без выполнения)."""
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from auditllm.checks.base import Check, CheckResult
from auditllm.checks.pickle_scan.container_walker import ContainerWalker
from auditllm.checks.pickle_scan.opcode_emulator import OpcodeEmulator
from auditllm.checks.pickle_scan.rules import RuleContext, RuleEngine
from auditllm.checks.pickle_scan.verdict import VerdictAggregator

if TYPE_CHECKING:
    from auditllm.progress import ProgressReporter


class PickleCheck(Check):
    name = "pickle"
    description = "Static pickle safety scan (no execution)"

    SUPPORTED = {
        ".pkl", ".pickle", ".joblib", ".dill",
        ".pt", ".pth", ".bin", ".ckpt",
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
        ".npy", ".npz",
    }

    MAX_PICKLE_STREAM_BYTES = 50 * 1024 * 1024
    DEFAULT_POLICY = "balanced"

    def __init__(self) -> None:
        self._emulator = OpcodeEmulator()
        self._rules = RuleEngine()
        self._verdict = VerdictAggregator()

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
            return self._verdict.build(
                findings=[],
                ctx=RuleContext(policy=policy),
                parse_warnings=list(walk.warnings) or [{
                    "type": "no_pickle_stream",
                    "message": "no pickle-like stream found in container",
                    "pos": -1,
                }],
                walk_info={
                    "inner_files": walk.inner_files,
                    "container_truncated": walk.truncated,
                    "reduce_count": 0,
                    "stream_count": 0,
                    "disassembly": [],
                },
            )

        all_findings = []
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
                    "type": "parse_error", "message": err,
                    "pos": -1, "inner_file": ref.inner_path,
                })

            rctx = RuleContext(
                policy=policy,
                reduce_count=emu.reduce_count,
                stream_count=emu.stream_count,
                inner_file=ref.inner_path,
            )
            all_findings.extend(self._rules.evaluate(emu.events, rctx))

        result = self._verdict.build(
            findings=all_findings,
            ctx=RuleContext(policy=policy),
            parse_warnings=parse_warnings,
            walk_info={
                "inner_files": walk.inner_files,
                "container_truncated": walk.truncated,
                "reduce_count": reduce_total,
                "stream_count": stream_total,
                "disassembly": disassembly,
            },
        )
        result.duration_ms = duration_ms
        return result


