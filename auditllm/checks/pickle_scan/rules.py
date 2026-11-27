"""RuleEngine: hard/soft правила и контекстные эвристики для pickle-потоков.

Severity:
- critical → fail при любой политике (кроме явного permissive для dynamic_global)
- major    → fail при strict, warn при balanced, warn при permissive
- minor    → warn при strict/balanced, warn/pass при permissive
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from auditllm.checks.pickle_scan.opcode_emulator import OpcodeEvent


Severity = Literal["critical", "major", "minor"]
Policy = Literal["strict", "balanced", "permissive"]


@dataclass
class Finding:
    severity: Severity
    code: str
    message: str
    pos: int = -1
    module_attr: str | None = None
    inner_file: str | None = None


@dataclass
class RuleContext:
    policy: Policy = "balanced"
    reduce_count: int = 0
    stream_count: int = 0
    inner_file: str | None = None


# ── HARD_BLOCK: точные module.attr, всегда critical ────────────
HARD_BLOCK: dict[str, str] = {
    # System calls
    "os.system": "system calls",
    "os.popen": "system calls",
    "os.spawn": "process spawn",
    "os.spawnl": "process spawn",
    "os.spawnv": "process spawn",
    "posix.system": "system calls",
    "posix.popen": "system calls",
    "nt.system": "system calls",
    # Process spawn
    "subprocess.Popen": "process spawn",
    "subprocess.call": "process spawn",
    "subprocess.run": "process spawn",
    "subprocess.check_call": "process spawn",
    "subprocess.check_output": "process spawn",
    # Code execution
    "builtins.eval": "arbitrary eval",
    "builtins.exec": "arbitrary exec",
    "builtins.compile": "code compilation",
    "builtins.__import__": "dynamic import",
    "builtins.open": "file manipulation",
    # Trampolines
    "operator.attrgetter": "attribute access",
    "operator.methodcaller": "method call",
    "operator.itemgetter": "item access",
    "functools.partial": "partial call",
    "types.FunctionType": "dynamic code",
    "types.CodeType": "dynamic code",
    "types.LambdaType": "dynamic code",
    # Dynamic import (точный вызов)
    "importlib.import_module": "dynamic import",
    "importlib.__import__": "dynamic import",
    # Torch (точные вызовы)
    "torch.hub.load": "external load",
    "torch.serialization._load": "external load",
    "torch.jit.load": "external load",
    "torch.utils.bottleneck.__main__": "code execution",
    # Modelscan bypass
    "distutils.spawn": "process spawn",
}


# ── SOFT_INDICATORS: модуль, у которого опасен любой атрибут ───
# major — warn при balanced, fail при strict
SOFT_MODULES_MAJOR: dict[str, str] = {
    "posix": "system calls",
    "nt": "system calls",
    "subprocess": "process spawn",
    "commands": "shell commands",
    "popen2": "process spawn",
    "builtins": "arbitrary eval/exec",
    "__builtin__": "arbitrary eval/exec",
    "runpy": "code execution",
    "code": "interactive interpreter",
    "codeop": "code compilation",
    "compile": "code compilation",
    "compileall": "code compilation",
    "importlib": "dynamic import",       # generic importlib.*
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
    "torch": "external load",           # generic torch.*
}

# minor — warning при balanced, не fail
SOFT_MODULES_MINOR: dict[str, str] = {
    "sys": "interpreter internals",
    "gc": "interpreter internals",
    "os": "system module (generic)",    # os.walk и т.п.
}


class RuleEngine:
    """Применяет hard/soft правила и контекстные эвристики."""

    def evaluate(
        self,
        events: list[OpcodeEvent],
        ctx: RuleContext,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. По каждому module.attr
        for ev in events:
            if ev.anomaly:
                findings.append(self._anomaly_to_finding(ev, ctx))
                continue
            if not ev.module_attr:
                continue
            findings.append(self._match_module_attr(ev, ctx))

        # 2. Контекстные правила (по всему потоку)
        findings.extend(self._contextual_rules(events, ctx))

        return findings

    # ── отдельный module.attr ──────────────────────────────────
    def _match_module_attr(self, ev: OpcodeEvent, ctx: RuleContext) -> Finding:
        full = ev.module_attr or ""
        if full in HARD_BLOCK:
            return Finding(
                severity="critical",
                code="hard_block",
                message=f"{full} ({HARD_BLOCK[full]})",
                pos=ev.pos,
                module_attr=full,
                inner_file=ctx.inner_file,
            )
        module = full.split(".")[0]
        if module in SOFT_MODULES_MAJOR:
            return Finding(
                severity="major",
                code="soft_major",
                message=f"{full} ({SOFT_MODULES_MAJOR[module]})",
                pos=ev.pos,
                module_attr=full,
                inner_file=ctx.inner_file,
            )
        if module in SOFT_MODULES_MINOR:
            return Finding(
                severity="minor",
                code="soft_minor",
                message=f"{full} ({SOFT_MODULES_MINOR[module]})",
                pos=ev.pos,
                module_attr=full,
                inner_file=ctx.inner_file,
            )
        return Finding(
            severity="minor",
            code="unknown_import",
            message=f"imports {full}",
            pos=ev.pos,
            module_attr=full,
            inner_file=ctx.inner_file,
        )

    # ── аномалии эмулятора ─────────────────────────────────────
    def _anomaly_to_finding(self, ev: OpcodeEvent, ctx: RuleContext) -> Finding:
        anomaly = ev.anomaly or "unknown"
        if anomaly == "dynamic_global":
            # критично при balanced/strict, minor при permissive
            sev: Severity = "minor" if ctx.policy == "permissive" else "critical"
            return Finding(
                severity=sev, code="dynamic_global",
                message=f"STACK_GLOBAL with non-string stack ({anomaly})",
                pos=ev.pos, inner_file=ctx.inner_file,
            )
        if anomaly == "multi_stream":
            return Finding(
                severity="major", code="multi_stream",
                message="multiple pickle streams in one file",
                pos=ev.pos, inner_file=ctx.inner_file,
            )
        if anomaly == "too_many_streams":
            return Finding(
                severity="major", code="too_many_streams",
                message="too many pickle streams",
                pos=ev.pos, inner_file=ctx.inner_file,
            )
        if anomaly == "stack_underflow":
            return Finding(
                severity="major", code="stack_underflow",
                message="STACK_GLOBAL with insufficient stack",
                pos=ev.pos, inner_file=ctx.inner_file,
            )
        if anomaly == "memo_miss":
            return Finding(
                severity="minor", code="memo_miss",
                message="BINGET of unknown memo slot (possibly obfuscated)",
                pos=ev.pos, inner_file=ctx.inner_file,
            )
        # bad_global_arg / прочее
        return Finding(
            severity="minor", code=anomaly,
            message=f"emulator anomaly: {anomaly}",
            pos=ev.pos, inner_file=ctx.inner_file,
        )

    # ── контекстные правила ────────────────────────────────────
    def _contextual_rules(
        self, events: list[OpcodeEvent], ctx: RuleContext,
    ) -> list[Finding]:
        out: list[Finding] = []

        # R1: REDUCE повышает severity, если вызывается опасный global.
        # Не добавляет critical сам по себе — иначе легитимный numpy.array даёт fail.
        has_stack_global = any(e.opcode == "STACK_GLOBAL" for e in events)
        if has_stack_global and ctx.reduce_count > 0:
            hard_attrs = [
                e.module_attr for e in events
                if e.module_attr and e.module_attr in HARD_BLOCK
            ]
            soft_attrs = [
                e.module_attr for e in events
                if e.module_attr and e.module_attr.split(".")[0] in SOFT_MODULES_MAJOR
            ]
            if hard_attrs:
                out.append(Finding(
                    severity="critical",
                    code="reduce_chain",
                    message=f"REDUCE on hard-blocked global: {hard_attrs[0]}",
                    pos=-1, inner_file=ctx.inner_file,
                ))
            elif soft_attrs:
                out.append(Finding(
                    severity="major",
                    code="reduce_chain_soft",
                    message=f"REDUCE on soft global: {soft_attrs[0]}",
                    pos=-1, inner_file=ctx.inner_file,
                ))

        # R2: >2 REDUCE в потоке → major
        if ctx.reduce_count > 2:
            out.append(Finding(
                severity="major",
                code="many_reduces",
                message=f"{ctx.reduce_count} REDUCE calls in one stream",
                pos=-1, inner_file=ctx.inner_file,
            ))

        # R3: REDUCE → BUILD подряд → major


        # R4: multi_stream + STACK_GLOBAL (во втором потоке) → critical
        # Эмулятор помечает MULTI_STREAM аномалией; проверяем, что после неё есть STACK_GLOBAL
        multi_idx = [i for i, e in enumerate(events) if e.opcode == "MULTI_STREAM"]
        for i in multi_idx:
            if any(e.opcode == "STACK_GLOBAL" for e in events[i + 1:]):
                out.append(Finding(
                    severity="critical",
                    code="multi_stream_global",
                    message="STACK_GLOBAL in second pickle stream",
                    pos=events[i].pos, inner_file=ctx.inner_file,
                ))
                break

        return out












