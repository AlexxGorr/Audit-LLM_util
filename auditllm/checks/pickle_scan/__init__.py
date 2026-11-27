"""Внутренние модули pickle-сканера (стек-эмулятор, контейнеры, правила)."""
from auditllm.checks.pickle_scan.container_walker import (
    ContainerWalker,
    StreamRef,
    WalkResult,
)
from auditllm.checks.pickle_scan.opcode_emulator import OpcodeEmulator
from auditllm.checks.pickle_scan.rules import (
    HARD_BLOCK,
    SOFT_MODULES_MAJOR,
    SOFT_MODULES_MINOR,
    Finding,
    RuleContext,
    RuleEngine,
    Severity,
)

__all__ = [
    "ContainerWalker",
    "StreamRef",
    "WalkResult",
    "OpcodeEmulator",
    "RuleEngine",
    "RuleContext",
    "Finding",
    "Severity",
    "HARD_BLOCK",
    "SOFT_MODULES_MAJOR",
    "SOFT_MODULES_MINOR",
]



