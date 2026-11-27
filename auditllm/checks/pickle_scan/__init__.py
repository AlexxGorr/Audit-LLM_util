"""Внутренние модули pickle-сканера (стек-эмулятор, контейнеры, правила)."""
from auditllm.checks.pickle_scan.container_walker import (
    ContainerWalker,
    StreamRef,
    WalkResult,
)
from auditllm.checks.pickle_scan.opcode_emulator import OpcodeEmulator

__all__ = [
    "ContainerWalker",
    "StreamRef",
    "WalkResult",
    "OpcodeEmulator",
]




