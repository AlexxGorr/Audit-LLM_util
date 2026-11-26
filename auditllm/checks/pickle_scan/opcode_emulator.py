"""Эмуляция стека pickle: резолв STACK_GLOBAL/INST/OBJ, memo, multi-stream.

Не исполняет pickle — только дизассемблирует и моделирует стек,
чтобы корректно разрешать module.attr в обход обфускации.
"""
from __future__ import annotations

import io
import pickletools
from dataclasses import dataclass, field
from typing import Any


class _Mark:
    __slots__ = ()


class _Obj:
    __slots__ = ()


_MARK = _Mark()
_OBJ = _Obj()


@dataclass
class OpcodeEvent:
    opcode: str
    pos: int
    module_attr: str | None = None
    anomaly: str | None = None  # dynamic_global / stack_underflow / multi_stream / memo_miss


@dataclass
class EmulatorResult:
    events: list[OpcodeEvent] = field(default_factory=list)
    reduce_count: int = 0
    stream_count: int = 0
    disassembly: list[dict] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    truncated: bool = False


_STR_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
    "BINUNICODE8", "SHORT_BINSTRING", "BINSTRING", "STRING",
})
_PUSH_OBJ = frozenset({
    "NONE", "NEWTRUE", "NEWFALSE", "INT", "BININT", "BININT1", "BININT2",
    "LONG", "LONG1", "LONG4", "FLOAT", "BINFLOAT",
    "BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8",
    "EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_DICT", "EMPTY_SET",
    "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID", "NEXT_BUFFER",
})


class OpcodeEmulator:
    MAX_STREAMS = 8
    MAX_DISASSEMBLY = 1000

    def run(self, data: bytes, truncated: bool = False) -> EmulatorResult:
        res = EmulatorResult(truncated=truncated)
        offset = 0
        n = len(data)
        while offset < n:
            if res.stream_count >= self.MAX_STREAMS:
                res.events.append(OpcodeEvent("MULTI_STREAM", offset, anomaly="too_many_streams"))
                break
            stop_pos = self._run_one(data, offset, res)
            if stop_pos is None:
                break
            res.stream_count += 1
            offset = stop_pos + 1
            if offset < n:
                res.events.append(OpcodeEvent("MULTI_STREAM", offset, anomaly="multi_stream"))
        return res

    # ── один поток ──────────────────────────────────────────────
    def _run_one(self, data: bytes, offset: int, res: EmulatorResult) -> int | None:
        stack: list[Any] = []
        memo: dict[int, Any] = {}
        stop_pos: int | None = None
        try:
            for opcode, arg, pos in pickletools.genops(io.BytesIO(data[offset:])):
                abs_pos = offset + pos
                self._record(res, opcode.name, arg, abs_pos)
                self._process(opcode.name, arg, abs_pos, stack, memo, res)
                if opcode.name == "STOP":
                    stop_pos = abs_pos
                    break
        except Exception as e:  # noqa: BLE001 — любой сбой парсинга = сигнал
            res.parse_errors.append(f"at {offset}: {e}")
            return None
        return stop_pos

    # ── дизассемблер ────────────────────────────────────────────
    def _record(self, res: EmulatorResult, name: str, arg: Any, pos: int) -> None:
        if len(res.disassembly) >= self.MAX_DISASSEMBLY:
            return
        arg_repr = repr(arg) if arg is not None else ""
        res.disassembly.append({"pos": pos, "opcode": name, "arg": arg_repr[:80]})

    # ── семантика опкодов ───────────────────────────────────────
    def _process(self, name, arg, pos, stack: list, memo: dict, res: EmulatorResult) -> None:
        if name in _STR_OPCODES and isinstance(arg, str):
            stack.append(arg)
        elif name in _PUSH_OBJ:
            stack.append(_OBJ)
        elif name == "MARK":
            stack.append(_MARK)
        elif name == "POP":
            if stack:
                stack.pop()
        elif name == "POP_MARK":
            self._pop_mark(stack)
        elif name == "DUP":
            if stack:
                stack.append(stack[-1])
        elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
            if stack and isinstance(arg, int):
                memo[arg] = stack[-1]
        elif name == "MEMOIZE":
            if stack:
                memo[len(memo)] = stack[-1]
        elif name in ("GET", "BINGET", "LONG_BINGET"):
            if isinstance(arg, int) and arg in memo:
                stack.append(memo[arg])
            else:
                res.events.append(OpcodeEvent(name, pos, anomaly="memo_miss"))
        elif name == "GLOBAL":
            self._emit_module_attr(name, arg, pos, res)
            stack.append(_OBJ)
        elif name == "INST":
            self._emit_module_attr(name, arg, pos, res)
            self._pop_mark(stack)
            stack.append(_OBJ)
        elif name == "STACK_GLOBAL":
            if len(stack) < 2:
                res.events.append(OpcodeEvent(name, pos, anomaly="stack_underflow"))
                return
            attr = stack.pop()
            module = stack.pop()
            if not isinstance(module, str) or not isinstance(attr, str):
                res.events.append(OpcodeEvent(name, pos, anomaly="dynamic_global"))
            else:
                res.events.append(OpcodeEvent(name, pos, module_attr=f"{module}.{attr}"))
            stack.append(_OBJ)
        elif name in ("TUPLE", "LIST", "DICT", "SET", "FROZENSET"):
            self._pop_mark(stack)
            stack.append(_OBJ)
        elif name in ("APPENDS", "SETITEMS", "ADDITEMS"):
            self._pop_mark(stack)
        elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
            n = {"TUPLE1": 1, "TUPLE2": 2, "TUPLE3": 3}[name]
            for _ in range(n):
                if stack:
                    stack.pop()
            stack.append(_OBJ)
        elif name == "APPEND":
            if stack:
                stack.pop()
        elif name == "SETITEM":
            for _ in range(2):
                if stack:
                    stack.pop()
        elif name == "REDUCE":
            res.reduce_count += 1
            if stack:
                stack.pop()  # args
            if stack:
                stack.pop()  # callable
            stack.append(_OBJ)
        elif name == "BUILD":
            if stack:
                stack.pop()
        elif name == "NEWOBJ":
            for _ in range(2):
                if stack:
                    stack.pop()
            stack.append(_OBJ)
        elif name == "NEWOBJ_EX":
            for _ in range(3):
                if stack:
                    stack.pop()
            stack.append(_OBJ)
        elif name == "OBJ":
            self._pop_mark(stack)
            if stack:
                stack.pop()  # class
            stack.append(_OBJ)
        elif name == "READONLY_BUFFER":
            if stack:
                stack.pop()
            stack.append(_OBJ)
        # PROTO / FRAME / STOP — без изменений стека

    def _emit_module_attr(self, name: str, arg: Any, pos: int, res: EmulatorResult) -> None:
        if isinstance(arg, tuple) and len(arg) == 2:
            module, attr = arg
        elif isinstance(arg, str):
            module, _, attr = arg.replace("\n", " ").partition(" ")
            attr = attr.strip()
        else:
            res.events.append(OpcodeEvent(name, pos, anomaly="bad_global_arg"))
            return
        if module and attr:
            res.events.append(OpcodeEvent(name, pos, module_attr=f"{module}.{attr}"))
        else:
            res.events.append(OpcodeEvent(name, pos, anomaly="bad_global_arg"))

    @staticmethod
    def _pop_mark(stack: list) -> list:
        items: list[Any] = []
        while stack:
            x = stack.pop()
            if x is _MARK:
                return items
            items.append(x)
        return items  # MARK не найден — малформированный поток, caller решит




    