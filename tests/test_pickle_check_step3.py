"""Тесты Шага 3.1: RuleEngine (hard/soft, контекстные правила)."""
from pathlib import Path

import pytest

from auditllm.checks.pickle_check import PickleCheck

FIX = Path(__file__).parent / "fixtures" / "pickle"


# ── hard_block ─────────────────────────────────────────────────
def test_hard_block_importlib() -> None:
    res = PickleCheck().run(FIX / "importlib_hard.pkl")
    assert res.status == "fail"
    codes = {d["category"] for d in res.details["dangerous"]}
    assert "hard_block" in codes
    mods = {d["module"] for d in res.details["dangerous"]}
    assert "importlib.import_module" in mods


# ── reduce_chain (hard) ────────────────────────────────────────
def test_reduce_chain_hard() -> None:
    res = PickleCheck().run(FIX / "stack_global_reduce.pkl")
    assert res.status == "fail"
    codes = {d["category"] for d in res.details["dangerous"]}
    assert "reduce_chain" in codes


# ── many_reduces ───────────────────────────────────────────────
def test_many_reduces() -> None:
    res = PickleCheck().run(FIX / "many_reduces.pkl")
    assert res.status == "fail"
    wtypes = {w["type"] for w in res.details["warnings"]}
    assert "many_reduces" in wtypes
    assert res.details["reduce_count"] > 2


# ── dynamic_global ─────────────────────────────────────────────
def test_dynamic_global_balanced() -> None:
    res = PickleCheck().run(FIX / "dynamic_global.pkl", context={"pickle_policy": "balanced"})
    assert res.status == "fail"
    codes = {d["category"] for d in res.details["dangerous"]}
    assert "dynamic_global" in codes


def test_dynamic_global_permissive() -> None:
    res = PickleCheck().run(FIX / "dynamic_global.pkl", context={"pickle_policy": "permissive"})
    # при permissive dynamic_global → minor → warn, не fail
    assert res.status == "warn", (res.message, res.details)
    wtypes = {w["type"] for w in res.details["warnings"]}
    assert "dynamic_global" in wtypes


# ── soft_major: не fail ────────────────────────────────────────
def test_legit_import_not_fail() -> None:
    res = PickleCheck().run(FIX / "legit_import.pkl")
    assert res.status == "warn", (res.message, res.details)
    assert not res.details.get("dangerous")


# ── регрессия Шаг 1/2 ──────────────────────────────────────────
def test_os_system_still_fail() -> None:
    res = PickleCheck().run(FIX / "os_system_v4.pkl")
    assert res.status == "fail"


def test_clean_still_warn() -> None:
    res = PickleCheck().run(FIX / "clean_v4.pkl")
    assert res.status == "warn"