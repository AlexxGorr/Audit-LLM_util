"""Тесты Шага 1: OpcodeEmulator + фикс протокола 0/1 + multi-stream."""
from pathlib import Path

import pytest

from auditllm.checks.pickle_check import PickleCheck

FIX = Path(__file__).parent / "fixtures" / "pickle"


@pytest.mark.parametrize("name,expected_status", [
    ("clean_v4.pkl", "warn"),
    ("os_system_v4.pkl", "fail"),
    ("obfuscated_memo_v4.pkl", "fail"),
    ("multi_stream.pkl", "fail"),
    ("os_system_v0.pkl", "fail"),
    ("evil_model.pt", "fail"),
])
def test_status(name: str, expected_status: str) -> None:
    res = PickleCheck().run(FIX / name)
    assert res.status == expected_status, (name, res.message, res.details)


def test_obfuscated_resolves_module_attr() -> None:
    res = PickleCheck().run(FIX / "obfuscated_memo_v4.pkl")
    modules = {d["module"] for d in res.details["dangerous"]}
    assert "os.system" in modules


def test_multi_stream_reported() -> None:
    res = PickleCheck().run(FIX / "multi_stream.pkl")
    types = {w["type"] for w in res.details.get("warnings", [])}
    assert "multi_stream" in types


def test_clean_not_fail() -> None:
    res = PickleCheck().run(FIX / "clean_v4.pkl")
    assert res.status != "fail"


def test_zip_inner_file_annotated() -> None:
    res = PickleCheck().run(FIX / "evil_model.pt")
    inner = {d.get("inner_file") for d in res.details["dangerous"]}
    assert "data.pkl" in inner


def test_cancel_check_respected(tmp_path) -> None:
    # Простейший тест: если cancel_check сразу True — сканирование ZIP прерывается
    calls = {"n": 0}

    def _cancel() -> bool:
        calls["n"] += 1
        return True

    res = PickleCheck().run(FIX / "evil_model.pt", cancel_check=_cancel)
    assert calls["n"] >= 1
    types = {w["type"] for w in res.details.get("warnings", [])}
    assert "cancelled" in types


    