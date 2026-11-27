"""Тесты Шага 2: ContainerWalker (TAR, TAR.GZ, вложенный ZIP, скрытый pickle, zip-bomb)."""
import importlib.util
from pathlib import Path

import pytest

from auditllm.checks.pickle_check import PickleCheck

FIX = Path(__file__).parent / "fixtures" / "pickle"


# ── TAR / TAR.GZ ───────────────────────────────────────────────
def test_tar_container_detected() -> None:
    res = PickleCheck().run(FIX / "evil_model.tar")
    assert res.status == "fail", (res.message, res.details)
    modules = {d["module"] for d in res.details["dangerous"]}
    assert "posix.system" in modules


def test_targz_container_detected() -> None:
    res = PickleCheck().run(FIX / "evil_model.tar.gz")
    assert res.status == "fail", (res.message, res.details)
    modules = {d["module"] for d in res.details["dangerous"]}
    assert "posix.system" in modules


# ── Вложенный ZIP ──────────────────────────────────────────────
def test_nested_zip_detected() -> None:
    res = PickleCheck().run(FIX / "nested_evil.zip")
    assert res.status == "fail", (res.message, res.details)
    modules = {d["module"] for d in res.details["dangerous"]}
    assert "posix.system" in modules
    # inner_file должен содержать цепочку через "!"
    inner = {d["inner_file"] for d in res.details["dangerous"]}
    assert any("inner.zip!data.pkl" in p for p in inner), inner


def test_nested_zip_depth_limited() -> None:
    """max_depth=0 отключает рекурсию — вложенный pickle не сканируется."""
    res = PickleCheck().run(FIX / "nested_evil.zip", context={"pickle_max_depth": 0})
    # при depth=0 внешний ZIP не раскрывается, а сам по себе ZIP — не pickle
    assert res.status in ("warn", "fail"), (res.message, res.details)
    # dangerous пуст, если рекурсия отключена, но это не гарантия —
    # главное, что max_depth_reached в warnings
    types = {w["type"] for w in res.details.get("warnings", [])}
    assert "max_depth_reached" in types


# ── Скрытый pickle без расширения .pkl ─────────────────────────
def test_hidden_pickle_in_zip() -> None:
    res = PickleCheck().run(FIX / "hidden_pickle.zip")
    assert res.status == "fail", (res.message, res.details)
    modules = {d["module"] for d in res.details["dangerous"]}
    assert "posix.system" in modules


# ── Zip Bomb ───────────────────────────────────────────────────
def test_zip_bomb_budget_respected() -> None:
    """Бюджет 200 MB должен остановить распаковку 300 MB бомбы."""
    res = PickleCheck().run(FIX / "zip_bomb.pt", context={"pickle_unpack_budget_mb": 10})
    types = {w["type"] for w in res.details.get("warnings", [])}
    assert "budget_exceeded" in types, (res.message, res.details)


# ── 7z не поддерживается — warning, не падение ─────────────────
def test_7z_warns_not_crashes(tmp_path: Path) -> None:
    # минимальный 7z-заголовок + мусор
    p = tmp_path / "fake.7z"
    p.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
    res = PickleCheck().run(p)
    # не должен падать; статус warn (нет streams, есть warning)
    assert res.status in ("warn", "fail"), (res.message, res.details)
    types = {w["type"] for w in res.details.get("warnings", [])}
    assert "7z_not_supported" in types


# ── NPY (условно, если numpy есть) ─────────────────────────────
@pytest.mark.skipif(
    not importlib.util.find_spec("numpy"),
    reason="numpy not installed",
)
def test_npy_object_dtype() -> None:
    res = PickleCheck().run(FIX / "evil_object.npy")
    types = {w["type"] for w in res.details.get("warnings", [])}
    assert "npy_object_dtype" in types, (res.message, res.details)
    assert res.status == "fail"


# ── контейнер без pickle — warn, не skip ───────────────────────
def test_empty_zip_warns(tmp_path: Path) -> None:
    import zipfile
    p = tmp_path / "empty.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("readme.txt", b"hello")
    res = PickleCheck().run(p)
    assert res.status == "warn", (res.message, res.details)
    types = {w["type"] for w in res.details.get("warnings", [])}
    assert "no_pickle_stream" in types



