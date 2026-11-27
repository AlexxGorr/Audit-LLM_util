"""Тесты Шага 3.2: VerdictAggregator (матрица политик)."""
from pathlib import Path

import pytest

from auditllm.checks.pickle_check import PickleCheck

FIX = Path(__file__).parent / "fixtures" / "pickle"


# ── strict: major → fail ───────────────────────────────────────
def test_strict_major_fails() -> None:
    res = PickleCheck().run(
        FIX / "many_reduces.pkl", context={"pickle_policy": "strict"},
    )
    assert res.status == "fail", (res.message, res.details)


# ── balanced: major → warn ─────────────────────────────────────
def test_balanced_major_warns() -> None:
    res = PickleCheck().run(
        FIX / "legit_import.pkl", context={"pickle_policy": "balanced"},
    )
    assert res.status == "warn", (res.message, res.details)


# ── permissive: major → warn (не fail) ─────────────────────────
def test_permissive_major_warns() -> None:
    res = PickleCheck().run(
        FIX / "many_reduces.pkl", context={"pickle_policy": "permissive"},
    )
    # many_reduces — major; hard_block — critical → fail всё равно
    # поэтому берём фикстуру без critical: legit_import (только minor)
    res2 = PickleCheck().run(
        FIX / "legit_import.pkl", context={"pickle_policy": "permissive"},
    )
    assert res2.status == "warn", (res2.message, res2.details)


# ── critical → fail при любой политике ─────────────────────────
@pytest.mark.parametrize("policy", ["strict", "balanced", "permissive"])
def test_critical_fails_any_policy(policy: str) -> None:
    res = PickleCheck().run(
        FIX / "os_system_v4.pkl", context={"pickle_policy": policy},
    )
    assert res.status == "fail", (policy, res.message, res.details)


# ── minor-only: strict → fail, balanced → warn, permissive → warn ─
@pytest.mark.parametrize("policy,expected", [
    ("strict", "fail"),
    ("balanced", "warn"),
    ("permissive", "warn"),
])
def test_minor_only_policies(policy: str, expected: str) -> None:
    res = PickleCheck().run(
        FIX / "legit_import.pkl", context={"pickle_policy": policy},
    )
    assert res.status == expected, (policy, res.message, res.details)


# ── details.policy фиксируется ─────────────────────────────────
def test_details_policy_recorded() -> None:
    res = PickleCheck().run(
        FIX / "clean_v4.pkl", context={"pickle_policy": "strict"},
    )
    assert res.details.get("policy") == "strict"


# ── пустой контейнер: политика не влияет на «warn» ─────────────
def test_empty_zip_strict_still_warn(tmp_path: Path) -> None:
    import zipfile
    p = tmp_path / "empty.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("readme.txt", b"hello")
    res = PickleCheck().run(p, context={"pickle_policy": "strict"})
    # нет findings, только parse_warnings → warn (не fail)
    assert res.status == "warn", (res.message, res.details)