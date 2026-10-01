# auditllm/checks/__init__.py
from auditllm.checks.base import Check, CheckResult
from auditllm.checks.hash_check import HashCheck
from auditllm.checks.header_check import HeaderCheck
from auditllm.checks.pickle_check import PickleCheck

# Реестр: имя → класс
REGISTRY: dict[str, type[Check]] = {
    "hash": HashCheck,
    "header": HeaderCheck,
    "pickle": PickleCheck,
}


def get_all_checks() -> list[Check]:
    """Возвращает экземпляры всех зарегистрированных проверок."""
    return [cls() for cls in REGISTRY.values()]


def get_check(name: str) -> Check:
    """Возвращает экземпляр проверки по имени. Бросает ValueError, если нет."""
    if name not in REGISTRY:
        available = ", ".join(REGISTRY.keys())
        raise ValueError(f"Unknown check: {name!r}. Available: {available}")
    return REGISTRY[name]()


def get_checks(names: list[str] | None = None) -> list[Check]:
    """Возвращает проверки по списку имён.

    Args:
        names: список имён. None или пусто → все зарегистрированные.

    Returns:
        Список экземпляров Check.

    Raises:
        ValueError: если какое-то имя не найдено.
    """
    if not names:
        return get_all_checks()
    return [get_check(n) for n in names]


__all__ = [
    "Check",
    "CheckResult",
    "HashCheck",
    "REGISTRY",
    "get_all_checks",
    "get_check",
    "get_checks",
    "HeaderCheck",
    'PickleCheck',
]




