from auditllm.checks.base import Check, CheckResult
from auditllm.checks.hash_check import HashCheck
from auditllm.checks.header_check import HeaderCheck
from auditllm.checks.pickle_check import PickleCheck
from auditllm.checks.magic_check import MagicCheck



# Реестр: имя → класс
REGISTRY: dict[str, type[Check]] = {
    "hash": HashCheck,
    "magic": MagicCheck,
    "header": HeaderCheck,
    "pickle": PickleCheck,
}


def register_check(name: str, cls: type[Check]) -> None:
    """Регистрирует новую проверку.

    Args:
        name: имя проверки (должно совпадать с cls.name)
        cls: класс проверки (наследник Check)

    Raises:
        ValueError: если имя уже занято
    """
    if name in REGISTRY:
        raise ValueError(f"Check '{name}' already registered")
    REGISTRY[name] = cls


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



def all_supported_extensions() -> set[str]:
    """Объединение SUPPORTED всех зарегистрированных проверок.

    Используется в scanner.py для поиска файлов моделей.
    Проверки без атрибута SUPPORTED (например, hash) игнорируются.
    """
    extensions: set[str] = set()
    for check_cls in REGISTRY.values():
        supported = getattr(check_cls, "SUPPORTED", None)
        if supported:
            extensions.update(supported)
    return extensions


__all__ = [
    "Check",
    "CheckResult",
    "HashCheck",
    "MagicCheck",
    "HeaderCheck",
    "PickleCheck",
    "REGISTRY",
    "get_all_checks",
    "get_check",
    "get_checks",
    "all_supported_extensions",
    "register_check",  # d3
]




