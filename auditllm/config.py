"""Загрузка конфигурации: секреты, пути, настройки.

Приоритеты: CLI-флаги > config.toml > дефолты внутри проекта.
"""
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ─── Дефолты ────────────────────────────────────────────
DEFAULT_MODELS_DIR = PROJECT_ROOT / "models"
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_QUARANTINE_DIR = PROJECT_ROOT / "quarantine"


@dataclass
class Config:
    """Разрешённая конфигурация приложения."""
    models_dir: Path
    quarantine_dir: Path
    data_dir: Path
    etalon_path: Path
    log_path: Path
    state_path: Path
    include_ext: set[str] = field(default_factory=set)
    exclude_ext: set[str] = field(default_factory=set)
    min_size: int = 1 * 1024 * 1024


def load_config(
    config_path: Path | None = None,
    models_dir: Path | None = None,
    data_dir: Path | None = None,
    quarantine_dir: Path | None = None,
) -> Config:
    """Загружает конфигурацию с приоритетами: CLI > TOML > defaults.

    Args:
        config_path: путь к config.toml (если None — не читаем TOML)
        models_dir: CLI-override для папки моделей
        data_dir: CLI-override для папки данных
        quarantine_dir: CLI-override для папки карантина

    Returns:
        Config с разрешёнными путями.
    """
    if config_path and config_path.is_file():
        with open(config_path, "rb") as f:
            toml_data = tomllib.load(f)
        paths = toml_data.get("paths", {})
        scanner = toml_data.get("scanner", {})  # H5
    else:
        paths = {}
        scanner = {}

    # Для каждого пути: CLI > TOML > default
    resolved_models = models_dir or (
        Path(paths["models_dir"]) if "models_dir" in paths else DEFAULT_MODELS_DIR
    )
    resolved_data = data_dir or (
        Path(paths['data_dir']) if 'data_dir' in paths else DEFAULT_DATA_DIR)
    resolved_quarantine = quarantine_dir or (
        Path(paths['quarantine_dir']) if 'quarantine_dir' in paths else DEFAULT_QUARANTINE_DIR
    )
    etalon_path = resolved_data / "model_hashes.json"
    log_path = resolved_data / "audit_log.jsonl"
    state_path = resolved_data / "models_state.json"

    return Config(
        models_dir=resolved_models,
        quarantine_dir=resolved_quarantine,
        data_dir=resolved_data,
        etalon_path=etalon_path,
        log_path=log_path,
        state_path=state_path,
        include_ext=set(scanner.get("include_ext", [])),
        exclude_ext=set(scanner.get("exclude_ext", [])),
        min_size=int(scanner.get("min_size", 1 * 1024 * 1024)),
    )


def load_secret_key() -> bytes:
    """Загружает AUDIT_SECRET_KEY из .env.

    Returns:
        Ключ в виде байтов.

    Raises:
        ValueError: если ключ не найден или слишком короткий.
    """
    load_dotenv()
    key_str = os.environ.get("AUDIT_SECRET_KEY")
    if not key_str:
        raise ValueError(
            "AUDIT_SECRET_KEY не найден.\n"
            "Создай .env с строкой AUDIT_SECRET_KEY=твой_ключ"
        )
    if len(key_str) < 32:
        raise ValueError("Ключ слишком короткий, нужно минимум 32 символа")
    return key_str.encode("utf-8")


if __name__ == '__main__':
    # Тест 1: дефолты
    from auditllm.config import load_config

    cfg = load_config()
    print(cfg)
    # Ожидаемо: models_dir=.../models, data_dir=.../data, etalon_path=.../data/model_hashes.json

    # Тест 2: CLI-override
    cfg = load_config(models_dir=Path("/tmp/custom_models"))
    print(cfg.models_dir)
    # Ожидаемо: /tmp/custom_models

    # Тест 3: TOML
    # Создай config.toml с [paths] models_dir = "/mnt/data/models"
    cfg = load_config(config_path=Path("config.toml"))
    print(cfg.models_dir)
    # Ожидаемо: /mnt/data/models

    # Тест 4: приоритет CLI над TOML
    cfg = load_config(config_path=Path("config.toml"), models_dir=Path("/tmp/override"))
    print(cfg.models_dir)
    # Ожидаемо: /tmp/override






