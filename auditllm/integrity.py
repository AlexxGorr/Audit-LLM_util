"""Подпись и проверка целостности эталона."""
from pathlib import Path
import hmac
import hashlib
import json
import os


class EtalonCorruptedError(ValueError):
    """Эталон повреждён (битый JSON, нет полей). НЕ атака."""


class EtalonSignatureError(ValueError):
    """Подпись не совпадает. Возможна атака."""


def sign_data(data: bytes, key: bytes) -> str:
    """Возвращает HMAC-SHA256 подпись для данных."""
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    return hmac_obj.hexdigest()


def save_hashes_signed(hashes: dict, path: Path, key: bytes) -> None:
    """Сохраняет хеши и подпись в JSON-файл (атомарно)."""
    data_bytes = json.dumps(hashes, sort_keys=True, ensure_ascii=False).encode('utf-8')
    signature = sign_data(data_bytes, key)
    payload = {'data': hashes, 'signature': signature}

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding='utf-8',
    )
    os.replace(tmp, path)


def load_hashes_verified(path: Path, key: bytes) -> dict:
    """Загружает хеши и проверяет подпись.

    Raises:
        FileNotFoundError: если файл не существует
        EtalonCorruptedError: если формат битый
        EtalonSignatureError: если подпись не совпадает
    """
    if not path.is_file():
        raise FileNotFoundError(f'Эталон не найден: {path}')

    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as e:
        raise EtalonCorruptedError(
            f'Эталон повреждён (невалидный JSON): {e}'
        ) from e

    if not isinstance(payload, dict) or 'data' not in payload or 'signature' not in payload:
        raise EtalonCorruptedError(
            'Эталон повреждён: отсутствует поле data или signature'
        )

    data = payload['data']
    save_sign = payload['signature']

    data_bytes = json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')
    expected_sign = sign_data(data_bytes, key)

    if not hmac.compare_digest(expected_sign, save_sign):
        raise EtalonSignatureError(
            'Подпись не совпадает! Эталон подменён.\n'
            'Если эталон создан старой версией auditllm — пересоздай:\n'
            '  auditllm reset && auditllm init'
        )

    return data


def load_hashes_unverified(path: Path) -> dict:
    """Загружает эталон БЕЗ проверки подписи."""
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
        return payload.get('data', {})
    except (json.JSONDecodeError, OSError):
        return {}