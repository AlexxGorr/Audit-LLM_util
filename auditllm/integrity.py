from pathlib import Path
import hmac
import hashlib
import json


def sign_data(data: bytes, key: bytes) -> str:
    """Возвращает HMAC-SHA256 подпись для данных."""
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    return hmac_obj.hexdigest()


def save_hashes_signed(hashes: dict, path: Path, key: bytes) -> None:
    """Сохраняет хеши и подпись в JSON-файл."""
    data_bytes = json.dumps(hashes, sort_keys=True).encode('utf-8')
    signature = sign_data(data_bytes, key)
    payload = {'data': hashes, 'signature': signature}
    file_path = Path(path)
    file_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))


def load_hashes_verified(path: Path, key: bytes) -> dict:
    """
    Загружает хеши и проверяет подпись.

    Raises:
        ValueError: если подпись не совпадает
        FileNotFoundError: если файл не существует
    """
    if not path.is_file():
        raise FileNotFoundError(f'Эталон не найден: {path}')

    payload = json.loads(path.read_text(encoding='utf-8'))
    data = payload['data']
    save_sign = payload['signature']

    data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
    expected_sign = sign_data(data_bytes, key)

    if not hmac.compare_digest(expected_sign, save_sign):
        raise ValueError('Подпись не совпадает! Эталон подменён!')

    return data

def load_hashes_unverified(path: Path):
    """
    Загружает эталон БЕЗ проверки подписи.

    Использовать только для некритичных операций (list).
    Для аудита — load_hashes_verified.
    """
    if not path.is_file():
        raise FileNotFoundError(f'Эталон не найден: {path}')

    payload = json.loads(path.read_text(encoding='utf-8'))
    return payload['data']


if __name__ == "__main__":
    import tempfile

    KEY1 = b"correct-key"
    KEY2 = b"wrong-key"

    hashes = {
        "models/test.gguf": {"hash": "abc123", "size": 100}
    }

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "model_hashes.json"

        # 1. Сохраняем
        save_hashes_signed(hashes, path, KEY1)
        print("✅ Сохранено")

        # 2. Загружаем правильным ключом
        loaded = load_hashes_verified(path, KEY1)
        assert loaded == hashes, "Данные не совпали!"
        print("✅ Загрузка с правильным ключом")

        # 3. Загружаем неправильным ключом
        try:
            load_hashes_verified(path, KEY2)
            print("❌ Должны были упасть с ValueError")
        except ValueError:
            print("✅ Неправильный ключ отвергнут")

        # 4. Подменяем данные в файле
        content = json.loads(path.read_text())
        content["data"]["models/test.gguf"]["hash"] = "HACKED"
        path.write_text(json.dumps(content, indent=2))

        try:
            load_hashes_verified(path, KEY1)
            print("❌ Должны были упасть с ValueError (подмена)")
        except ValueError:
            print("✅ Подмена обнаружена")







