from datetime import datetime
import shutil
from pathlib import Path
import json


def quarantine_file(file_path: Path, reason: str, details: dict, quarantine_dir: Path) -> dict:
    if not file_path.is_file():
        raise FileNotFoundError(f'Файл отсутствует: {file_path}')

    quarantine_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_name = f'{file_path.name}.{timestamp}.quarantined'
    quarantine_path = quarantine_dir / new_name

    counter = 1
    while quarantine_path.exists():
        new_name = f'{file_path.name}.{timestamp}_{counter}.quarantined'
        quarantine_path = quarantine_dir / new_name
        counter += 1

    shutil.move(file_path, quarantine_path)

    metadata = {
        'original_path': str(file_path),
        'quarantined_path': str(quarantine_path),
        'reason': reason,
        'details': details,
        'detected_at': datetime.now().isoformat()
    }

    metadata_path = quarantine_path.with_suffix(quarantine_path.suffix + '.metadata.json')
    metadata_path.write_text(json.dumps(metadata, indent=2))

    return metadata


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        models_dir = tmp_path / "models"
        quarantine_dir = tmp_path / "quarantine"
        models_dir.mkdir()

        # 1. Создаём файл и помещаем в карантин
        test_file = models_dir / "test.gguf"
        test_file.write_text("fake model data")

        meta = quarantine_file(
            test_file,
            reason="hash_mismatch",
            details={"expected": "abc", "actual": "def"},
            quarantine_dir=quarantine_dir
        )

        assert not test_file.exists(), "Файл должен был исчезнуть"
        assert Path(meta["quarantined_path"]).exists(), "Файл должен быть в карантине"
        print(f"✅ Файл перемещён: {meta['quarantined_path']}")

        # 2. Проверяем метаданные
        metadata_path = Path(meta["quarantined_path"]).parent / (
                Path(meta["quarantined_path"]).name + ".metadata.json"
        )
        assert metadata_path.exists(), "Метаданные не найдены"
        loaded = json.loads(metadata_path.read_text())
        assert loaded["reason"] == "hash_mismatch"
        assert loaded["details"]["expected"] == "abc"
        print("✅ Метаданные корректны")

        # 3. Коллизия: тот же файл ещё раз
        test_file.write_text("fake model data 2")
        meta2 = quarantine_file(
            test_file,
            reason="hash_mismatch",
            details={},
            quarantine_dir=quarantine_dir
        )
        assert "_1" in Path(meta2["quarantined_path"]).name, "Коллизия не обработана"
        print(f"✅ Коллизия обработана: {Path(meta2['quarantined_path']).name}")

        # 4. Несуществующий файл
        try:
            quarantine_file(
                models_dir / "no_such_file.gguf",
                reason="test",
                details={},
                quarantine_dir=quarantine_dir
            )
            print("❌ Должны были упасть с FileNotFoundError")
        except FileNotFoundError:
            print("✅ FileNotFoundError пойман")



















