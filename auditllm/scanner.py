from pathlib import Path


MODEL_EXTENSIONS = {".bin", ".gguf", ".safetensors", ".pt", ".pth"}

def find_model_files(directory: Path) -> list[Path]:
    """
    Рекурсивно находит все файлы моделей в директории.
    """
    models_lst = sorted([f for f in directory.rglob('*') if f.is_file() and
                  f.suffix.lower() in MODEL_EXTENSIONS])

    return models_lst


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Создаём структуру
        (root / "llama-3-8b").mkdir()
        (root / "mistral-7b").mkdir()

        (root / "llama-3-8b" / "model.safetensors").touch()
        (root / "llama-3-8b" / "config.json").touch()  # не модель
        (root / "mistral-7b" / "model.Q4_K_M.gguf").touch()
        (root / "mistral-7b" / "MODEL_UPPER.BIN").touch()  # проверяем регистр
        (root / "readme.txt").touch()  # не модель

        found = find_model_files(root)

        print(f"Найдено файлов: {len(found)}")
        for f in found:
            print(f"  {f.relative_to(root)}")

        # Проверки
        assert len(found) == 3, f"Ожидали 3 файла, получили {len(found)}"
        assert all(f.suffix.lower() in MODEL_EXTENSIONS for f in found)
        assert found == sorted(found), "Список не отсортирован!"

        print("✅ Все проверки пройдены")



