Аудит локальных LLM: проверка целостности и безопасности файлов моделей.

## Что это

`audit-llm` — CLI-инструмент для проверки локальных LLM-моделей на:

- **Целостность** — не изменился ли файл с момента последней проверки
- **Формат** — валиден ли заголовок (GGUF, safetensors)
- **Безопасность** — нет ли опасного pickle-кода (для `.pt`/`.pth`/`.bin`)

## Возможности

- SHA-256 хеширование с эталоном, подписанным HMAC
- Проверка заголовков GGUF и safetensors (magic bytes, метаданные)
- Статический анализ pickle без выполнения (blocklist опасных модулей)
- Карантин подозрительных файлов с метаданными
- Прогресс-бар, JSON-вывод, коды возврата для CI/CD
- Расширяемая архитектура через абстракцию `Check`

## Установка

```bash
git clone <repo> ~/audit_llm
cd ~/audit_llm

python -m venv venv
source venv/bin/activate

pip install -e .
```

## Настройка

Создать `.env` в корне:

```
AUDIT_SECRET_KEY=your-super-secret-key-at-least-32-chars
```

Опционально — `config.toml`:

```toml
[paths]
models_dir = "/mnt/data/models"
data_dir = "/var/lib/audit-llm"
quarantine_dir = "/var/lib/audit-llm/quarantine"
```

## Использование

```bash
# Первый запуск — создать эталон
auditllm init

# Аудит
auditllm audit

# Список моделей
auditllm list

# Только конкретные проверки
auditllm audit --check hash --check header
```

## CLI

| Команда | Описание |
|---------|----------|
| `auditllm init` | Создать эталон (хеши всех моделей) |
| `auditllm audit` | Проверить модели против эталона |
| `auditllm list` | Показать статус моделей |
| `auditllm report` | (TODO) Последний отчёт |
| `auditllm shell` | (TODO) Интерактивная оболочка |

**Общие флаги:**

- `--config PATH` — путь к config.toml
- `--models-dir PATH` — переопределить папку моделей
- `--data-dir PATH` — переопределить папку данных
- `--quarantine-dir PATH` — переопределить карантин
- `-v, --verbose` — подробный вывод
- `--no-progress` — отключить прогресс-бар

**Флаги `audit`:**

- `--update-etalon` — обновить эталон (added/removed, не modified)
- `--no-quarantine` — не перемещать подозрительные файлы
- `--check NAME` — выбрать проверки

## Коды возврата

| Код | Значение |
|-----|----------|
| 0 | Всё чисто |
| 1 | Есть отличия (added/removed), но не критично |
| 2 | Критичные проблемы (modified, fail проверок) |
| 130 | Отменено пользователем (Ctrl+C) |

## Проверки

### `hash` — SHA-256

Считает хеш файла, сравнивает с эталоном. Определяет `size_mismatch` / `hash_mismatch`.

### `header` — заголовок

Для `.gguf` — magic bytes `GGUF`, версия, tensor_count, metadata_kv_count.
Для `.safetensors` — JSON-заголовок, список тензоров.

### `pickle` — безопасность pickle

Для `.pkl`/`.pt`/`.pth`/`.bin` — статический анализ через `pickletools.genops`.
Ищет опасные импорты (`os`, `subprocess`, `builtins`, ...) через blocklist.
**Всегда возвращает `warn` или `fail`, никогда `pass`** — pickle принципиально небезопасен.

## Архитектура

```
audit_llm/
├── auditllm/
│   ├── cli.py              # typer-команды
│   ├── config.py           # Config, load_config, load_secret_key
│   ├── core.py             # run_checks, cmd_*, print_report
│   ├── state.py            # models_state.json
│   ├── logging_setup.py    # JSON-логи с ротацией
│   ├── progress.py         # ProgressReporter
│   ├── hashing.py          # get_file_hash
│   ├── integrity.py        # HMAC-подпись эталона
│   ├── quarantine.py       # изоляция файлов
│   ├── scanner.py          # find_model_files
│   ├── utils.py            # format_size
│   └── checks/
│       ├── base.py         # Check, CheckResult
│       ├── hash_check.py   # HashCheck
│       ├── header_check.py # HeaderCheck
│       ├── pickle_check.py # PickleCheck
│       └── __init__.py     # REGISTRY
├── pyproject.toml
├── .env                    # AUDIT_SECRET_KEY (не в git)
├── .gitignore
├── data/                   # эталон, логи, state
├── models/                 # модели (можно переопределить)
└── quarantine/             # карантин
```

## Как добавить новую проверку

1. Создать `auditllm/checks/my_check.py`:

```python
from auditllm.checks.base import Check, CheckResult

class MyCheck(Check):
    name = "my_check"
    description = "My custom check"

    def supports(self, file_path):
        return file_path.suffix.lower() == ".myformat"

    def run(self, file_path, context=None, progress=None):
        return CheckResult(status="pass", message="OK")
```

2. Зарегистрировать в `checks/__init__.py`:

```python
from auditllm.checks.my_check import MyCheck

REGISTRY = {
    "hash": HashCheck,
    "header": HeaderCheck,
    "pickle": PickleCheck,
    "my_check": MyCheck,
}
```

3. Готово. `audit` подхватит автоматически, `list` покажет новую колонку, `--check my_check` заработает.

## Лицензия

MIT
