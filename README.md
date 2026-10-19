Аудит локальных LLM: проверка целостности, формата и безопасности файлов моделей.

## Что это

`audit-llm` — CLI-инструмент для проверки локальных LLM-моделей на:

- **Целостность** — не изменился ли файл с момента последней проверки (SHA-256 + HMAC-подписанный эталон)
- **Формат** — валиден ли заголовок (GGUF, safetensors) + метаданные модели
- **Безопасность** — нет ли опасного pickle-кода (для `.pt`/`.pth`/`.bin`)

## Возможности

- SHA-256 хеширование с эталоном, подписанным HMAC
- Проверка заголовков GGUF (architecture, context_length, quantization, license) и safetensors
- Статический анализ pickle без выполнения (blocklist опасных модулей, REDUCE, STACK_GLOBAL)
- Карантин подозрительных файлов с метаданными
- Прогресс-бар с elapsed-временем и скоростью
- Per-file duration: сколько времени ушло на каждую модель
- JSON-вывод для CI/CD
- Коды возврата для автоматизации
- **Инкрементальный аудит**: `--new-only` — только новые файлы
- **Promote**: добавить проверенные файлы в эталон без пересканирования
- **Report**: последний audit из лога / детали конкретного файла из state
- **Reset**: сброс эталона, state и лога с бэкапом
- **Trust**: проверка репутации HF-репозитория
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

Создать `.env` в корне проекта:

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

**Приоритеты:** CLI-флаги > `config.toml` > дефолты (внутри проекта).

## Быстрый старт

```bash
# 1. Положить модели в models/
cp model.gguf models/

# 2. Создать эталон (HMAC-подписанный)
auditllm init

# 3. Проверить
auditllm audit

# 4. Посмотреть реестр
auditllm list

# 5. Инкрементальный аудит (только новые)
auditllm audit --new-only
auditllm promote   # добавить проверенные в эталон
```

## CLI

### `init` — создать эталон

```bash
auditllm init
auditllm init --models-dir /mnt/data/models --data-dir /var/lib/audit-llm
```

### `audit` — проверить модели

```bash
auditllm audit                              # полная проверка
auditllm audit --new-only                    # только новые файлы
auditllm audit --new-only --update-etalon    # проверить + добавить в эталон
auditllm audit --check hash --check header  # только конкретные проверки
auditllm audit --no-quarantine               # не перемещать в карантин
auditllm audit --no-progress                 # без прогресс-бара
```

**Коды возврата:** `0` — чисто, `1` — added/removed, `2` — modified/fail проверок.

### `list` — реестр проверенных моделей

```bash
auditllm list
auditllm list --json
```

Показывает: имя, размер, наличие на диске, в эталоне ли, статусы проверок, **Time** (сколько ушло на файл), дата последней проверки.

### `inbox` — что лежит в папке сейчас

```bash
auditllm inbox
auditllm inbox --new-only    # только непроверенные
auditllm inbox --json
```

Показывает: имя, размер, статус в реестре, в эталоне ли. Внизу — подсказки, что делать дальше.

### `inspect` — просмотр без сохранения

```bash
auditllm inspect model.gguf              # быстрые проверки (header + pickle)
auditllm inspect model.gguf --show hash  # + hash (медленно)
auditllm inspect --all                    # все файлы в папке
auditllm inspect model.gguf --json
```

**GGUF metadata:** architecture, context_length, embedding_length, block_count, quantization, license, rope.freq_base, head_count_kv и др.

### `promote` — из state в эталон (без сканирования)

```bash
auditllm promote                       # добавить все pass/warn из state
auditllm promote model.gguf            # конкретный файл
auditllm promote model.gguf --force    # даже с fail
auditllm promote --dry-run             # показать, не менять
```

**Мгновенно** — не сканирует файлы. После `promote` → `hash = [OK]` в `list`.

### `report` — последний audit / детали файла

```bash
auditllm report                       # последний audit из лога (diff)
auditllm report model.gguf            # детали из state (мгновенно)
auditllm report model.gguf --json
```

### `reset` — сброс с бэкапом

```bash
auditllm reset              # интерактивное подтверждение (введи 'yes')
auditllm reset --yes        # без подтверждения
auditllm reset --no-backup  # без бэкапа (опасно)
```

**Сбрасывает:** эталон, state, лог. **Бэкапы** — в `data/backups/`.  
**НЕ трогает:** модели, карантин, config, `.env`.

### `trust` — репутация HF-репозитория

```bash
auditllm trust meta-llama/Llama-2-7b
auditllm trust meta-llama/Llama-2-7b --json
```

Проверяет: author (официальный?), downloads, likes, license, model card, gated.  
Возвращает trust score 0–100.

## Проверки

### `hash` — SHA-256

Сравнивает хеш файла с эталоном. Определяет `size_mismatch` / `hash_mismatch`.  
По умолчанию включён в `audit`, выключен в `inspect` (медленно — читает весь файл).

### `header` — заголовок модели

**GGUF:** magic `GGUF`, version, tensor_count, metadata_kv_count + метаданные (architecture, context_length, ...).  
**safetensors:** JSON-заголовок, tensor_count, dtype_distribution, sample_tensors.

### `pickle` — безопасность pickle

Для `.pkl`/`.pt`/`.pth`/`.bin` — статический анализ через `pickletools.genops`.  
Ищет: опасные модули (`os`, `subprocess`, `builtins`, ...), REDUCE (callable), STACK_GLOBAL (динамический импорт).  
**Всегда `warn` или `fail`** — pickle принципиально небезопасен.

## Коды возврата

| Код | Значение |
|-----|----------|
| `0` | Всё чисто |
| `1` | Есть отличия (added/removed), не критично |
| `2` | Критично (modified, fail проверок, подпись эталона) |
| `130` | Отменено пользователем (Ctrl+C) |

## Архитектура

```
audit_llm/
├── pyproject.toml
├── .env                    # AUDIT_SECRET_KEY (не в git)
├── .gitignore
├── config.toml.example
├── data/
│   ├── model_hashes.json   # подписанный эталон
│   ├── models_state.json   # результаты последнего аудита
│   ├── audit_log.jsonl     # лог с ротацией
│   └── backups/            # бэкапы после reset
├── models/                 # модели (можно переопределить)
├── quarantine/             # карантин
└── auditllm/
    ├── cli.py              # typer-команды
    ├── config.py           # Config, load_config, load_secret_key
    ├── core.py             # run_checks, cmd_*, print_report
    ├── state.py            # models_state.json
    ├── report.py           # read_last_audit (из лога)
    ├── logging_setup.py    # JSON-логи с ротацией
    ├── progress.py         # ProgressReporter (elapsed, speed)
    ├── spinner.py          # Spinner для inspect
    ├── hashing.py          # get_file_hash
    ├── integrity.py        # HMAC-подпись эталона
    ├── quarantine.py       # изоляция файлов
    ├── scanner.py          # find_model_files
    ├── utils.py            # format_size
    └── checks/
        ├── base.py         # Check, CheckResult
        ├── hash_check.py   # HashCheck
        ├── header_check.py # HeaderCheck (GGUF + safetensors)
        ├── pickle_check.py # PickleCheck
        └── __init__.py     # REGISTRY, get_checks
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
```