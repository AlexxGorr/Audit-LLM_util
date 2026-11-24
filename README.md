Аудит локальных LLM: проверка целостности, формата и безопасности файлов моделей.

## Что это

`audit-llm` — CLI-инструмент для проверки локальных LLM-моделей на:

- **Целостность** — не изменился ли файл с момента последней проверки (SHA-256 + HMAC-подписанный эталон)
- **Формат** — валиден ли заголовок (GGUF, safetensors) + метаданные модели
- **Безопасность** — нет ли опасного pickle-кода (для `.pt`/`.pth`/`.bin`)

## Возможности

- SHA-256 хеширование с эталоном, подписанным HMAC
- Проверка заголовков GGUF (architecture, context_length, quantization, license) и safetensors
- **Magic bytes detection** (`MagicCheck`) — быстрая классификация формата (GGUF, HDF5, TFLite, GGML, ZIP, pickle) до `hash`
- Статический анализ pickle без выполнения (blocklist опасных модулей, REDUCE, STACK_GLOBAL, BUILD-after-REDUCE)
- **Расширенный blocklist** (`pty`, `distutils`, `marshal`, `torch.utils.bottleneck.__main__`, `__builtin__`)
- **GLOBAL/STACK_GLOBAL** — проверка полного `module.attr` + префиксов (CVE-2025-71366)
- Карантин подозрительных файлов с метаданными
- **Прогресс-бар с ETA**, общим прогрессом по всем файлам, скоростью текущей проверки
- **Per-check строки** (`✓ hash pass 125 ms`) + **per-file duration**
- **Автодополнение** команд и путей в shell, история (`~/.auditllm_history`), горячие клавиши (`Ctrl+C/D/L/R`)
- JSON-вывод для CI/CD
- Коды возврата для автоматизации
- **Инкрементальный аудит**: `--new-only` — только новые файлы
- **Promote**: добавить проверенные файлы в эталон без пересканирования
- **Report**: последний audit из лога / детали конкретного файла из state
- **Reset**: сброс эталона, state и лога с бэкапом
- **Trust**: проверка репутации HF-репозитория + **security status** (safe/unsafe/unknown)
- **Эталон update**: `etalon update` — синхронизация эталона с диском (удаление отсутствующих) без пересчёта хешей
- **State cleanup**: `etalon update` чистит `state.json` от «мёртвых» записей (опционально `--keep-state`)
- **Сканер**: `min_size`, `include_ext`/`exclude_ext`, `exclude_patterns` (`.git`, `__pycache__`, `*.tmp`)
- Расширяемая архитектура через абстракцию `Check` (`SUPPORTED`, `depends_on`, `cancel_check`)

## Установка

```bash
git clone <repo> ~/audit_llm
cd ~/audit_llm

python -m venv venv
source venv/bin/activate

pip install -e ".[dev]"
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

[scanner]
min_size = 1048576          # 1 МБ — отсекать мелкие файлы
include_ext = [".gguf", ".safetensors"]
exclude_ext = [".tmp"]
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
auditllm init --min-size 0    # все файлы (включая мелкие)
```

### `audit` — проверить модели

```bash
auditllm audit                              # полная проверка
auditllm audit model.gguf                    # один файл
auditllm audit --new-only                    # только новые файлы
auditllm audit --new-only --update-etalon    # проверить + добавить в эталон
auditllm audit --new-only --update-etalon --allow-partial-update  # + удалить absent
auditllm audit --check hash --check header  # только конкретные проверки
auditllm audit --no-quarantine               # не перемещать в карантин
auditllm audit --no-progress                 # без прогресс-бара
auditllm audit --min-size 0                  # все файлы
auditllm audit --include-ext .gguf           # только .gguf
auditllm audit --exclude-ext .tmp            # исключить .tmp
```

**Коды возврата:** `0` — чисто, `1` — added/removed, `2` — modified/fail проверок.

### `list` — реестр проверенных моделей

```bash
auditllm list
auditllm list --all          # включая «мёртвые» (нет на диске / нет в эталоне)
auditllm list --json
```

Показывает: имя, размер, наличие на диске, в эталоне ли, статусы проверок, **Time**, дата последней проверки.  
**Сортировка:** здоровые → не в эталоне → мёртвые.

### `inbox` — что лежит в папке сейчас

```bash
auditllm inbox
auditllm inbox --new-only    # только непроверенные
auditllm inbox --json
```

Показывает: имя, размер, статус в реестре, в эталоне ли. **Сортировка:** verified → modified → new.

### `inspect` — ручной анализ (без сохранения)

```bash
auditllm inspect model.gguf              # быстрые проверки (magic + header + pickle)
auditllm inspect model.gguf --show hash  # + hash (медленно)
auditllm inspect --all                    # все файлы в папке
auditllm inspect model.gguf --search "llama"     # поиск по metadata/opcodes
auditllm inspect model.gguf --json
```

**Ручной анализ:** `--search PATTERN` — поиск по `header.metadata` и `pickle.disassembly`.  
**GGUF metadata:** architecture, context_length, embedding_length, block_count, quantization, license, rope.freq_base, head_count_kv и др.

### `promote` — из state в эталон (без сканирования)

```bash
auditllm promote                       # добавить все pass/warn из state
auditllm promote model.gguf            # конкретный файл
auditllm promote model.gguf --force    # даже с fail
auditllm promote --dry-run             # показать, не менять
```

**Мгновенно** — не сканирует файлы. После `promote` → `hash = [OK]` в `list`.

### `etalon update` — синхронизация эталона с диском

```bash
auditllm etalon update --dry-run       # показать, что будет удалено
auditllm etalon update                 # интерактивно (введи 'yes')
auditllm etalon update --yes           # без подтверждения (CI)
auditllm etalon update --yes --keep-state  # не чистить state
```

**Удаляет** из эталона записи, которых нет на диске. **Не добавляет** новые (для этого `audit --update-etalon`).  
**Чистит** `state.json` от «мёртвых» (если не `--keep-state`).

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

Проверяет: author (официальный?), downloads, likes, license, model card, gated, **security status** (safe/unsafe/unknown).  
Возвращает trust score 0–100.

### `shell` — интерактивная оболочка (REPL)

```bash
auditllm shell
```

Команды: `init`, `audit [<file>]`, `list`, `inbox`, `inspect`, `promote`, `etalon update`, `report`, `trust`, `reset`, `config`, `help`, `exit`.  
**Автодополнение** команд и путей, история (`~/.auditllm_history`), горячие клавиши: `Ctrl+C` (прервать), `Ctrl+D` (выход), `Ctrl+L` (очистить), `Ctrl+R` (поиск), `Tab` (дополнение).

## Проверки

### `hash` — SHA-256

Сравнивает хеш файла с эталоном. Определяет `size_mismatch` / `hash_mismatch`.  
По умолчанию включён в `audit`, выключен в `inspect` (медленно — читает весь файл).

### `magic` — magic bytes

Быстрая классификация формата: GGUF, HDF5, TFLite, GGML, ZIP, pickle.  
`pass` — распознан, `warn` — неизвестные magic bytes.

### `header` — заголовок модели

**GGUF:** magic `GGUF`, version, tensor_count, metadata_kv_count + метаданные (architecture, context_length, ...).  
**safetensors:** JSON-заголовок, tensor_count, dtype_distribution, sample_tensors.

### `pickle` — безопасность pickle

Для `.pkl`/`.pt`/`.pth`/`.bin`/`.ckpt`/`.joblib`/`.dill` — статический анализ через `pickletools.genops`.  
Ищет: опасные модули (`os`, `subprocess`, `builtins`, `pty`, `distutils`, `marshal`, `torch.utils.bottleneck.__main__`, ...), REDUCE (callable), STACK_GLOBAL (динамический импорт), **BUILD после REDUCE** (bypass).  
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
    ├── shell.py            # REPL (prompt_toolkit)
    ├── config.py           # Config, load_config, load_secret_key
    ├── core.py             # run_checks, cmd_*, print_report
    ├── state.py            # models_state.json
    ├── report.py           # read_last_audit (из лога)
    ├── logging_setup.py    # JSON-логи с ротацией
    ├── progress.py         # ProgressReporter (ETA, overall, per-check)
    ├── spinner.py          # Spinner для inspect/trust
    ├── hashing.py          # get_file_hash
    ├── integrity.py        # HMAC-подпись эталона
    ├── quarantine.py       # изоляция файлов
    ├── scanner.py          # find_model_files (min_size, ext, patterns)
    ├── utils.py            # format_size
    └── checks/
        ├── base.py         # Check, CheckResult (SUPPORTED, depends_on)
        ├── hash_check.py   # HashCheck
        ├── magic_check.py  # MagicCheck (GGUF, HDF5, TFLite, GGML, ZIP)
        ├── header_check.py # HeaderCheck (GGUF + safetensors)
        ├── pickle_check.py # PickleCheck
        └── __init__.py     # REGISTRY, get_checks, register_check
```

## Как добавить новую проверку

1. Создать `auditllm/checks/my_check.py`:

```python
from auditllm.checks.base import Check, CheckResult

class MyCheck(Check):
    name = "my_check"
    description = "My custom check"
    SUPPORTED = {".myformat"}  # опционально

    def supports(self, file_path):
        return file_path.suffix.lower() in self.SUPPORTED

    def run(self, file_path, context=None, progress=None, cancel_check=None):
        return CheckResult(status="pass", message="OK")
```

2. Зарегистрировать в `checks/__init__.py`:

```python
from auditllm.checks.my_check import MyCheck

REGISTRY = {
    "hash": HashCheck,
    "magic": MagicCheck,
    "header": HeaderCheck,
    "pickle": PickleCheck,
    "my_check": MyCheck,
}
```

3. Готово. `audit` подхватит автоматически, `list` покажет новую колонку, `--check my_check` заработает.

**Или** — динамически: `register_check("my_check", MyCheck)`.

## Лицензия

MIT
```