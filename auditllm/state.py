"""Работа с models_state.json — результатами последнего аудита."""
import json
from datetime import datetime
from pathlib import Path


def build_state(results: dict, models_dir: Path) -> dict:
    """Собирает models_state.json из результатов run_checks.

    Args:
        results: {path: {check_name: CheckResult}}
        models_dir: папка с моделями (для size)

    Returns:
        {path: {size, last_audit, file_duration_ms, checks: {...}}}
    """
    timestamp = datetime.now().isoformat()
    state = {}

    for path, check_res in results.items():
        # size — всегда из st_size (файл ещё на диске во время build_state)
        file_path = models_dir / path
        try:
            size = file_path.stat().st_size
        except OSError:
            size = None

        # fallback: если файл уже удалён/перемещён — берём из hash-проверки
        if size is None:
            hash_res = check_res.get('hash')
            if hash_res:
                details = hash_res.details
                if 'size' in details:
                    size = details['size']
                elif 'actual' in details:
                    size = details['actual'].get('size')

        # Общее время файла = сумма duration_ms всех проверок
        file_duration_ms = sum(
            res.duration_ms
            for res in check_res.values()
            if hasattr(res, "duration_ms")
        )

        checks_out = {}
        for name, res in check_res.items():
            details = res.details
            # c7: для pickle — только summary, без disassembly
            if name == "pickle":
                summary = {
                    "dangerous_count": len(details.get("dangerous", [])),
                    "warnings_count": len(details.get("warnings", [])),
                    "reduce_count": details.get("reduce_count", 0),
                    "inner_files": details.get("inner_files", [])[:10],
                }
                if "note" in details:
                    summary["note"] = details["note"]
                details = summary
            checks_out[name] = {
                'status': res.status,
                'message': res.message,
                'duration_ms': res.duration_ms,
                'details': details,
            }

        state[path] = {
            'size': size,
            'last_audit': timestamp,
            'file_duration_ms': file_duration_ms,
            'checks': checks_out,
        }

    return state


def load_state(path: Path) -> dict:
    """Загружает models_state.json. Возвращает {} если файла нет или битый."""
    if not path.is_file():
        return {}
    try:
        content = path.read_text(encoding='utf-8')
        return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state: dict, path: Path) -> None:
    """Сохраняет models_state.json."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(state, indent=2, ensure_ascii=False),
        encoding='utf-8',
    )





