import json
from pathlib import Path
from datetime import datetime


def build_state(results: dict, models_dir: Path) -> dict:
    timestamp = datetime.now().isoformat()
    state = {}
    for path, check_res in results.items():
        # Размер файла — из hash-проверки (если есть)
        size = None
        hash_res = check_res.get('hash')
        if hash_res:
            details = hash_res.details
            if 'size' in details:
                size = details['size']
            elif 'actual' in details:
                size = details['actual'].get('size')

        state[path] = {
            'size': size,
            'last_audit': timestamp,
            'checks': {
                name: {
                    'status': res.status,
                    'message': res.message,
                    'duration_ms': res.duration_ms,
                    'details': res.details,
                }
                for name, res in check_res.items()
            }
        }
    return state


def load_state(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        content = path.read_text(encoding='utf-8')
        return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(state, indent=2, ensure_ascii=False),
        encoding='utf-8',
    )














