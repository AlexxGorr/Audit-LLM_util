"""Реконструкция последнего отчёта аудита из лога."""
import json
from pathlib import Path


def read_last_audit(log_path: Path) -> dict | None:
    """Читает audit_log.jsonl, находит последний audit-цикл.

    Returns:
        {
            "started_at": str,
            "finished_at": str | None,
            "scan_started": {...},
            "scan_finished": {...},
            "events_count": int,
            "summary": {
                "check_failures": [...],
                "modified": [...],
                "added": [...],
                "removed": [...],
                "quarantined": [...],
            },
        }
        или None, если audit не найден.
    """
    if not log_path.is_file():
        return None

    events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not events:
        return None

    # Ищем последний scan_started с конца
    start_idx = None
    for i in range(len(events) - 1, -1, -1):
        if events[i].get("event") == "scan_started":
            start_idx = i
            break

    if start_idx is None:
        return None

    # Собираем события от start_idx до scan_finished
    cycle = []
    finished_at = None
    for i in range(start_idx, len(events)):
        ev = events[i]
        cycle.append(ev)
        if ev.get("event") == "scan_finished":
            finished_at = ev.get("ts")
            break

    # Собираем summary
    failures = []
    modified = []
    added = []
    removed = []
    quarantined = []

    for ev in cycle:
        event = ev.get("event")
        if event == "check_failed":
            failures.append({
                "path": ev.get("path", "?"),
                "check": ev.get("check", "?"),
                "message": ev.get("message", ""),
            })
        elif event == "modified_detected":
            modified.append({
                "path": ev.get("path", "?"),
                "reason": ev.get("reason", "?"),
            })
        elif event == "file_added":
            added.append(ev.get("path", "?"))
        elif event == "file_removed":
            removed.append(ev.get("path", "?"))
        elif event == "quarantined":
            quarantined.append(ev.get("path", "?"))

    return {
        "started_at": cycle[0].get("ts", ""),
        "finished_at": finished_at,
        "scan_started": next(
            (e for e in cycle if e.get("event") == "scan_started"), {}
        ),
        "scan_finished": next(
            (e for e in cycle if e.get("event") == "scan_finished"), None
        ),
        "events_count": len(cycle),
        "summary": {
            "check_failures": failures,
            "modified": modified,
            "added": added,
            "removed": removed,
            "quarantined": quarantined,
        },
    }























