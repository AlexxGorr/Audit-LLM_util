"""Бизнес-логика аудита: сканирование, сравнение, отчёты.

Не знает ничего о CLI — принимает простые аргументы, возвращает данные.
"""
import logging
from pathlib import Path
from datetime import datetime
import sys
import shutil

from auditllm.spinner import Spinner
from auditllm.checks.hash_check import HashCheck
from auditllm.integrity import (load_hashes_verified,
                                save_hashes_signed,
                                load_hashes_unverified,
                                EtalonCorruptedError,
                                EtalonSignatureError)
from auditllm.quarantine import quarantine_file
from auditllm.scanner import find_model_files
from auditllm.config import Config
from auditllm.utils import format_size
from auditllm.progress import ProgressReporter
from auditllm.checks.base import CheckResult
from auditllm.state import save_state, build_state
from auditllm.state import load_state
from auditllm.checks import get_checks, get_all_checks

from rich.console import Console
from rich.table import Table
from rich import box
import json


# ─── Сравнение ──────────────────────────────────────────
def compare_states(old: dict, new: dict) -> dict:
    """Сравнивает эталон и текущее состояние."""
    result = {
        'unchanged': [],
        'modified': [],
        'added': [],
        'removed': [],
    }
    old_keys = set(old.keys())
    new_keys = set(new.keys())

    for path in (old_keys & new_keys):
        old_entry = old[path]
        new_entry = new[path]

        if old_entry == new_entry:
            result['unchanged'].append(path)
        else:
            if old_entry['size'] != new_entry['size']:
                reason = 'size_mismatch'
            else:
                reason = 'hash_mismatch'

            result['modified'].append({
                'path': path,
                'reason': reason,
                'expected': old_entry,
                'actual': new_entry,
            })

    for path in (new_keys - old_keys):
        result['added'].append(path)

    for path in (old_keys - new_keys):
        result['removed'].append(path)

    return result


# ─── Отчёт ──────────────────────────────────────────────
def print_report(diff: dict, results: dict) -> None:
    """Печатает отчёт: целостность + проверки безопасности."""
    line = "=" * 55
    print(line)
    print("ОТЧЁТ АУДИТА".center(55))
    print(line)
    print()

    unchanged = len(diff["unchanged"])
    modified = len(diff["modified"])
    added = len(diff["added"])
    removed = len(diff["removed"])
    total = unchanged + modified + added + removed

    print("📊 ЦЕЛОСТНОСТЬ:")
    print(f"  Проверено файлов: {total}")
    print(f"    Не изменены: {unchanged}")
    print(f"    Изменены:    {modified}")
    print(f"    Добавлены:   {added}")
    print(f"    Удалены:     {removed}")
    print()

    if diff["modified"]:
        print("  Изменённые файлы:")
        for item in sorted(diff["modified"], key=lambda x: x["path"]):
            print(f"    - {item['path']} | {item['reason']}")
        print()

    if diff["added"]:
        print("  Добавленные файлы:")
        for path in sorted(diff["added"]):
            print(f"    - {path}")
        print()

    if diff["removed"]:
        print("  Удалённые файлы:")
        for path in sorted(diff["removed"]):
            print(f"    - {path}")
        print()

    agg = _aggregate_checks(results)
    if agg:
        print("🔒 ПРОВЕРКИ БЕЗОПАСНОСТИ:")
        for check_name in sorted(agg):
            counts = agg[check_name]
            parts = []
            if counts["pass"]:
                parts.append(f"[OK] × {counts['pass']}")
            if counts["fail"]:
                parts.append(f"[!] × {counts['fail']}")
            if counts["warn"]:
                parts.append(f"[?] × {counts['warn']}")
            if counts["skip"]:
                parts.append(f"[--] × {counts['skip']}")
            print(f"  {check_name:10s} {'   '.join(parts)}")
        print()

    failures, warnings = _collect_issues(results)

    if failures:
        print("🚨 КРИТИЧНЫЕ ПРОБЛЕМЫ:")
        for check_name in sorted(failures):
            print(f"  {check_name}:")
            for issue in sorted(failures[check_name], key=lambda x: x["path"]):
                print(f"    - {issue['path']} — {issue['message']}")
        print()

    if warnings:
        print("⚠️  ПРЕДУПРЕЖДЕНИЯ:")
        for check_name in sorted(warnings):
            print(f"  {check_name}:")
            for issue in sorted(warnings[check_name], key=lambda x: x["path"]):
                print(f"    - {issue['path']} — {issue['message']}")
        print()

    total_fails = sum(len(v) for v in failures.values())

    if modified or total_fails:
        verdict = "🚨 КРИТИЧНЫЕ ПРОБЛЕМЫ!"
        details = []
        if modified:
            details.append(f"{modified} изменённых")
        if total_fails:
            details.append(f"{total_fails} провалов проверок")
        print(f"ВЕРДИКТ: {verdict} ({', '.join(details)})")
    elif added or removed or warnings:
        verdict = "⚠️  Есть замечания"
        details = []
        if added:
            details.append(f"{added} добавленных")
        if removed:
            details.append(f"{removed} удалённых")
        if warnings:
            details.append(f"{sum(len(v) for v in warnings.values())} предупреждений")
        print(f"ВЕРДИКТ: {verdict} ({', '.join(details)})")
    else:
        print("ВЕРДИКТ: ✅ Все файлы соответствуют эталону")

    print(line)


# ─── Команда: init ──────────────────────────────────────
def cmd_init(
        config: Config,
        logger: logging.Logger,
        key: bytes,
        progress: "ProgressReporter | None" = None
) -> int:
    """Создаёт эталон. Возвращает код выхода."""
    if config.etalon_path.exists():
        logger.error("etalon_already_exists", extra={"extra_data": {
            "path": str(config.etalon_path)
        }})
        return 1

    if not config.models_dir.is_dir():
        logger.error("models_dir_not_found", extra={"extra_data": {
            "path": str(config.models_dir)
        }})
        return 1

    logger.info("init_started")
    checks = get_all_checks()  # ← все проверки (hash, header, pickle)
    results = run_checks(
        config.models_dir, checks, logger,
        etalon=None,
        progress=progress,
        exclude_dirs=[config.quarantine_dir],
    )
    for path, checks_res in results.items():
        hash_res = checks_res.get("hash")
        if hash_res and hash_res.status == "warn":
            hash_res.status = "pass"
            hash_res.message = "Hash calculated (etalon created)"
    hashes = extract_hash_size(results)
    save_hashes_signed(hashes, config.etalon_path, key)
    state = build_state(results, config.models_dir)
    save_state(state, config.state_path)
    logger.info("etalon_created", extra={"extra_data": {"count": len(hashes)}})
    print(f"✅ Эталон создан: {len(hashes)} файлов")
    return 0


# ─── Команда: audit ─────────────────────────────────────
def cmd_audit(
    config: Config,
    logger: logging.Logger,
    key: bytes,
    update_etalon: bool = False,
    no_quarantine: bool = False,
    new_only: bool = False,
    allow_partial_update: bool = False,
    progress: "ProgressReporter | None" = None,
    check_names: list[str] | None = None,
) -> int:
    """Запускает аудит. Возвращает код выхода."""
    if not config.etalon_path.exists():
        logger.error("etalon_not_found", extra={"extra_data": {
            "path": str(config.etalon_path),
            "hint": "Если это первый запуск — используй --init"
        }})
        return 1

    try:
        old_hashes = load_hashes_verified(config.etalon_path, key)
    except EtalonCorruptedError as e:
        logger.error("etalon_corrupted", extra={"extra_data": {
            "path": str(config.etalon_path),
            "error": str(e),
            "hint": "Эталон повреждён. Пересоздай: auditllm reset && auditllm init"
        }})
        return 2
    except EtalonSignatureError as e:
        logger.error("etalon_signature_invalid", extra={"extra_data": {
            "path": str(config.etalon_path),
            "error": str(e),
            "hint": "🚨 Возможна атака! Эталон подменён."
        }})
        return 2

    if not config.models_dir.is_dir():
        logger.error("models_dir_not_found", extra={"extra_data": {
            "path": str(config.models_dir)
        }})
        return 1

    try:
        checks = get_checks(check_names)
    except ValueError as e:
        logger.error("invalid_check", extra={"extra_data": {"error": str(e)}})
        return 1

    files_to_scan: list[Path] | None = None

    if new_only:
        all_files = find_model_files(
            config.models_dir,
            exclude_dirs=[config.quarantine_dir],
        )
        files_to_scan = [
            f for f in all_files
            if str(f.relative_to(config.models_dir)) not in old_hashes
        ]

        logger.info("new_only_mode", extra={"extra_data": {
            "total": len(all_files),
            "to_scan": len(files_to_scan),
            "skipped": len(all_files) - len(files_to_scan),
        }})

        if not files_to_scan:
            print("🔍 Режим --new-only: все файлы уже в эталоне")
            print("   Для полной проверки запусти: auditllm audit")
            return 0

        print(
            f"🔍 Режим --new-only: {len(files_to_scan)} новых "
            f"из {len(all_files)} "
            f"(пропущено {len(all_files) - len(files_to_scan)})"
        )

    results = run_checks(
        config.models_dir, checks, logger,
        etalon=old_hashes,
        progress=progress,
        exclude_dirs=[config.quarantine_dir],
        files=files_to_scan,
    )

    new_state = build_state(results, config.models_dir)
    if new_only:
        old_state = load_state(config.state_path)
        merged_state = {**old_state, **new_state}
        save_state(merged_state, config.state_path)
    else:
        save_state(new_state, config.state_path)

    new_hashes = extract_hash_size(results)

    if new_only:
        combined = {**old_hashes, **new_hashes}
        diff = compare_states(old_hashes, combined)
    else:
        diff = compare_states(old_hashes, new_hashes)

    for item in diff["modified"]:
        path = item["path"]
        logger.warning("modified_detected", extra={"extra_data": {
            "path": path,
            "reason": item["reason"],
            "expected": item["expected"],
            "actual": item["actual"]
        }})

        if not no_quarantine:
            file_path = config.models_dir / path
            try:
                quarantine_file(
                    file_path=file_path,
                    reason=item["reason"],
                    details={"expected": item["expected"], "actual": item["actual"]},
                    quarantine_dir=config.quarantine_dir
                )
                logger.error("quarantined", extra={"extra_data": {"path": path}})
            except FileNotFoundError:
                logger.error("quarantine_failed_file_gone", extra={"extra_data": {
                    "path": path,
                    "hint": "Файл исчез между сканированием и карантином"
                }})

    critical_check_failed = False
    for path, checks_res in results.items():
        for check_name, check_res in checks_res.items():
            if check_res.status == "fail":
                logger.error("check_failed", extra={"extra_data": {
                    "path": path,
                    "check": check_name,
                    "message": check_res.message,
                }})
                critical_check_failed = True

    for path in diff["added"]:
        logger.info("file_added", extra={"extra_data": {"path": path}})
    for path in diff["removed"]:
        logger.info("file_removed", extra={"extra_data": {"path": path}})

    print_report(diff, results)

    if update_etalon:
        if new_only and not allow_partial_update:
            logger.warning("partial_update_no_removed", extra={"extra_data": {
                "hint": "removed не будут удалены в --new-only"
            }})
            print("⚠️  --new-only: отсутствующие файлы НЕ будут удалены из эталона")
        updated = dict(old_hashes)
        added_clean = []
        added_with_warn = []
        skipped_fail = []

        for path in diff["added"]:
            file_checks = results.get(path, {})

            has_fail = any(res.status == "fail" for res in file_checks.values())
            has_warn = any(res.status == "warn" for res in file_checks.values())

            if has_fail:
                skipped_fail.append(path)
                continue

            updated[path] = new_hashes[path]
            if has_warn:
                added_with_warn.append(path)
            else:
                added_clean.append(path)

        for path in diff["removed"]:
            updated.pop(path, None)

        save_hashes_signed(updated, config.etalon_path, key)

        logger.info("etalon_updated", extra={"extra_data": {
            "count": len(updated),
            "added_clean": added_clean,
            "added_with_warn": added_with_warn,
            "skipped_fail": skipped_fail,
            "removed": len(diff["removed"]),
            "modified_skipped": len(diff["modified"]),
        }})

        print(f"✅ Эталон обновлён: {len(updated)} файлов")
        if added_clean:
            print(f"   Добавлены: {', '.join(added_clean)}")
        if added_with_warn:
            print(f"   ⚠️  Добавлены с warning: {', '.join(added_with_warn)}")
        if skipped_fail:
            print(f"   ❌ Пропущены (fail): {', '.join(skipped_fail)}")
            print(f"   Для принудительного добавления: auditllm promote <file> --force")
        if diff["removed"]:
            print(f"   Удалены из эталона: {len(diff['removed'])}")

    if diff["modified"] or critical_check_failed:
        return 2
    if diff["added"] or diff["removed"]:
        return 1
    return 0


def cmd_etalon_update(
    config: Config,
    logger: logging.Logger,
    key: bytes,
    dry_run: bool = False,
    yes: bool = False,
    keep_state: bool = False,
) -> int:
    """Синхронизирует эталон с диском БЕЗ пересчёта хешей.

    Удаляет из эталона записи, которых нет на диске.
    Новые файлы НЕ добавляет (для этого нужен audit --update-etalon).

    Returns:
        0 — успех / нечего обновлять
        1 — эталон не найден / ошибка
        2 — подпись не совпадает
    """
    if not config.etalon_path.exists():
        logger.error("etalon_not_found", extra={"extra_data": {
            "path": str(config.etalon_path),
            "hint": "Если это первый запуск — используй init"
        }})
        return 1

    try:
        old_hashes = load_hashes_verified(config.etalon_path, key)
    except EtalonCorruptedError as e:
        logger.error("etalon_corrupted", extra={"extra_data": {
            "path": str(config.etalon_path),
            "error": str(e),
            "hint": "Эталон повреждён. Пересоздай: auditllm reset && auditllm init"
        }})
        return 2
    except EtalonSignatureError as e:
        logger.error("etalon_signature_invalid", extra={"extra_data": {
            "path": str(config.etalon_path),
            "error": str(e),
            "hint": "🚨 Возможна атака! Эталон подменён."
        }})
        return 2

    if not config.models_dir.is_dir():
        logger.error("models_dir_not_found", extra={"extra_data": {
            "path": str(config.models_dir)
        }})
        return 1

    # Только список файлов (без хешей)
    files = find_model_files(config.models_dir, exclude_dirs=[config.quarantine_dir])
    on_disk = {str(f.relative_to(config.models_dir)) for f in files}

    # removed: в эталоне, но нет на диске
    removed = sorted(set(old_hashes.keys()) - on_disk)
    # added: на диске, но нет в эталоне (не добавляем без хешей)
    added = sorted(on_disk - set(old_hashes.keys()))

    if not removed:
        print(f"✅ Эталон синхронизирован: {len(old_hashes)} файлов, удалять нечего")
        if added:
            print(f"   ⚠️  Новые файлы (нужен audit --update-etalon): {', '.join(added)}")
        return 0

    # E4: подробный отчёт с размерами
    print()
    print("=" * 60)
    print("СИНХРОНИЗАЦИЯ ЭТАЛОНА".center(60))
    print("=" * 60)
    print()
    print(f"  Файлов в эталоне:  {len(old_hashes)}")
    print(f"  Файлов на диске:   {len(on_disk)}")
    print()
    print(f"  🗑️  Будет удалено из эталона ({len(removed)}):")
    print()
    total_size = 0
    for p in removed:
        size = old_hashes[p].get("size", 0)
        total_size += size
        print(f"     - {p}  ({format_size(size)})")
    print()
    print(f"  Итого удаляется: {format_size(total_size)} из эталона")
    if added:
        print()
        print(f"  ➕ Новые файлы (НЕ добавляются без хешей, {len(added)}):")
        for p in added:
            print(f"     - {p}")
    print()
    print("  ⚠️  Модели на диске НЕ трогаются. Удаляются только записи из эталона.")
    print()

    if dry_run:
        print("🔍 Dry run — эталон НЕ изменён")
        return 0

    if not yes:
        try:
            answer = input("Введи 'yes' для подтверждения: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nОтменено")
            return 0
        if answer != "yes":
            print("Отменено")
            return 0

    updated = {k: v for k, v in old_hashes.items() if k not in removed}
    save_hashes_signed(updated, config.etalon_path, key)

    # B: чистим state от «мёртвых» (если не --keep-state)
    state_cleaned = 0
    if not keep_state:
        state = load_state(config.state_path)
        before = len(state)
        state = {
            k: v for k, v in state.items()
            if k in updated or (config.models_dir / k).is_file()
        }
        state_cleaned = before - len(state)
        if state_cleaned > 0:
            save_state(state, config.state_path)
            logger.info("state_cleaned", extra={"extra_data": {
                "removed": state_cleaned,
            }})

    logger.info("etalon_updated", extra={"extra_data": {
        "count": len(updated),
        "removed": removed,
        "added_skipped": added,
        "state_cleaned": state_cleaned,
    }})

    print()
    print(f"✅ Эталон обновлён: {len(updated)} файлов (удалено {len(removed)})")
    if state_cleaned > 0:
        print(f"🧹 State очищен: удалено {state_cleaned} «мёртвых» записей")
    return 0


def cmd_list(
    config: Config,
    logger: logging.Logger,
    as_json: bool = False,
    show_all: bool = False,
) -> int:
    state = load_state(config.state_path)
    etalon = load_hashes_unverified(config.etalon_path)
    if not state:
        logger.warning("state_not_found_for_list", extra={"extra_data": {
            "path": str(config.state_path),
            "hint": "Запусти audit или init для создания state"
        }})

    models = []
    for path, entry in state.items():
        file_path = config.models_dir / path
        present = file_path.is_file()
        in_etalon = path in etalon

        # B: скрываем «мёртвые» записи (нет на диске И нет в эталоне)
        if not show_all and not present and not in_etalon:
            continue
        if present:
            actual_size = file_path.stat().st_size
            if entry.get("size") != actual_size:
                checks_status = {name: "stale" for name in entry.get("checks", {})}
            else:
                checks_status = {
                    name: res.get("status", "unknown")
                    for name, res in entry.get("checks", {}).items()
                }
        else:
            checks_status = {
                name: res.get("status", "unknown")
                for name, res in entry.get("checks", {}).items()
            }
        models.append({
            "name": path,
            "path": path,
            "size": entry.get('size'),
            "size_human": format_size(entry["size"]) if entry.get("size") else "?",
            "present": present,
            "last_audit": entry.get('last_audit'),
            "file_duration_ms": entry.get('file_duration_ms', 0),
            "checks": checks_status,
            "in_etalon": in_etalon,
        })

    # 4.4: сортировка — здоровые сверху, требующие внимания внизу
    def _sort_key(m):
        if not m["present"]:
            return (2, m["path"])  # мёртвые — вниз
        if not m["in_etalon"]:
            return (1, m["path"])  # на диске, не в эталоне — середина
        return (0, m["path"])  # здоровые — вверх

    models.sort(key=_sort_key)
    present_count = sum(1 for m in models if m["present"])
    summary = {
        "total": len(models),
        "present": present_count,
        "absent": len(models) - present_count,
        "in_etalon": sum(1 for m in models if m["in_etalon"]),
        "not_in_etalon": sum(1 for m in models if not m["in_etalon"]),
    }

    if as_json:
        _print_list_json(config.models_dir, models, summary)
    else:
        _print_list_table(config.models_dir, models, summary)

    return 0


def cmd_inbox(
    config: Config,
    logger: logging.Logger,
    as_json: bool = False,
    new_only: bool = False,
) -> int:
    """Показывает файлы в папке моделей (транзитная папка inbox)."""
    if not config.models_dir.is_dir():
        logger.error("models_dir_not_found", extra={"extra_data": {
            "path": str(config.models_dir)
        }})
        return 1

    files = find_model_files(config.models_dir, exclude_dirs=[config.quarantine_dir])
    state = load_state(config.state_path)
    etalon = load_hashes_unverified(config.etalon_path)

    models = []
    for file_path in files:
        relative = file_path.relative_to(config.models_dir)
        st = file_path.stat()
        state_entry = state.get(str(relative))
        in_etalon = str(relative) in etalon

        if state_entry is None:
            registry_status = "new"
        elif state_entry.get("size") != st.st_size:
            registry_status = "modified"
        else:
            registry_status = "verified"

        if new_only and registry_status != "new":
            continue

        models.append({
            "name": str(relative),
            "path": str(relative),
            "size": st.st_size,
            "size_human": format_size(st.st_size),
            "registry_status": registry_status,
            "in_etalon": in_etalon,
        })

    # 4.4: сортировка — verified сверху, new внизу
    REGISTRY_ORDER = {"verified": 0, "modified": 1, "new": 2}
    models.sort(key=lambda m: (REGISTRY_ORDER.get(m["registry_status"], 9), m["path"]))

    summary = {
        "total": len(models),
        "verified": sum(1 for m in models if m["registry_status"] == "verified"),
        "new": sum(1 for m in models if m["registry_status"] == "new"),
        "modified": sum(1 for m in models if m["registry_status"] == "modified"),
        "total_size": sum(m["size"] for m in models),
        "total_size_human": format_size(sum(m["size"] for m in models)),
        "in_etalon": sum(1 for m in models if m["in_etalon"]),
        "not_in_etalon": sum(1 for m in models if not m["in_etalon"]),
    }

    if as_json:
        _print_inbox_json(config.models_dir, models, summary)
    else:
        _print_inbox_table(config.models_dir, models, summary)

    return 0


def cmd_inspect(
        config: Config,
        logger: logging.Logger,
        paths: list[Path] | None = None,
        all_files: bool = False,
        check_names: list[str] | None = None,
        as_json: bool = False,
) -> int:
    """Просмотр файлов без сохранения. Возвращает код выхода."""
    if all_files:
        if not config.models_dir.is_dir():
            logger.error("models_dir_not_found", extra={"extra_data": {
                "path": str(config.models_dir)
            }})
            return 1
        files = find_model_files(
            config.models_dir,
            exclude_dirs=[config.quarantine_dir],
        )
    elif paths:
        files = []
        for p in paths:
            resolved = _resolve_path(Path(p), config.models_dir)
            if resolved is None:
                logger.error("file_not_found", extra={"extra_data": {
                    "path": str(p),
                    "hint": f"Не найден ни как {p}, ни в {config.models_dir}",
                }})
                return 1
            files.append(resolved)
    else:
        logger.error("no_files_specified", extra={"extra_data": {
            "path": str(config.models_dir),
            "hint": "Укажи файлы или --all",
        }})
        return 1

    if not files:
        logger.warning("no_files_found", extra={"extra_data": {
            "path": str(config.models_dir)
        }})
        return 0

    try:
        if check_names:
            checks = get_checks(check_names)
        else:
            checks = [c for c in get_all_checks() if c.name != "hash"]
    except ValueError as e:
        logger.error("invalid_check", extra={"extra_data": {"error": str(e)}})
        return 1

    results = []
    use_spinner = not as_json

    with Spinner(enabled=use_spinner, prefix="🔍 ") as spinner:
        for i, file_path in enumerate(files):
            spinner.update(f"{file_path.name} ({i + 1}/{len(files)})")

            file_res = {"path": str(file_path), "name": file_path.name}
            try:
                st = file_path.stat()
                file_res["size"] = st.st_size
                file_res["size_human"] = format_size(st.st_size)
            except OSError:
                file_res["size"] = None
                file_res["size_human"] = "?"

            file_res["checks"] = {}
            for check in checks:
                if not check.supports(file_path):
                    file_res["checks"][check.name] = CheckResult(
                        status="skip",
                        message=f"Not supported for {file_path.suffix}",
                    )
                    continue

                spinner.update(f"{file_path.name} — {check.name}")
                try:
                    res = check.run(file_path, context=None)
                except Exception as e:
                    res = CheckResult(status="fail", message=f"Check crashed: {e}")
                file_res["checks"][check.name] = res

            results.append(file_res)

    if as_json:
        _print_inspect_json(results)
    else:
        _print_inspect_table(results)

    return 0


def cmd_promote(
    config: Config,
    logger: logging.Logger,
    key: bytes,
    paths: list[Path] | None = None,
    force: bool = False,
    dry_run: bool = False,
    as_json: bool = False,
) -> int:
    """Добавить проверенные файлы из state в эталон БЕЗ сканирования."""
    state = load_state(config.state_path)
    if not state:
        logger.error("state_not_found", extra={"extra_data": {
            "path": str(config.state_path),
            "hint": "Запусти audit или init для создания state"
        }})
        return 1

    try:
        old_hashes = load_hashes_verified(config.etalon_path, key)
    except EtalonCorruptedError as e:
        logger.error("etalon_corrupted", extra={"extra_data": {
            "path": str(config.etalon_path),
            "error": str(e),
            "hint": "Эталон повреждён. Пересоздай: auditllm reset && auditllm init"
        }})
        return 2
    except EtalonSignatureError as e:
        logger.error("etalon_signature_invalid", extra={"extra_data": {
            "path": str(config.etalon_path),
            "error": str(e),
            "hint": "🚨 Возможна атака! Эталон подменён."
        }})
        return 2

    if paths:
        target_paths = []
        for p in paths:
            resolved = _resolve_path(Path(p), config.models_dir)
            if resolved is None:
                logger.error("file_not_found", extra={"extra_data": {
                    "path": str(p),
                    "hint": f"Не найден ни как {p}, ни в {config.models_dir}",
                }})
                return 1
            relative = str(resolved.relative_to(config.models_dir))
            target_paths.append(relative)
    else:
        target_paths = sorted(state.keys())

    updated = dict(old_hashes)
    added_clean = []
    added_with_warn = []
    added_forced = []
    skipped_fail = []
    skipped_not_in_state = []
    skipped_no_hash = []
    skipped_already_in_etalon = []

    for path in target_paths:
        entry = state.get(path)
        if entry is None:
            skipped_not_in_state.append(path)
            continue

        if path in old_hashes:
            skipped_already_in_etalon.append(path)
            continue

        checks = entry.get("checks", {})
        has_fail = any(r.get("status") == "fail" for r in checks.values())
        has_warn = any(r.get("status") == "warn" for r in checks.values())

        hash_res = checks.get("hash", {})
        details = hash_res.get("details", {})
        hash_val = None
        size_val = None
        if "hash" in details and "size" in details:
            hash_val = details["hash"]
            size_val = details["size"]
        elif "actual" in details:
            hash_val = details["actual"].get("hash")
            size_val = details["actual"].get("size")

        if not hash_val or not size_val:
            skipped_no_hash.append(path)
            continue

        if has_fail and not force:
            skipped_fail.append(path)
            continue

        updated[path] = {"hash": hash_val, "size": size_val}

        if has_fail:
            added_forced.append(path)
        elif has_warn:
            added_with_warn.append(path)
        else:
            added_clean.append(path)

    if dry_run:
        print("🔍 Dry run — эталон НЕ изменён")
        _print_added_lists(added_clean, added_with_warn, added_forced)
        _print_skipped_lists(
            skipped_fail, skipped_not_in_state,
            skipped_no_hash, skipped_already_in_etalon,
        )
        if not (added_clean or added_with_warn or added_forced):
            print("   Нечего добавлять")
        return 0

    total_added = len(added_clean) + len(added_with_warn) + len(added_forced)
    if total_added == 0:
        print("Нечего добавлять в эталон")
        _print_skipped_lists(
            skipped_fail, skipped_not_in_state,
            skipped_no_hash, skipped_already_in_etalon,
        )
        return 0

    save_hashes_signed(updated, config.etalon_path, key)

    # Обновить state: hash → pass
    for path in (added_clean + added_with_warn + added_forced):
        entry = state.get(path)
        if entry is None:
            continue
        checks = entry.get("checks", {})
        hash_res = checks.get("hash", {})
        if hash_res.get("status") == "warn":
            hash_res["status"] = "pass"
            hash_res["message"] = "Hash matches etalon (promoted)"
    save_state(state, config.state_path)

    logger.info("promoted", extra={"extra_data": {
        "count": len(updated),
        "added_clean": added_clean,
        "added_with_warn": added_with_warn,
        "added_forced": added_forced,
        "skipped_fail": skipped_fail,
        "skipped_not_in_state": skipped_not_in_state,
        "skipped_no_hash": skipped_no_hash,
    }})

    if as_json:
        output = {
            "count": len(updated),
            "added_clean": added_clean,
            "added_with_warn": added_with_warn,
            "added_forced": added_forced,
            "skipped_fail": skipped_fail,
            "skipped_not_in_state": skipped_not_in_state,
            "skipped_no_hash": skipped_no_hash,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(f"✅ Эталон обновлён: {len(updated)} файлов")
        _print_added_lists(added_clean, added_with_warn, added_forced)
        _print_skipped_lists(
            skipped_fail, skipped_not_in_state,
            skipped_no_hash, skipped_already_in_etalon,
        )

    return 0


def _print_added_lists(added_clean, added_with_warn, added_forced):
    """Печатает added-списки: в строку если <= 3, иначе в столбик."""
    if added_clean:
        if len(added_clean) <= 3:
            print(f"   Добавлены: {', '.join(added_clean)}")
        else:
            print(f"   Добавлены ({len(added_clean)}):")
            for p in added_clean:
                print(f"      - {p}")
    if added_with_warn:
        if len(added_with_warn) <= 3:
            print(f"   ⚠️  Добавлены с warning: {', '.join(added_with_warn)}")
        else:
            print(f"   ⚠️  Добавлены с warning ({len(added_with_warn)}):")
            for p in added_with_warn:
                print(f"      - {p}")
    if added_forced:
        if len(added_forced) <= 3:
            print(f"   ⚠️  Добавлены принудительно (fail): {', '.join(added_forced)}")
        else:
            print(f"   ⚠️  Добавлены принудительно (fail, {len(added_forced)}):")
            for p in added_forced:
                print(f"      - {p}")


def _print_skipped_lists(skipped_fail, skipped_not_in_state, skipped_no_hash, skipped_already_in_etalon):
    """Печатает skipped-списки: всегда в столбик."""
    if skipped_fail:
        print(f"   ❌ Пропущены (fail, {len(skipped_fail)}):")
        for p in skipped_fail:
            print(f"      - {p}")
        print(f"      Используй --force для принудительного добавления")
    if skipped_not_in_state:
        print(f"   ⏭️  Нет в state ({len(skipped_not_in_state)}):")
        for p in skipped_not_in_state:
            print(f"      - {p}")
    if skipped_no_hash:
        print(f"   ⏭️  Нет hash в state ({len(skipped_no_hash)}):")
        for p in skipped_no_hash:
            print(f"      - {p}")
    if skipped_already_in_etalon:
        print(f"   ⏭️  Уже в эталоне ({len(skipped_already_in_etalon)}):")
        for p in skipped_already_in_etalon:
            print(f"      - {p}")


def cmd_report(
        config: Config,
        logger: logging.Logger,
        paths: list[Path] | None = None,
        as_json: bool = False,
) -> int:
    """Показать результат последней проверки."""
    if not paths:
        from auditllm.report import read_last_audit

        audit = read_last_audit(config.log_path)
        if audit is None:
            logger.warning("no_audit_in_log", extra={"extra_data": {
                "path": str(config.log_path),
                "hint": "Запусти auditllm audit"
            }})
            print("Нет записей об аудите в логе")
            return 0

        if as_json:
            print(json.dumps(audit, indent=2, ensure_ascii=False))
        else:
            _print_last_audit(audit)
        return 0

    state = load_state(config.state_path)
    if not state:
        logger.error("state_not_found", extra={"extra_data": {
            "path": str(config.state_path),
            "hint": "Запусти audit или init для создания state"
        }})
        return 1

    results = []
    for p in paths:
        resolved = _resolve_path(Path(p), config.models_dir)

        if resolved is not None:
            relative = str(resolved.relative_to(config.models_dir))
        else:
            p_str = str(p)
            matches = [k for k in state.keys() if Path(k).name == Path(p_str).name]
            if len(matches) == 1:
                relative = matches[0]
            elif len(matches) > 1:
                logger.error("ambiguous_path", extra={"extra_data": {
                    "path": str(p),
                    "candidates": matches,
                    "hint": "Укажи полный относительный путь",
                }})
                return 1
            else:
                logger.error("file_not_found", extra={"extra_data": {
                    "path": str(p),
                    "hint": f"Не найден ни в {config.models_dir}, ни в state",
                }})
                return 1

        entry = state.get(relative)
        if entry is None:
            results.append({
                "path": relative,
                "error": "not in state",
            })
            continue

        file_path = config.models_dir / relative
        present = file_path.is_file()
        stale = False
        if present:
            actual_size = file_path.stat().st_size
            if entry.get("size") != actual_size:
                stale = True

        results.append({
            "path": relative,
            "name": Path(relative).name,
            "size": entry.get("size"),
            "last_audit": entry.get("last_audit"),
            "file_duration_ms": entry.get("file_duration_ms", 0),
            "present": present,
            "stale": stale,
            "checks": entry.get("checks", {}),
        })

    if as_json:
        _print_report_json(results, state)
    else:
        _print_report_table(results)

    return 0


def cmd_reset(
        config: Config,
        logger: logging.Logger,
        key: bytes,
        no_backup: bool = False,
        yes: bool = False,
) -> int:
    """Сбросить эталон, state и лог с бэкапом."""
    if not yes:
        print()
        print("⚠️  СБРОС:")
        print(f"   Эталон:   {config.etalon_path}")
        print(f"   State:    {config.state_path}")
        print(f"   Лог:      {config.log_path}")
        if not no_backup:
            print(f"   Бэкап:    {config.data_dir / 'backups'}")
        print()
        print("НЕ трогаются: модели, карантин, config, .env")
        print()

        try:
            answer = input("Введи 'yes' для подтверждения: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nОтменено")
            return 0

        if answer != "yes":
            print("Отменено")
            return 0

    backups_dir = config.data_dir / "backups"
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    backup_paths = []

    if not no_backup:
        backups_dir.mkdir(parents=True, exist_ok=True)

        if config.etalon_path.exists():
            bak = backups_dir / f"model_hashes.json.{timestamp}.bak"
            shutil.copy2(config.etalon_path, bak)
            backup_paths.append(bak)

        if config.state_path.exists():
            bak = backups_dir / f"models_state.json.{timestamp}.bak"
            shutil.copy2(config.state_path, bak)
            backup_paths.append(bak)

        if config.log_path.exists():
            bak = backups_dir / f"audit_log.jsonl.{timestamp}.bak"
            shutil.copy2(config.log_path, bak)
            backup_paths.append(bak)

    save_hashes_signed({}, config.etalon_path, key)
    print(f"✅ Эталон сброшен: {config.etalon_path}")

    save_state({}, config.state_path)
    print(f"✅ State сброшен: {config.state_path}")

    if config.log_path.exists():
        config.log_path.unlink()
    config.log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"✅ Лог сброшен: {config.log_path}")

    logger.info("reset_completed", extra={"extra_data": {
        "backups": [str(b) for b in backup_paths],
    }})

    if backup_paths:
        print()
        print("Бэкапы:")
        for bak in backup_paths:
            print(f"   - {bak}")

    return 0


# ─── Печать (inspect, list, report) ─────────────────────

def _print_inspect_table(results: list):
    for i, file_res in enumerate(results):
        if i > 0:
            print()
        print(f"📄 {file_res['name']} ({file_res['size_human']})")
        print(f"   {file_res['path']}")
        print()
        for check_name, check_res in file_res["checks"].items():
            print(f"🔒 {check_name}: [{_status_short(check_res.status)}] — {check_res.message}")
            if check_res.details:
                _print_details(check_res.details)
            print()


def _print_details(details: dict):
    for k, v in details.items():
        if k == "error":
            continue

        if k == "dangerous" and isinstance(v, list):
            if not v:
                continue
            print(f"     dangerous:")
            for d in v:
                if isinstance(d, dict):
                    module = d.get("module", "?")
                    category = d.get("category", "?")
                    pos = d.get("pos", "?")
                    inner = d.get("inner_file")
                    prefix = f"{inner}: " if inner else ""
                    print(f"       - {prefix}{module} ({category}) at pos {pos}")
                else:
                    print(f"       - {d}")

        elif k == "warnings" and isinstance(v, list):
            if not v:
                continue
            print(f"     warnings:")
            for w in v:
                if isinstance(w, dict):
                    msg = w.get("message", "?")
                    inner = w.get("inner_file")
                    prefix = f"{inner}: " if inner else ""
                    print(f"       - {prefix}{msg}")
                else:
                    print(f"       - {w}")
        elif k == "disassembly" and isinstance(v, list):
            if not v:
                continue
            print(f"     disassembly:")
            for item in v[:30]:
                pos = item.get("pos", "?")
                opcode = item.get("opcode", "?")
                arg = item.get("arg", "")
                inner = item.get("inner_file")
                prefix = f"{inner}: " if inner else ""
                arg_str = f" {arg}" if arg else ""
                print(f"       {prefix}{pos:>4}: {opcode:<20}{arg_str}")
            if len(v) > 30:
                print(f"       ... ({len(v) - 30} more)")

        elif isinstance(v, dict):
            if not v:
                continue
            print(f"     {k}:")
            for kk, vv in v.items():
                print(f"       {kk}: {vv}")

        elif isinstance(v, list):
            if not v:
                continue
            print(f"     {k}:")
            for item in v[:10]:
                print(f"       - {item}")
            if len(v) > 10:
                print(f"       ... ({len(v) - 10} more)")
        else:
            print(f"     {k}: {v}")


def _status_short(status: str) -> str:
    return {
        "pass": "OK",
        "fail": "!",
        "warn": "?",
        "skip": "--",
    }.get(status, "?")


def _print_inspect_json(results: list):
    output = {
        "count": len(results),
        "files": [
            {
                "path": fr["path"],
                "name": fr["name"],
                "size": fr["size"],
                "size_human": fr["size_human"],
                "checks": {
                    name: {
                        "status": res.status,
                        "message": res.message,
                        "details": res.details,
                        "duration_ms": res.duration_ms,
                    }
                    for name, res in fr["checks"].items()
                },
            }
            for fr in results
        ],
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


def _print_last_audit(audit: dict) -> None:
    line = "=" * 55
    print(line)
    print("ПОСЛЕДНИЙ АУДИТ".center(55))
    print(line)
    print()

    print(f"  Начат:      {_format_last_audit(audit.get('started_at'))}")
    print(f"  Завершён:   {_format_last_audit(audit.get('finished_at'))}")
    print()

    summary = audit.get("summary", {})

    failures = summary.get("check_failures", [])
    if failures:
        print(f"🚨 ПРОВАЛЫ ПРОВЕРОК ({len(failures)}):")
        for f in failures:
            print(f"    - {f['path']} [{f['check']}] — {f['message']}")
        print()

    modified = summary.get("modified", [])
    if modified:
        print(f"⚠️  ИЗМЕНЁННЫЕ ({len(modified)}):")
        for m in modified:
            print(f"    - {m['path']} | {m['reason']}")
        print()

    added = summary.get("added", [])
    if added:
        print(f"➕ ДОБАВЛЕННЫЕ ({len(added)}):")
        for a in added:
            print(f"    - {a}")
        print()

    removed = summary.get("removed", [])
    if removed:
        print(f"➖ УДАЛЁННЫЕ ({len(removed)}):")
        for r in removed:
            print(f"    - {r}")
        print()

    quarantined = summary.get("quarantined", [])
    if quarantined:
        print(f"🚧 В КАРАНТИНЕ ({len(quarantined)}):")
        for q in quarantined:
            print(f"    - {q}")
        print()

    if not any([failures, modified, added, removed, quarantined]):
        print("  Замечаний нет.")
        print()

    print(line)


def compute_checks_status(state_entry: dict | None, file_size: int) -> dict:
    if state_entry is None:
        return {}

    checks = state_entry.get("checks", {})
    result = {}

    if state_entry.get("size") != file_size:
        for name in checks:
            result[name] = "stale"
    else:
        for name, check_res in checks.items():
            result[name] = check_res.get("status", "unknown")

    return result


STATUS_LABELS = {
    "pass": "[green][OK][/green]",
    "fail": "[red][!][/red]",
    "warn": "[yellow][?][/yellow]",
    "skip": "[dim][--][/dim]",
    "stale": "[yellow][~][/yellow]",
    "unknown": "[dim][?][/dim]",
}

REGISTRY_LABELS = {
    "verified": "[green][OK][/green]",
    "modified": "[yellow][!][/yellow]",
    "new":      "[dim][ ][/dim]",
}

IN_ETALON_LABELS = {
    True:  "[green][+][/green]",
    False: "[dim][-][/dim]",
}

PRESENCE_LABELS = {
    True:  "[green][+][/green]",
    False: "[dim][-][/dim]",
}


def _format_duration_ms(ms: int) -> str:
    """Форматирует миллисекунды в читаемый вид: 0.1s, 1.2s, 1m 5s."""
    if not ms:
        return "—"
    sec = ms / 1000
    if sec < 60:
        return f"{sec:.1f}s"
    m = int(sec // 60)
    s = int(sec % 60)
    return f"{m}m {s}s"


def _print_list_table(models_dir, models, summary):
    console = Console()
    console.print(f"\n📁 Реестр проверенных моделей\n")
    console.print(f"Всего записей: {summary['total']}\n")

    if not models:
        console.print("[yellow]Реестр пуст. Запусти init или audit.[/yellow]")
        return

    all_checks = set()
    for m in models:
        all_checks.update(m["checks"].keys())
    check_names = sorted(all_checks)

    table = Table(show_header=True, header_style="bold", box=box.SIMPLE, border_style='dim')
    table.add_column("#", style="dim", width=3)
    table.add_column("Имя")
    table.add_column("Размер", justify="right")
    table.add_column("Наличие", justify="center")
    table.add_column("Эталон", justify="center")
    for name in check_names:
        table.add_column(name, justify="center")
    table.add_column("Time", justify="right")
    table.add_column("Последняя проверка", justify="right")

    for i, m in enumerate(models, 1):
        row = [
            str(i),
            m["name"],
            m["size_human"],
            PRESENCE_LABELS[m["present"]],
            IN_ETALON_LABELS[m["in_etalon"]],
        ]
        for name in check_names:
            status = m["checks"].get(name, "unknown")
            row.append(STATUS_LABELS.get(status, status))
        row.append(_format_duration_ms(m.get("file_duration_ms", 0)))
        row.append(_format_last_audit(m.get("last_audit")))
        table.add_row(*row)

    console.print(table)

    console.print(
        f"\nИтого: {summary['total']} записей, "
        f"{summary['present']} на диске, {summary['absent']} отсутствуют"
    )
    if summary.get("in_etalon") is not None:
        console.print(
            f"[dim]В эталоне: {summary['in_etalon']}, "
            f"не в эталоне: {summary['not_in_etalon']}[/dim]"
        )

    tips = []
    has_stale = any(
        "stale" in m["checks"].values()
        for m in models
    )
    if has_stale:
        tips.append("Есть устаревшие записи — запусти: auditllm audit")

    if summary.get("not_in_etalon", 0) > 0:
        tips.append("Добавь проверенные в эталон: auditllm promote (без пересканирования)")

    _print_tips(tips)


def _print_list_json(models_dir, models, summary):
    output = {
        "models_dir": str(models_dir),
        "summary": summary,
        "models": models,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


def _print_tips(tips: list[str]) -> None:
    if not tips:
        return
    print()
    print("💡 Подсказки:")
    for tip in tips:
        print(f"   • {tip}")


def _print_inbox_table(models_dir, models, summary):
    console = Console()
    console.print(f"\n📁 Inbox: {models_dir}\n")
    console.print(
        f"Найдено: {summary['total']} "
        f"({'файл' if summary['total'] == 1 else 'файлов'}), "
        f"{summary['total_size_human']}\n"
    )

    if not models:
        console.print("[yellow]Файлов не найдено[/yellow]")
        _print_tips([f"Положи модели в {models_dir}"])
        return

    table = Table(show_header=True, header_style="bold", box=box.SIMPLE, border_style='dim')
    table.add_column("#", style="dim", width=3)
    table.add_column("Имя")
    table.add_column("Размер", justify="right")
    table.add_column("Реестр", justify="center")
    table.add_column("Эталон", justify="center")

    for i, m in enumerate(models, 1):
        table.add_row(
            str(i),
            m["name"],
            m["size_human"],
            REGISTRY_LABELS[m["registry_status"]],
            IN_ETALON_LABELS[m["in_etalon"]],
        )

    console.print(table)

    parts = []
    if summary["verified"]:
        parts.append(f"{summary['verified']} проверено")
    if summary["new"]:
        parts.append(f"{summary['new']} новых")
    if summary["modified"]:
        parts.append(f"{summary['modified']} изменено")
    if parts:
        console.print(f"\nИтого: {', '.join(parts)}")

    etalon_info = f"В эталоне: {summary['in_etalon']}, не в эталоне: {summary['not_in_etalon']}"
    console.print(f"[dim]{etalon_info}[/dim]")

    tips = []
    if summary["new"] > 0 and summary["not_in_etalon"] > 0:
        tips.append("Проверь новые: auditllm audit --new-only")
        tips.append("Затем добавь в эталон: auditllm promote (без пересканирования)")
    elif summary["new"] > 0:
        tips.append("Проверь новые: auditllm audit --new-only")

    if summary["modified"] > 0:
        tips.append("Есть изменённые файлы — запусти: auditllm audit")

    if summary["total"] == 0:
        tips.append(f"Положи модели в {models_dir}")

    if summary["verified"] == summary["total"] and summary["total"] > 0:
        tips.append("Всё проверено. Периодически запускай: auditllm audit")

    _print_tips(tips)


def _print_inbox_json(models_dir, models, summary):
    output = {
        "models_dir": str(models_dir),
        "summary": summary,
        "models": models,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


def _format_last_audit(iso_str: str | None) -> str:
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(iso_str)


# ─── run_checks ─────────────────────────────────────────

def run_checks(
    models_dir: Path,
    checks: list,
    logger: logging.Logger,
    etalon: dict | None = None,
    progress: "ProgressReporter | None" = None,
    exclude_dirs: list[Path] | None = None,
    files: list[Path] | None = None,
) -> dict:
    """Запускает проверки для всех файлов. Возвращает {path: {check_name: CheckResult}}."""
    if not models_dir.is_dir():
        logger.error('models_dir_not_found', extra={'extra_data': {
            'path': str(models_dir)
        }})
        raise FileNotFoundError(f'Файл не найден: {models_dir}')
    if files is None:
        files = find_model_files(models_dir, exclude_dirs=exclude_dirs)
    if not files:
        logger.warning('no_models_found', extra={'extra_data': {
            'path': str(models_dir)
        }})
        return {}
    logger.info('scan_started', extra={'extra_data': {'count': len(files)}})
    if progress:
        progress.start([(f.name, f.stat().st_size) for f in files])
    result = {}
    for i, file in enumerate(files):
        relative = file.relative_to(models_dir)
        file_results = {}

        if progress:
            progress.start_file(i)

        for check in checks:
            if progress:
                progress.start_check(check.name)

            if not check.supports(file):
                res = CheckResult(
                    status='skip',
                    message=f'Not supported for {file.suffix}',
                )
            else:
                context = etalon.get(str(relative)) if etalon else None
                try:
                    res = check.run(file, context=context, progress=progress)
                except Exception as e:
                    res = CheckResult(status='fail', message=f'Check crashed: {e}')

            if progress:
                progress.finish_check(status=res.status)

            file_results[check.name] = res
            logger.debug('check_done', extra={'extra_data': {
                'path': str(relative),
                'check': check.name,
                'status': res.status,
                'duration_ms': res.duration_ms,
            }})
        result[str(relative)] = file_results
        if progress:
            progress.finish_file()
    if progress:
        progress.finish()
    logger.info('scan_finished', extra={'extra_data': {'count': len(result)}})
    return result


def extract_hash_size(results: dict) -> dict:
    flat = {}
    for path, checks_res in results.items():
        hash_res = checks_res.get("hash")
        if not hash_res:
            continue
        details = hash_res.details
        if "hash" in details and "size" in details:
            flat[path] = {"hash": details["hash"], "size": details["size"]}
        elif "actual" in details:
            flat[path] = {
                "hash": details["actual"].get("hash"),
                "size": details["actual"].get("size"),
            }
    return flat


def _aggregate_checks(results: dict) -> dict:
    agg = {}
    for path, checks_res in results.items():
        for check_name, check_res in checks_res.items():
            if check_name not in agg:
                agg[check_name] = {"pass": 0, "fail": 0, "warn": 0, "skip": 0}
            agg[check_name][check_res.status] += 1
    return agg


def _collect_issues(results: dict) -> tuple[dict, dict]:
    failures = {}
    warnings = {}
    for path, checks_res in results.items():
        for check_name, check_res in checks_res.items():
            if check_res.status == "fail":
                failures.setdefault(check_name, []).append({
                    "path": path,
                    "message": check_res.message,
                    "details": check_res.details,
                })
            elif check_res.status == "warn":
                warnings.setdefault(check_name, []).append({
                    "path": path,
                    "message": check_res.message,
                    "details": check_res.details,
                })
    return failures, warnings


def _resolve_path(path: Path, models_dir: Path) -> Path | None:
    if path.is_file():
        return path
    if not path.is_absolute():
        candidate = models_dir / path
        if candidate.is_file():
            return candidate
        if path.parent == Path("."):
            matches = sorted(m for m in models_dir.rglob(path.name) if m.is_file())
            if len(matches) == 1:
                return matches[0]
            # b5: неоднозначность — возвращаем None
    return None



def _print_report_table(results: list) -> None:
    """Печатает детали из state."""
    for i, file_res in enumerate(results):
        if i > 0:
            print()

        if "error" in file_res:
            print(f"❌ {file_res['path']}")
            print(f"   {file_res['error']}")
            continue

        size_str = format_size(file_res["size"]) if file_res["size"] else "?"
        present_str = "[+]" if file_res["present"] else "[-]"
        stale_str = " ⚠️  изменился после проверки" if file_res["stale"] else ""

        print(f"📄 {file_res['name']} ({size_str})")
        print(f"   Path: {file_res['path']}")
        print(f"   Present: {present_str}{stale_str}")
        last_audit = _format_last_audit(file_res.get("last_audit"))
        print(f"   Last audit: {last_audit}")
        duration = _format_duration_ms(file_res.get("file_duration_ms", 0))
        print(f"   Time: {duration}")
        print()

        for check_name, check_res in file_res.get("checks", {}).items():
            status = check_res.get("status", "?")
            message = check_res.get("message", "")
            details = check_res.get("details", {})
            duration = check_res.get("duration_ms", 0)

            print(f"🔒 {check_name}: [{_status_short(status)}] — {message} ({duration} ms)")
            if details:
                _print_details(details)
            print()


def _print_report_json(results: list, state: dict) -> None:
    """JSON-вывод."""
    output = {
        "count": len(results),
        "files": results,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))





    