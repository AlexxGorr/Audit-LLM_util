"""Бизнес-логика аудита: сканирование, сравнение, отчёты.

Не знает ничего о CLI — принимает простые аргументы, возвращает данные.
"""
import logging
from pathlib import Path
from datetime import datetime

from auditllm.checks.hash_check import HashCheck

from auditllm.integrity import load_hashes_verified, save_hashes_signed
from auditllm.quarantine import quarantine_file
from auditllm.scanner import find_model_files
from auditllm.config import Config
from auditllm.utils import format_size
from auditllm.progress import ProgressReporter
from auditllm.checks.base import CheckResult
from auditllm.state import save_state, build_state
from auditllm.state import load_state
from auditllm.checks import get_checks

from rich.console import Console
from rich.table import Table
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

    # Файлы в обоих состояниях
    for path in (old_keys & new_keys):
        old_entry = old[path]
        new_entry = new[path]

        if old_entry == new_entry:
            result['unchanged'].append(path)
        else:
            # Определяем причину
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
    # Новые файлы (в new, но не в old)
    for path in (new_keys - old_keys):
        result['added'].append(path)

    # Пропавшие файлы (в old, но не в new)
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

    # ─── 1. ЦЕЛОСТНОСТЬ ───
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

    # ─── 2. ПРОВЕРКИ БЕЗОПАСНОСТИ ───
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

    # ─── 3. КРИТИЧНЫЕ ПРОБЛЕМЫ ───
    failures, warnings = _collect_issues(results)

    if failures:
        print("🚨 КРИТИЧНЫЕ ПРОБЛЕМЫ:")
        for check_name in sorted(failures):
            print(f"  {check_name}:")
            for issue in sorted(failures[check_name], key=lambda x: x["path"]):
                print(f"    - {issue['path']} — {issue['message']}")
        print()

    # ─── 4. ПРЕДУПРЕЖДЕНИЯ ───
    if warnings:
        print("⚠️  ПРЕДУПРЕЖДЕНИЯ:")
        for check_name in sorted(warnings):
            print(f"  {check_name}:")
            for issue in sorted(warnings[check_name], key=lambda x: x["path"]):
                print(f"    - {issue['path']} — {issue['message']}")
        print()

    # ─── 5. ВЕРДИКТ ───
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
    checks = [HashCheck()]  # для init — только hash, чтобы получить эталон
    results = run_checks(config.models_dir, checks, logger, progress=progress)
    for path, checks_res in results.items():
        hash_res = checks_res.get("hash")
        if hash_res and hash_res.status == "warn":
            # эталон только что создан из этих файлов → pass
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
    except ValueError as e:
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
        checks = get_checks(check_names)  # None → все
    except ValueError as e:
        logger.error("invalid_check", extra={"extra_data": {"error": str(e)}})
        return 1
    results = run_checks(config.models_dir, checks, logger, etalon=old_hashes, progress=progress)
    state = build_state(results, config.models_dir)
    save_state(state, config.state_path)
    new_hashes = extract_hash_size(results)
    diff = compare_states(old_hashes, new_hashes)

    # ─── Обработка modified → карантин ───
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

    # ─── Логирование added/removed ───
    for path in diff["added"]:
        logger.info("file_added", extra={"extra_data": {"path": path}})
    for path in diff["removed"]:
        logger.info("file_removed", extra={"extra_data": {"path": path}})

    # ─── Отчёт ───
    print_report(diff, results)

    # ─── Обновление эталона ───
    if update_etalon:
        updated = dict(old_hashes)
        for path in diff["added"]:
            updated[path] = new_hashes[path]
        for path in diff["removed"]:
            updated.pop(path, None)
        save_hashes_signed(updated, config.etalon_path, key)
        logger.info("etalon_updated", extra={"extra_data": {
            "count": len(updated),
            "added": len(diff["added"]),
            "removed": len(diff["removed"]),
            "modified_skipped": len(diff["modified"])
        }})
        print(f"✅ Эталон обновлён: {len(updated)} файлов")

    # ─── Код возврата ───
    if diff["modified"] or critical_check_failed:
        return 2
    if diff["added"] or diff["removed"]:
        return 1
    return 0


def cmd_list(config: Config, logger: logging.Logger, as_json: bool = False) -> int:
    state = load_state(config.state_path)
    if not state:
        logger.warning("state_not_found_for_list", extra={"extra_data": {
            "path": str(config.state_path),
            "hint": "Запусти audit или init для создания state"
        }})

    # 4. Сбор данных
    models = []
    for path, entry in state.items():
        file_path = config.models_dir / path
        present = file_path.is_file()
        # Определяем статусы checks
        if present:
            actual_size = file_path.stat().st_size
            if entry.get("size") != actual_size:
                # файл изменился → все проверки stale
                checks_status = {name: "stale" for name in entry.get("checks", {})}
            else:
                checks_status = {
                    name: res.get("status", "unknown")
                    for name, res in entry.get("checks", {}).items()
                }
        else:
            # файла нет — последние известные статусы
            checks_status = {
                name: res.get("status", "unknown")
                for name, res in entry.get("checks", {}).items()
            }
        models.append({
            "name": Path(path).name,
            "path": path,
            "size": entry.get('size'),
            "size_human": format_size(entry["size"]) if entry.get("size") else "?",
            "present": present,
            "last_audit": entry.get('last_audit'),
            "checks": checks_status,
        })

    models.sort(key=lambda x: x["path"])
    present_count = sum(1 for m in models if m["present"])
    summary = {
        "total": len(models),
        "present": present_count,
        "absent": len(models) - present_count,
    }

    # 5. Вывод
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

    files = find_model_files(config.models_dir)
    state = load_state(config.state_path)

    models = []
    for file_path in files:
        relative = file_path.relative_to(config.models_dir)
        st = file_path.stat()
        state_entry = state.get(str(relative))

        # Статус в реестре
        if state_entry is None:
            registry_status = "new"
        elif state_entry.get("size") != st.st_size:
            registry_status = "modified"
        else:
            registry_status = "verified"

        if new_only and registry_status != "new":
            continue

        models.append({
            "name": file_path.name,
            "path": str(relative),
            "size": st.st_size,
            "size_human": format_size(st.st_size),
            "registry_status": registry_status,
        })

    models.sort(key=lambda x: x["path"])

    summary = {
        "total": len(models),
        "verified": sum(1 for m in models if m["registry_status"] == "verified"),
        "new": sum(1 for m in models if m["registry_status"] == "new"),
        "modified": sum(1 for m in models if m["registry_status"] == "modified"),
        "total_size": sum(m["size"] for m in models),
        "total_size_human": format_size(sum(m["size"] for m in models)),
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
    # 1. Определить список файлов
    if all_files:
        if not config.models_dir.is_dir():
            logger.error("models_dir_not_found", extra={'extra_data': {'path': paths}})
            return 1
        files = find_model_files(config.models_dir)
    elif paths:
        files = [Path(p) for p in paths]
        # проверить, что все существуют
        for f in files:
            if not f.is_file():
                logger.error("file_not_found", extra={"extra_data": {"path": str(f)}})
                return 1
    else:
        logger.error("no_files_specified", extra={'extra_data': {'path': paths}})
        return 1

    if not files:
        logger.warning("no_files_found", extra={'extra_data': {'path': paths}})
        return 0

    # 2. Получить проверки
    try:
        checks = get_checks(check_names)
    except ValueError as e:
        logger.error("invalid_check", extra={'extra_data': {'check': str(e)}})
        return 1

    # 3. Запустить проверки для каждого файла (context=None!)
    results = []
    for file_path in files:
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
            try:
                res = check.run(file_path, context=None)  # ← context=None!
            except Exception as e:
                res = CheckResult(status="fail", message=f"Check crashed: {e}")
            file_res["checks"][check.name] = res

        results.append(file_res)

    # 4. Вывод
    if as_json:
        _print_inspect_json(results)
    else:
        _print_inspect_table(results)

    return 0


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
                for k, v in check_res.details.items():
                    # пропускаем "error", если он уже в message
                    if k == "error" and str(v) in check_res.message:
                        continue
                    print(f"     {k}: {v}")
            print()


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


def compute_checks_status(state_entry: dict | None, file_size: int) -> dict:
    """Возвращает {check_name: status} для одного файла.

    Statuses: "pass" | "fail" | "warn" | "skip" | "stale" | "unknown"
    """
    if state_entry is None:
        return {}  # нет данных — колонок не будет

    checks = state_entry.get("checks", {})
    result = {}

    # Если размер изменился — все проверки устарели
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


PRESENCE_LABELS = {
    True:  "[green][+][/green]",
    False: "[dim][-][/dim]",
}


def _print_list_table(models_dir, models, summary):
    console = Console()
    console.print(f"\n📁 Реестр проверенных моделей\n")
    console.print(f"Всего записей: {summary['total']}\n")

    if not models:
        console.print("[yellow]Реестр пуст. Запусти init или audit.[/yellow]")
        return

    # Собираем все check_names
    all_checks = set()
    for m in models:
        all_checks.update(m["checks"].keys())
    check_names = sorted(all_checks)

    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=3)
    table.add_column("Имя")
    table.add_column("Размер", justify="right")
    table.add_column("Наличие", justify="center")
    for name in check_names:
        table.add_column(name, justify="center")
    table.add_column("Последняя проверка", justify="right")

    for i, m in enumerate(models, 1):
        row = [
            str(i),
            m["name"],
            m["size_human"],
            PRESENCE_LABELS[m["present"]],
        ]
        for name in check_names:
            status = m["checks"].get(name, "unknown")
            row.append(STATUS_LABELS.get(status, status))
        row.append(_format_last_audit(m.get("last_audit")))
        table.add_row(*row)

    console.print(table)

    # Сводка
    console.print(
        f"\nИтого: {summary['total']} записей, "
        f"{summary['present']} на диске, {summary['absent']} отсутствуют"
    )



def _print_list_json(models_dir, models, summary):
    output = {
        "models_dir": str(models_dir),
        "summary": summary,
        "models": models,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


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
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=3)
    table.add_column("Имя")
    table.add_column("Размер", justify="right")
    table.add_column("Реестр", justify="center")

    for i, m in enumerate(models, 1):
        table.add_row(
            str(i),
            m["name"],
            m["size_human"],
            REGISTRY_LABELS[m["registry_status"]],
        )

    console.print(table)

    # Сводка
    parts = []
    if summary["verified"]:
        parts.append(f"{summary['verified']} проверен" + ("о" if summary['verified'] > 1 else ""))
    if summary["new"]:
        parts.append(f"{summary['new']} новый" + ("х" if summary['new'] > 1 else ""))
    if summary["modified"]:
        parts.append(f"{summary['modified']} изменён" + ("о" if summary['modified'] > 1 else ""))
    if parts:
        console.print(f"\nИтого: {', '.join(parts)}")


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



def run_checks(
    models_dir: Path,
    checks: list,
    logger: logging.Logger,
    etalon: dict | None = None,
    progress: "ProgressReporter | None" = None,
) -> dict:
    """Запускает проверки для всех файлов. Возвращает {path: {check_name: CheckResult}}."""
    if not models_dir.is_dir():
        logger.error('models_dir_not_found', extra={'extra_data': {
            'path': str(models_dir)
        }})
        raise FileNotFoundError(f'Файл не найден: {models_dir}')
    files = find_model_files(models_dir)
    if not files:
        logger.warning('no_models_found', extra={'extra_data': {
            'path': str(models_dir)
        }})
        return {}
    logger.info('scan_started', extra={'count': len(files)})
    if progress:
        progress.start([(f.name, f.stat().st_size) for f in files])
    result = {}
    for i, file in enumerate(files):
        relative = file.relative_to(models_dir)
        file_results = {}

        if progress:
            progress.start_file(i)

        for check in checks:
            if not check.supports(file):
                file_results[check.name] = CheckResult(
                    status='skip',
                    message=f'Not supported for {file.suffix}',
                )
                continue
            context = etalon.get(str(relative)) if etalon else None

            if progress:
                progress.start_check(check.name)
            try:
                res = check.run(file, context=context, progress=progress)
            except Exception as e:
                res = CheckResult(status='fail', message=f'Check crashed: {e}')

            file_results[check.name] = res
            logger.debug('check_done', extra={
                'path': str(relative),
                'check': check.name,
                'status': res.status
            })
        result[str(relative)] = file_results
        if progress:
            progress.finish_file()
    if progress:
        progress.finish()
    logger.info('scan_finished', extra={'count': len(result)})
    return result


def extract_hash_size(results: dict) -> dict:
    flat = {}
    for path, checks_res in results.items():
        hash_res = checks_res.get("hash")
        if not hash_res:
            continue
        details = hash_res.details
        if "hash" in details and "size" in details:
            # pass / warn
            flat[path] = {"hash": details["hash"], "size": details["size"]}
        elif "actual" in details:
            # fail: берём actual
            flat[path] = {
                "hash": details["actual"].get("hash"),
                "size": details["actual"].get("size"),
            }
    return flat


def _aggregate_checks(results: dict) -> dict:
    """
    Returns:
        {
            "hash": {"pass": 6, "fail": 0, "warn": 0, "skip": 0},
            "header": {"pass": 1, "fail": 3, "warn": 0, "skip": 2},
            "pickle": {"pass": 0, "fail": 1, "warn": 1, "skip": 4},
        }
    """
    agg = {}
    for path, checks_res in results.items():
        for check_name, check_res in checks_res.items():
            if check_name not in agg:
                agg[check_name] = {"pass": 0, "fail": 0, "warn": 0, "skip": 0}
            agg[check_name][check_res.status] += 1
    return agg


def _collect_issues(results: dict) -> tuple[dict, dict]:
    """
    Returns:
        (failures, warnings)
        failures = {"pickle": [{"path": "evil.pt", "message": "..."}], ...}
        warnings = {"pickle": [{"path": "safe.pt", "message": "..."}], ...}
    """
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










