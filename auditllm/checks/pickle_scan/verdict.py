"""VerdictAggregator: сборка CheckResult из findings с учётом политики.

Матрица политик:
  severity   | strict | balanced | permissive
  -----------+--------+----------+-----------
  critical   | fail   | fail     | fail
  major      | fail   | warn     | warn
  minor      | warn   | warn     | warn
  (нет)      | warn   | warn     | warn
"""
from __future__ import annotations

from auditllm.checks.base import CheckResult
from auditllm.checks.pickle_scan.rules import Finding, Policy, RuleContext


_SEVERITY_ORDER = {"critical": 3, "major": 2, "minor": 1}


class VerdictAggregator:
    """Собирает CheckResult из findings + метаданных обхода."""

    def build(
        self,
        findings: list[Finding],
        ctx: RuleContext,
        *,
        parse_warnings: list[dict],
        walk_info: dict,
    ) -> CheckResult:
        critical = [f for f in findings if f.severity == "critical"]
        major = [f for f in findings if f.severity == "major"]
        minor = [f for f in findings if f.severity == "minor"]

        policy: Policy = ctx.policy  # type: ignore[assignment]
        status = self._status_for(policy, critical, major, minor)

        dangerous = [self._finding_to_dict(f) for f in critical]
        warnings = (
            [self._finding_to_dict(f) for f in major]
            + [self._finding_to_dict(f) for f in minor]
            + list(parse_warnings)
        )

        max_sev = "minor"
        for f in findings:
            if _SEVERITY_ORDER[f.severity] > _SEVERITY_ORDER[max_sev]:
                max_sev = f.severity

        details = {
            **walk_info,
            "policy": policy,
            "findings_count": len(findings),
            "dangerous": dangerous,
            "warnings": warnings,
        }

        if status == "fail":
            return CheckResult(
                status="fail",
                message=(
                    f"Pickle safety issues: {len(critical)} critical, "
                    f"{len(major)} major, {len(minor)} minor"
                ),
                severity=max_sev,
                suggestion="⚠️ НЕ загружай файл: возможна RCE. Удали или проверь в песочнице (inspect --search)",
                details=details,
            )

        if status == "warn":
            return CheckResult(
                status="warn",
                message=(
                    f"Pickle parsed, {len(warnings)} warnings "
                    f"(policy={policy}, pickle is never fully safe)"
                ),
                severity=max_sev,
                suggestion="Проверь warnings вручную (inspect --search) — возможна обфускация",
                details=details,
            )

        # pass (в текущей матрице недостижим, но оставляем для будущего)
        return CheckResult(
            status="pass",
            message=f"Pickle parsed, no issues (policy={policy})",
            severity=max_sev,
            details=details,
        )

    # ── матрица политик ────────────────────────────────────────
    def _status_for(
        self,
        policy: Policy,
        critical: list[Finding],
        major: list[Finding],
        minor: list[Finding],
    ) -> str:
        if critical:
            return "fail"
        if policy == "strict":
            if major or minor:
                return "fail"
            return "warn"
        if policy == "balanced":
            if major or minor:
                return "warn"
            return "warn"
        if policy == "permissive":
            # только critical → fail (уже отсечено выше); всё остальное → warn
            return "warn"
        return "warn"

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict:
        return {
            "type": f.code,
            "category": f.code,
            "severity": f.severity,
            "message": f.message,
            "pos": f.pos,
            "module": f.module_attr,
            "inner_file": f.inner_file,
        }


