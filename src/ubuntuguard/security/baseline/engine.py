"""Run baseline rules against a snapshot."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from ...core.config import Config
from ...models import Finding, SystemSnapshot
from .cis_map import references_for
from .registry import ALL_RULES
from .rules import Rule
from .scoring import SEVERITY_RANK, grade_for, score_findings, severity_breakdown


@dataclass(frozen=True)
class AuditResult:
    findings: tuple[Finding, ...]
    passed: int
    skipped: tuple[str, ...]
    score: int
    grade: str
    by_severity: dict[str, int]
    generated_at: str
    rules_total: int


def run_audit(
    snapshot: SystemSnapshot,
    config: Config,
    rules: Sequence[Rule] | None = None,
    extra_findings: Sequence[Finding] = (),
    extra_skipped: Sequence[str] = (),
    extra_evaluated: int = 0,
) -> AuditResult:
    selected = tuple(rules) if rules is not None else ALL_RULES
    findings: list[Finding] = []
    skipped: list[str] = list(extra_skipped)
    passed = 0

    for rule in selected:
        if rule.prerequisite is not None:
            reason = rule.prerequisite(snapshot)
            if reason:
                skipped.append(f"{rule.id}: {reason}")
                continue
        try:
            outcome = rule.evaluate(snapshot, config)
        except Exception as exc:  # one broken rule must not abort the audit
            skipped.append(f"{rule.id}: evaluation failed: {exc}")
            continue
        if outcome is None:
            passed += 1
        else:
            cis = references_for(outcome.id)
            if cis:
                outcome = replace(outcome, references=outcome.references + cis)
            findings.append(outcome)

    findings.extend(extra_findings)
    findings.sort(key=lambda item: SEVERITY_RANK[item.severity], reverse=True)
    evaluated = passed + len(findings) + extra_evaluated
    if evaluated == 0:
        score = 0
        grade = "N/A"
    else:
        score = score_findings(findings)
        grade = grade_for(score)

    return AuditResult(
        findings=tuple(findings),
        passed=passed,
        skipped=tuple(skipped),
        score=score,
        grade=grade,
        by_severity=severity_breakdown(findings),
        generated_at=datetime.now(tz=timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds"),
        rules_total=len(selected),
    )
