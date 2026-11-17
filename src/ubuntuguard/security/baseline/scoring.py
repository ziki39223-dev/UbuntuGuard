"""Risk scoring for audit findings."""

from __future__ import annotations

from collections.abc import Sequence

from ...models import Finding, Severity

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def score_findings(findings: Sequence[Finding]) -> int:
    deduction = sum(DEDUCTIONS[finding.severity] for finding in findings)
    return max(0, 100 - deduction)


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "E"


def severity_breakdown(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def meets_threshold(findings: Sequence[Finding], fail_on: str) -> bool:
    """True when at least one finding is at or above the configured level."""
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[Severity(fail_on)]
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings)
