"""Rule definition shared by all baseline checks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ...core.config import Config
from ...models import Finding, Severity, SystemSnapshot


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    references: tuple[str, ...]
    evaluate: Callable[[SystemSnapshot, Config], Finding | None]
    prerequisite: Callable[[SystemSnapshot], str | None] | None = None


def finding(
    rule: Rule,
    evidence: dict[str, Any],
    remediation: str,
) -> Finding:
    return Finding(
        id=rule.id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        evidence=evidence,
        remediation=remediation,
        references=rule.references,
    )
