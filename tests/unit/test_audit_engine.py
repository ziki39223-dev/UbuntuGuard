"""Audit engine and scoring tests."""

from __future__ import annotations

from collections.abc import Callable

from ubuntuguard.core.config import Config
from ubuntuguard.models import Finding, Severity, SystemSnapshot
from ubuntuguard.security.baseline import run_audit
from ubuntuguard.security.baseline.rules import Rule
from ubuntuguard.security.baseline.scoring import (
    grade_for,
    meets_threshold,
    score_findings,
)
from ubuntuguard.security.ssh.rules import SSH_RULES


def _finding(severity: Severity, finding_id: str = "TEST-001") -> Finding:
    return Finding(
        id=finding_id,
        title="test finding",
        severity=severity,
        category="test",
    )


def _rule(
    rule_id: str,
    severity: Severity,
    outcome: Finding | None,
    prerequisite: Callable[[SystemSnapshot], str | None] | None = None,
) -> Rule:
    return Rule(
        id=rule_id,
        title=rule_id,
        severity=severity,
        category="test",
        references=(),
        evaluate=lambda _snapshot, _config: outcome,
        prerequisite=prerequisite,
    )


def test_score_and_grade() -> None:
    assert score_findings([]) == 100
    assert grade_for(100) == "A"

    critical = [_finding(Severity.CRITICAL)]
    assert score_findings(critical) == 75
    assert grade_for(75) == "B"

    many = [_finding(Severity.CRITICAL) for _ in range(5)]
    assert score_findings(many) == 0
    assert grade_for(0) == "E"


def test_meets_threshold() -> None:
    findings = [_finding(Severity.MEDIUM)]
    assert meets_threshold(findings, "low")
    assert meets_threshold(findings, "medium")
    assert not meets_threshold(findings, "high")
    assert not meets_threshold(findings, "none")


def test_engine_skips_unavailable_ssh(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    result = run_audit(make_snapshot(), config, rules=SSH_RULES)
    assert result.findings == ()
    assert result.passed == 0
    assert len(result.skipped) == len(SSH_RULES)
    assert result.score == 0
    assert result.grade == "N/A"
    assert result.rules_total == len(SSH_RULES)


def test_engine_appends_cis_references(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    finding = Finding(
        id="SSH-001",
        title="root login",
        severity=Severity.HIGH,
        category="ssh",
    )
    rule = Rule(
        id="SSH-001",
        title="root login",
        severity=Severity.HIGH,
        category="ssh",
        references=(),
        evaluate=lambda _snapshot, _config: finding,
    )
    result = run_audit(make_snapshot(), config, rules=(rule,))
    assert any("5.1.20" in reference for reference in result.findings[0].references)


def test_engine_orders_findings_and_isolates_failures(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    def boom(_snapshot: SystemSnapshot, _config: Config) -> Finding | None:
        raise RuntimeError("broken rule")

    rules = (
        _rule("T-001", Severity.LOW, _finding(Severity.LOW, "T-001")),
        _rule("T-002", Severity.CRITICAL, _finding(Severity.CRITICAL, "T-002")),
        _rule("T-003", Severity.INFO, None),
        Rule(
            id="T-004",
            title="T-004",
            severity=Severity.HIGH,
            category="test",
            references=(),
            evaluate=boom,
        ),
        _rule("T-005", Severity.HIGH, None, prerequisite=lambda _snapshot: "not applicable"),
    )

    result = run_audit(make_snapshot(), config, rules=rules)
    assert [item.id for item in result.findings] == ["T-002", "T-001"]
    assert result.passed == 1
    assert result.score == 100 - 25 - 2
    assert result.grade == "C"
    assert any(item.startswith("T-004:") for item in result.skipped)
    assert any(item.startswith("T-005:") for item in result.skipped)
    assert result.by_severity["critical"] == 1
    assert result.by_severity["low"] == 1
