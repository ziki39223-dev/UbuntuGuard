"""Report rendering tests."""

from __future__ import annotations

from collections.abc import Callable

from ubuntuguard.core.config import Config
from ubuntuguard.models import Finding, Severity, SystemSnapshot
from ubuntuguard.reporting import build_report, render_text
from ubuntuguard.security.baseline import run_audit
from ubuntuguard.security.baseline.rules import Rule


def _test_rule() -> Rule:
    finding = Finding(
        id="TEST-001",
        title="Example finding",
        severity=Severity.HIGH,
        category="test",
        evidence={"path": "/etc/example", "line": 7},
        remediation="Fix the example",
        references=("CIS test",),
    )
    return Rule(
        id="TEST-001",
        title="Example finding",
        severity=Severity.HIGH,
        category="test",
        references=("CIS test",),
        evaluate=lambda _snapshot, _config: finding,
    )


def test_build_report_structure(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    result = run_audit(make_snapshot(), config, rules=(_test_rule(),))
    report = build_report(result, make_snapshot())

    assert report["schema_version"] == "1.0"
    assert report["host"]["hostname"] == "test-host"
    assert report["summary"]["score"] == 85
    assert report["summary"]["grade"] == "B"
    assert report["summary"]["total"] == 1
    assert report["findings"][0]["id"] == "TEST-001"
    assert report["checks"]["failed"] == 1
    assert report["summary"]["evaluated"] == 1
    assert report["skipped"] == []


def test_render_text_contains_findings(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot()
    result = run_audit(snapshot, config, rules=(_test_rule(),))
    text = render_text(result, snapshot)

    assert "UbuntuGuard audit" in text
    assert "score: 85/100 (B)" in text
    assert "[HIGH] TEST-001 Example finding" in text
    assert "Fix the example" in text
