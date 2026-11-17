"""Health checks based on collected metrics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..audit.events import EventLog
from ..core.config import Config
from ..models import Finding, Severity
from .metrics import Metrics


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    value: float | None = None
    threshold: float | None = None
    detail: str = ""


@dataclass(frozen=True)
class HealthReport:
    checks: tuple[CheckResult, ...]
    findings: tuple[Finding, ...]
    metrics: Metrics
    generated_at: str
    events_written: int = 0


def evaluate_health(
    metrics: Metrics,
    config: Config,
    state_dir: Path | None = None,
) -> HealthReport:
    thresholds = config.get("monitoring.thresholds", {}) or {}
    cpu_threshold = float(thresholds.get("cpu_percent", 85))
    memory_threshold = float(thresholds.get("memory_percent", 85))
    disk_threshold = float(thresholds.get("disk_percent", 85))
    load_threshold = float(thresholds.get("load_per_core", 1.5))

    checks: list[CheckResult] = []
    findings: list[Finding] = []

    _check_threshold(
        "cpu",
        metrics.cpu_percent,
        cpu_threshold,
        "%",
        "HEALTH-001",
        "CPU usage is above threshold",
        Severity.HIGH,
        "Investigate CPU consumers or resize the host",
        metrics.source,
        checks,
        findings,
    )
    _check_threshold(
        "memory",
        metrics.memory_percent,
        memory_threshold,
        "%",
        "HEALTH-002",
        "Memory usage is above threshold",
        Severity.HIGH,
        "Investigate memory consumers or add swap/memory",
        metrics.source,
        checks,
        findings,
    )
    for mount, percent in metrics.disk_usage:
        _check_threshold(
            f"disk:{mount}",
            percent,
            disk_threshold,
            "%",
            "HEALTH-003",
            f"Disk usage on {mount} is above threshold",
            Severity.HIGH,
            "Clean up disk space or extend the filesystem",
            metrics.source,
            checks,
            findings,
        )
    _check_threshold(
        "load",
        metrics.load_per_core,
        load_threshold,
        "",
        "HEALTH-004",
        "System load per core is above threshold",
        Severity.MEDIUM,
        "Identify CPU-bound or blocked processes",
        metrics.source,
        checks,
        findings,
    )

    for service, active in metrics.services:
        name = f"service:{service}"
        if active is None:
            checks.append(
                CheckResult(name, "skipped", detail="service state unavailable")
            )
        elif active:
            checks.append(CheckResult(name, "ok", 1.0, 1.0, "active"))
        else:
            checks.append(CheckResult(name, "critical", 0.0, 1.0, "inactive"))
            findings.append(
                Finding(
                    id="HEALTH-005",
                    title=f"Service {service} is not active",
                    severity=Severity.HIGH,
                    category="monitoring",
                    evidence={"service": service, "source": metrics.source},
                    remediation=f"Start the service: systemctl start {service}",
                    references=("CIS Ubuntu 22.04/24.04 §1 System Maintenance",),
                )
            )

    findings.sort(key=_severity_rank, reverse=True)
    events_written = 0
    if state_dir is not None:
        events_written = EventLog(state_dir / "events.jsonl").append(findings)

    return HealthReport(
        checks=tuple(checks),
        findings=tuple(findings),
        metrics=metrics,
        generated_at=datetime.now(tz=timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds"),
        events_written=events_written,
    )


def _check_threshold(
    name: str,
    value: float | None,
    threshold: float,
    unit: str,
    finding_id: str,
    title: str,
    severity: Severity,
    remediation: str,
    source: str,
    checks: list[CheckResult],
    findings: list[Finding],
) -> None:
    if value is None:
        checks.append(
            CheckResult(name, "skipped", threshold=threshold, detail="metric unavailable")
        )
        return
    if value > threshold:
        checks.append(
            CheckResult(
                name,
                "critical",
                value,
                threshold,
                f"{value}{unit} > {threshold}{unit}",
            )
        )
        findings.append(
            Finding(
                id=finding_id,
                title=title,
                severity=severity,
                category="monitoring",
                evidence={
                    "metric": name,
                    "value": value,
                    "threshold": threshold,
                    "source": source,
                },
                remediation=remediation,
                references=("CIS Ubuntu 22.04/24.04 §1 System Maintenance",),
            )
        )
        return
    checks.append(
        CheckResult(name, "ok", value, threshold, f"{value}{unit} <= {threshold}{unit}")
    )


def _severity_rank(finding: Finding) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[finding.severity]
