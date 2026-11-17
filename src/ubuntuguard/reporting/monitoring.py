"""Monitoring report assembly and text rendering."""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..monitoring.health import HealthReport


def build_monitoring_report(report: HealthReport) -> dict[str, Any]:
    metrics = report.metrics
    return {
        "schema_version": "1.0",
        "tool_version": __version__,
        "generated_at": report.generated_at,
        "metrics_source": metrics.source,
        "metrics": {
            "cpu_percent": metrics.cpu_percent,
            "memory_percent": metrics.memory_percent,
            "load_per_core": metrics.load_per_core,
            "disk_usage": [
                {"mount": mount, "used_percent": percent}
                for mount, percent in metrics.disk_usage
            ],
            "services": [
                {"name": name, "active": active}
                for name, active in metrics.services
            ],
            "errors": list(metrics.errors),
        },
        "checks": [
            {
                "name": check.name,
                "status": check.status,
                "value": check.value,
                "threshold": check.threshold,
                "detail": check.detail,
            }
            for check in report.checks
        ],
        "findings": [
            {
                "id": item.id,
                "title": item.title,
                "severity": item.severity.value,
                "category": item.category,
                "evidence": item.evidence,
                "remediation": item.remediation,
                "references": list(item.references),
            }
            for item in report.findings
        ],
        "events_written": report.events_written,
    }


def render_monitoring_text(report: HealthReport) -> str:
    lines = [
        "UbuntuGuard monitoring",
        f"generated: {report.generated_at}",
        f"source: {report.metrics.source}",
        "",
        "checks:",
    ]
    for check in report.checks:
        value = "-" if check.value is None else str(check.value)
        threshold = "-" if check.threshold is None else str(check.threshold)
        lines.append(
            f"  [{check.status.upper()}] {check.name:<16} "
            f"value={value} threshold={threshold} {check.detail}"
        )

    if report.findings:
        lines.extend(["", "findings:"])
        for item in report.findings:
            lines.append(f"  [{item.severity.value.upper()}] {item.id} {item.title}")
            evidence = json.dumps(item.evidence, ensure_ascii=False, sort_keys=True)
            lines.append(f"         evidence: {evidence}")
            lines.append(f"         remediation: {item.remediation}")
    else:
        lines.extend(["", "no findings"])

    if report.metrics.errors:
        lines.extend(["", "errors:"])
        lines.extend(f"  {error}" for error in report.metrics.errors)

    return "\n".join(lines)
