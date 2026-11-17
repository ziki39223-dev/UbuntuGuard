"""Audit report assembly and text rendering."""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..models import SystemSnapshot
from ..security.baseline.engine import AuditResult


def build_report(result: AuditResult, snapshot: SystemSnapshot) -> dict[str, Any]:
    host = snapshot.host
    os_label = host.os_pretty_name or f"{host.os_id} {host.os_version}"
    return {
        "schema_version": "1.0",
        "tool_version": __version__,
        "generated_at": result.generated_at,
        "host": {
            "hostname": host.hostname,
            "os": os_label,
            "kernel": host.kernel,
            "uptime_seconds": host.uptime_seconds,
        },
        "summary": {
            "score": result.score,
            "grade": result.grade,
            "total": len(result.findings),
            "by_severity": result.by_severity,
            "passed": result.passed,
            "evaluated": result.passed + len(result.findings),
            "skipped": len(result.skipped),
        },
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
            for item in result.findings
        ],
        "checks": {
            "total": result.rules_total,
            "passed": result.passed,
            "failed": len(result.findings),
            "skipped": len(result.skipped),
        },
        "skipped": list(result.skipped),
    }


def render_text(result: AuditResult, snapshot: SystemSnapshot) -> str:
    host = snapshot.host
    os_label = host.os_pretty_name or f"{host.os_id} {host.os_version}"
    evaluated = result.passed + len(result.findings)
    if evaluated:
        score_line = f"score: {result.score}/100 ({result.grade})"
    else:
        score_line = "score: n/a (no checks could be evaluated)"
    lines = [
        f"UbuntuGuard audit - {host.hostname}",
        f"os: {os_label}   kernel: {host.kernel}",
        "",
        f"{score_line}   "
        f"findings: {len(result.findings)}   "
        f"passed: {result.passed}   skipped: {len(result.skipped)}",
    ]

    counts = ", ".join(
        f"{severity} {count}"
        for severity, count in result.by_severity.items()
        if count
    )
    if counts:
        lines.append(f"by severity: {counts}")

    if result.findings:
        lines.extend(["", "findings:"])
        for item in result.findings:
            lines.append(f"  [{item.severity.value.upper()}] {item.id} {item.title}")
            evidence = json.dumps(item.evidence, ensure_ascii=False, sort_keys=True)
            lines.append(f"         evidence: {evidence}")
            lines.append(f"         remediation: {item.remediation}")
            if item.references:
                lines.append(f"         references: {', '.join(item.references)}")
    else:
        lines.extend(["", "no findings"])

    if result.skipped:
        lines.extend(["", "skipped:"])
        lines.extend(f"  {reason}" for reason in result.skipped)

    return "\n".join(lines)
