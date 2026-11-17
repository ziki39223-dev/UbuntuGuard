"""Detection report assembly and text rendering."""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..audit.detector import DetectionResult


def build_detection_report(result: DetectionResult) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "tool_version": __version__,
        "generated_at": result.generated_at,
        "summary": result.summary,
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
        "skipped": list(result.skipped),
        "baseline_initialized": result.baseline_initialized,
        "events_written": result.events_written,
    }


def render_detection_text(result: DetectionResult) -> str:
    lines = ["UbuntuGuard detection", f"generated: {result.generated_at}", ""]
    lines.append(
        f"findings: {len(result.findings)}   skipped: {len(result.skipped)}   "
        f"events_written: {result.events_written}"
    )
    if result.baseline_initialized:
        lines.append(f"file baseline initialized: {result.baseline_initialized} files")

    auth = result.summary.get("auth", {})
    lines.append(
        "ssh auth : source={source} failed={failed} accepted={accepted}".format(
            source=auth.get("source", "-"),
            failed=auth.get("failed", "-"),
            accepted=auth.get("accepted", "-"),
        )
    )
    auditd = result.summary.get("auditd", {})
    lines.append(
        "auditd   : available={available} active={active} rules={rules}".format(
            available=auditd.get("available", "-"),
            active=auditd.get("active", "-"),
            rules=auditd.get("rule_count", "-"),
        )
    )
    aide = result.summary.get("aide", {})
    lines.append(
        "aide     : installed={installed} database={database}".format(
            installed=aide.get("installed", "-"),
            database=aide.get("database_present", "-"),
        )
    )
    processes = result.summary.get("processes", {})
    lines.append(f"processes: suspicious={processes.get('suspicious', '-')}")

    baseline = result.summary.get("file_baseline", {})
    changes = baseline.get("changes", [])
    lines.append(f"baseline : changes={len(changes)}")

    if result.findings:
        lines.extend(["", "findings:"])
        for item in result.findings:
            lines.append(f"  [{item.severity.value.upper()}] {item.id} {item.title}")
            evidence = json.dumps(item.evidence, ensure_ascii=False, sort_keys=True)
            lines.append(f"         evidence: {evidence}")
            lines.append(f"         remediation: {item.remediation}")
    else:
        lines.extend(["", "no findings"])

    if result.skipped:
        lines.extend(["", "skipped:"])
        lines.extend(f"  {reason}" for reason in result.skipped)

    return "\n".join(lines)
