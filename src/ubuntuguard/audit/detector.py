"""Detection orchestrator: authentication, integrity, processes, file baseline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.config import Config
from ..core.executor import CommandExecutor
from ..models import Finding, Severity
from ..security.baseline.cis_map import references_for
from .authlog import DEFAULT_AUTH_LOG, AuthLogInfo, collect_auth_log, summarize_auth
from .events import EventLog
from .file_baseline import DEFAULT_WATCHED_FILES, FileBaseline, FileChange
from .integrity import (
    DEFAULT_AIDE_DATABASES,
    DEFAULT_RULE_SOURCES,
    AideStatus,
    AuditdStatus,
    collect_aide,
    collect_auditd,
)
from .processes import SuspiciousProcess, detect_suspicious_processes

BASELINE_FILENAME = "file_baseline.json"
EVENTS_FILENAME = "events.jsonl"


@dataclass(frozen=True)
class DetectionResult:
    findings: tuple[Finding, ...]
    skipped: tuple[str, ...]
    summary: dict[str, Any]
    generated_at: str
    events_written: int = 0
    baseline_initialized: int = 0


def run_detection(
    executor: CommandExecutor,
    config: Config,
    *,
    auth_log_path: Path = DEFAULT_AUTH_LOG,
    state_dir: Path | None = None,
    init_baseline: bool = False,
    proc_root: Path = Path("/proc"),
    auditd_sources: tuple[Path, ...] = DEFAULT_RULE_SOURCES,
    aide_candidates: tuple[Path, ...] = DEFAULT_AIDE_DATABASES,
) -> DetectionResult:
    findings: list[Finding] = []
    skipped: list[str] = []

    auth = collect_auth_log(executor, auth_log_path)
    findings.extend(_auth_findings(auth))
    if not auth.readable:
        skipped.append(f"authlog: {auth.note or 'unavailable'}")
    auth_summary = summarize_auth(auth.events) if auth.readable else {}

    auditd = collect_auditd(executor, auditd_sources)
    findings.extend(_auditd_findings(auditd))

    aide = collect_aide(aide_candidates)
    findings.extend(_aide_findings(aide))

    suspicious: tuple[SuspiciousProcess, ...] = ()
    if proc_root.is_dir():
        suspicious = detect_suspicious_processes(proc_root)
        findings.extend(_process_findings(suspicious))
    else:
        skipped.append("processes: /proc not available")

    baseline_initialized = 0
    file_changes: tuple[FileChange, ...] = ()
    if state_dir is None:
        skipped.append("file_baseline: state directory unavailable")
    else:
        baseline = FileBaseline(state_dir / BASELINE_FILENAME)
        if init_baseline:
            baseline_initialized = baseline.initialize(DEFAULT_WATCHED_FILES)
        elif not baseline.exists:
            skipped.append(
                "file_baseline: not initialized "
                "(run 'ubuntuguard detect --init-baseline')"
            )
        else:
            file_changes = baseline.compare(DEFAULT_WATCHED_FILES)
            findings.extend(_file_findings(file_changes))

    findings.sort(key=_severity_rank, reverse=True)

    events_written = 0
    if state_dir is not None:
        events_written = EventLog(state_dir / EVENTS_FILENAME).append(findings)

    summary: dict[str, Any] = {
        "auth": {"source": auth.source, "readable": auth.readable, **auth_summary},
        "auditd": {
            "available": auditd.available,
            "active": auditd.active,
            "rule_count": auditd.rule_count,
            "watched_paths": list(auditd.watched_paths),
        },
        "aide": {
            "installed": aide.installed,
            "database_present": aide.database_present,
            "database_path": aide.database_path,
            "last_modified": aide.last_modified,
        },
        "processes": {"suspicious": len(suspicious)},
        "file_baseline": {
            "initialized": baseline_initialized,
            "changes": [
                {"path": change.path, "status": change.status}
                for change in file_changes
            ],
        },
        "events_written": events_written,
    }

    return DetectionResult(
        findings=tuple(findings),
        skipped=tuple(skipped),
        summary=summary,
        generated_at=datetime.now(tz=timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds"),
        events_written=events_written,
        baseline_initialized=baseline_initialized,
    )


def _auth_findings(auth: AuthLogInfo) -> list[Finding]:
    if not auth.readable:
        return []
    findings: list[Finding] = []
    data = summarize_auth(auth.events)

    top_ips = data["top_failure_ips"]
    if isinstance(top_ips, list) and top_ips:
        top = top_ips[0]
        count = int(str(top.get("count", 0))) if isinstance(top, dict) else 0
        if count >= 10:
            severity = Severity.HIGH
        elif count >= 5:
            severity = Severity.MEDIUM
        else:
            severity = None
        if severity is not None:
            findings.append(
                _finding(
                    "LOG-001",
                    "Repeated SSH authentication failures",
                    severity,
                    "auth",
                    {"top_failure_ips": top_ips, "source": auth.source},
                    "Block the source addresses and enforce key-only authentication",
                )
            )

    if any(
        event.kind == "accepted" and event.user == "root" and event.method == "password"
        for event in auth.events
    ):
        findings.append(
            _finding(
                "LOG-002",
                "Root logged in with a password",
                Severity.HIGH,
                "auth",
                {"source": auth.source},
                "Disable password authentication and root login in sshd",
            )
        )

    distinct = int(str(data["distinct_invalid_users"]))
    if distinct >= 10:
        findings.append(
            _finding(
                "LOG-003",
                "SSH user enumeration detected",
                Severity.MEDIUM,
                "auth",
                {"distinct_invalid_users": distinct, "source": auth.source},
                "Restrict SSH access and consider Fail2ban",
            )
        )
    return findings


def _auditd_findings(status: AuditdStatus) -> list[Finding]:
    findings: list[Finding] = []
    if not status.available:
        findings.append(
            _finding(
                "AUD-001",
                "auditd is not available",
                Severity.MEDIUM,
                "auditd",
                {"rule_count": 0},
                "Install auditd and enable the audit service",
            )
        )
        return findings

    if not status.active:
        findings.append(
            _finding(
                "AUD-002",
                "auditd service is not active",
                Severity.MEDIUM,
                "auditd",
                {"rule_count": status.rule_count},
                "Enable and start auditd: 'systemctl enable --now auditd'",
            )
        )

    watched = status.watched_paths
    missing = [
        path
        for path in ("/etc/sudoers", "/etc/ssh")
        if not any(item == path or item.startswith(f"{path}/") for item in watched)
    ]
    if missing:
        findings.append(
            _finding(
                "AUD-003",
                "auditd does not watch sensitive paths",
                Severity.LOW,
                "auditd",
                {"missing_watches": missing, "watched_paths": list(watched)},
                "Add -w rules for /etc/sudoers and /etc/ssh in audit rules",
            )
        )
    return findings


def _aide_findings(status: AideStatus) -> list[Finding]:
    if not status.installed:
        return [
            _finding(
                "AID-001",
                "AIDE is not installed",
                Severity.LOW,
                "integrity",
                {"installed": False},
                "Install AIDE and initialize its database for integrity monitoring",
            )
        ]
    if not status.database_present:
        return [
            _finding(
                "AID-002",
                "AIDE database is missing",
                Severity.LOW,
                "integrity",
                {"installed": True, "database_present": False},
                "Initialize the AIDE database: 'aideinit'",
            )
        ]
    return []


def _process_findings(suspicious: tuple[Any, ...]) -> list[Finding]:
    if not suspicious:
        return []
    evidence = [
        {"pid": item.pid, "exe": item.exe, "reason": item.reason, "command": item.command}
        for item in suspicious[:10]
    ]
    return [
        _finding(
            "PROC-001",
            "Suspicious processes detected",
            Severity.HIGH,
            "processes",
            {"processes": evidence, "total": len(suspicious)},
            "Investigate the listed processes and remove unauthorized binaries",
        )
    ]


def _file_findings(changes: tuple[FileChange, ...]) -> list[Finding]:
    findings: list[Finding] = []
    dangerous = [
        {"path": change.path, "status": change.status}
        for change in changes
        if change.status in {"changed", "missing"}
    ]
    if dangerous:
        findings.append(
            _finding(
                "FILE-001",
                "Critical files changed or missing",
                Severity.HIGH,
                "integrity",
                {"changes": dangerous},
                "Review the changes; restore from a trusted backup if unauthorized",
            )
        )
    added = [
        {"path": change.path}
        for change in changes
        if change.status == "added"
    ]
    if added:
        findings.append(
            _finding(
                "FILE-002",
                "New files appeared in watched paths",
                Severity.LOW,
                "integrity",
                {"added": added},
                "Confirm the new files are expected",
            )
        )
    return findings


def _finding(
    finding_id: str,
    title: str,
    severity: Severity,
    category: str,
    evidence: dict[str, Any],
    remediation: str,
) -> Finding:
    references = references_for(finding_id) or (
        "CIS Ubuntu 24.04/22.04 §6 Logging and Auditing",
    )
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category=category,
        evidence=evidence,
        remediation=remediation,
        references=references,
    )


def _severity_rank(finding: Finding) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[finding.severity]
