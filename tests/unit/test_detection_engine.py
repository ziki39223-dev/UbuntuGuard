"""Detection orchestrator tests."""

from __future__ import annotations

from pathlib import Path

from ubuntuguard.audit import run_detection
from ubuntuguard.audit.detector import DetectionResult
from ubuntuguard.core.config import Config
from ubuntuguard.models import CommandResult, Finding, Severity
from ubuntuguard.reporting import build_detection_report, render_detection_text


def _write_failures(path: Path, count: int, ip: str = "203.0.113.5") -> None:
    lines = [
        f"May  1 10:00:{index:02d} host sshd[1]: Failed password for root "
        f"from {ip} port {1000 + index} ssh2"
        for index in range(count)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_brute_force_detection(
    tmp_path: Path, config: Config, fake_executor
) -> None:
    auth_log = tmp_path / "auth.log"
    _write_failures(auth_log, 10)
    state_dir = tmp_path / "state"

    result = run_detection(
        fake_executor,
        config,
        auth_log_path=auth_log,
        state_dir=state_dir,
        proc_root=tmp_path / "proc",
        auditd_sources=(tmp_path / "rules",),
        aide_candidates=(tmp_path / "aide.db",),
    )

    finding = next((item for item in result.findings if item.id == "LOG-001"), None)
    assert finding is not None
    assert finding.severity is Severity.HIGH
    assert result.summary["auth"]["failed"] == 10
    assert result.events_written == len(result.findings)
    assert (state_dir / "events.jsonl").is_file()


def test_root_password_login_detection(
    tmp_path: Path, config: Config, fake_executor
) -> None:
    auth_log = tmp_path / "auth.log"
    auth_log.write_text(
        "May  1 10:00:03 host sshd[1]: Accepted password for root "
        "from 198.51.100.7 port 6666 ssh2\n",
        encoding="utf-8",
    )

    result = run_detection(
        fake_executor,
        config,
        auth_log_path=auth_log,
        state_dir=tmp_path / "state",
        proc_root=tmp_path / "proc",
        auditd_sources=(tmp_path / "rules",),
        aide_candidates=(tmp_path / "aide.db",),
    )
    assert any(item.id == "LOG-002" for item in result.findings)


def test_auditd_inactive_and_missing_watches(
    tmp_path: Path, config: Config, fake_executor
) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "99-guard.rules").write_text(
        "-a always,exit -F arch=b64 -S execve -k exec\n", encoding="utf-8"
    )
    fake_executor.responses[("systemctl", "is-active", "auditd")] = CommandResult(
        argv=("systemctl", "is-active", "auditd"),
        returncode=3,
        stdout="inactive\n",
    )

    result = run_detection(
        fake_executor,
        config,
        auth_log_path=tmp_path / "missing.log",
        state_dir=tmp_path / "state",
        proc_root=tmp_path / "proc",
        auditd_sources=(rules_dir,),
        aide_candidates=(tmp_path / "aide.db",),
    )
    ids = {item.id for item in result.findings}
    assert "AUD-002" in ids
    assert "AUD-003" in ids


def test_suspicious_process_detection(
    tmp_path: Path, config: Config, fake_executor
) -> None:
    proc = tmp_path / "proc"
    pid_dir = proc / "42"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cmdline").write_bytes(b"/tmp/backdoor\x00--listen\x00")

    result = run_detection(
        fake_executor,
        config,
        auth_log_path=tmp_path / "missing.log",
        state_dir=tmp_path / "state",
        proc_root=proc,
        auditd_sources=(tmp_path / "rules",),
        aide_candidates=(tmp_path / "aide.db",),
    )
    assert any(item.id == "PROC-001" for item in result.findings)


def test_baseline_initialization_and_missing_note(
    tmp_path: Path, config: Config, fake_executor
) -> None:
    state_dir = tmp_path / "state"
    run_detection(
        fake_executor,
        config,
        auth_log_path=tmp_path / "missing.log",
        state_dir=state_dir,
        init_baseline=True,
        proc_root=tmp_path / "proc",
        auditd_sources=(tmp_path / "rules",),
        aide_candidates=(tmp_path / "aide.db",),
    )
    assert (state_dir / "file_baseline.json").is_file()

    second = run_detection(
        fake_executor,
        config,
        auth_log_path=tmp_path / "missing.log",
        state_dir=tmp_path / "fresh-state",
        proc_root=tmp_path / "proc",
        auditd_sources=(tmp_path / "rules",),
        aide_candidates=(tmp_path / "aide.db",),
    )
    assert any("not initialized" in reason for reason in second.skipped)


def test_detection_report_rendering() -> None:
    result = DetectionResult(
        findings=(
            Finding(
                id="LOG-001",
                title="Repeated SSH authentication failures",
                severity=Severity.HIGH,
                category="auth",
                evidence={"top_failure_ips": [{"ip": "203.0.113.5", "count": 10}]},
                remediation="Block the source addresses",
            ),
        ),
        skipped=("authlog: unavailable",),
        summary={
            "auth": {"source": "file", "failed": 10, "accepted": 0},
            "auditd": {"available": False, "active": False, "rule_count": 0},
            "aide": {"installed": False, "database_present": False},
            "processes": {"suspicious": 0},
            "file_baseline": {"initialized": 0, "changes": []},
        },
        generated_at="2026-11-17T00:00:00+08:00",
        events_written=1,
    )

    report = build_detection_report(result)
    assert report["schema_version"] == "1.0"
    assert report["findings"][0]["id"] == "LOG-001"
    assert report["events_written"] == 1

    text = render_detection_text(result)
    assert "UbuntuGuard detection" in text
    assert "[HIGH] LOG-001" in text
    assert "skipped:" in text
    assert "authlog: unavailable" in text
