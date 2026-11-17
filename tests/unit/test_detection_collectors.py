"""Phase 5 collector and parser tests."""

from __future__ import annotations

from pathlib import Path

from ubuntuguard.audit.authlog import (
    collect_auth_log,
    parse_auth_log,
    summarize_auth,
)
from ubuntuguard.audit.events import EventLog
from ubuntuguard.audit.file_baseline import FileBaseline
from ubuntuguard.audit.integrity import collect_aide, collect_auditd, parse_audit_rules
from ubuntuguard.audit.processes import classify_process, detect_suspicious_processes
from ubuntuguard.models import CommandResult, Finding, Severity

AUTH_LOG = """\
May  1 10:00:00 host sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 2222 ssh2
May  1 10:00:01 host sshd[1]: Invalid user test from 203.0.113.6
May  1 10:00:02 host sshd[1]: Accepted publickey for deploy from 192.0.2.10 port 5555 ssh2
May  1 10:00:03 host sshd[1]: Accepted password for root from 198.51.100.7 port 6666 ssh2
"""

AUDIT_RULES = """\
# managed rules
-w /etc/sudoers -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S execve -k exec
"""


def test_parse_auth_log() -> None:
    events = parse_auth_log(AUTH_LOG)
    assert len(events) == 4
    assert events[0].kind == "failed_password"
    assert events[0].user == "admin"
    assert events[0].source_ip == "203.0.113.5"
    assert events[1].kind == "invalid_user"
    assert events[2].method == "publickey"
    assert events[3].method == "password"
    assert events[3].user == "root"


def test_summarize_auth() -> None:
    summary = summarize_auth(parse_auth_log(AUTH_LOG))
    assert summary["failed"] == 2
    assert summary["accepted"] == 2
    assert summary["distinct_invalid_users"] == 1
    assert summary["top_failure_ips"] == [
        {"ip": "203.0.113.5", "count": 1},
        {"ip": "203.0.113.6", "count": 1},
    ]


def test_collect_auth_log_from_file(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text(AUTH_LOG, encoding="utf-8")
    info = collect_auth_log(None, path)  # type: ignore[arg-type]
    assert info.readable
    assert info.source == str(path)
    assert len(info.events) == 4


def test_collect_auth_log_falls_back_to_journald(tmp_path: Path, fake_executor) -> None:
    argv = ("journalctl", "-u", "ssh", "--no-pager", "-n", "2000")
    fake_executor.responses[argv] = CommandResult(
        argv=argv,
        returncode=0,
        stdout=(
            "May  1 10:00:00 host sshd[1]: Failed password for root "
            "from 203.0.113.9 port 1000 ssh2\n"
        ),
    )
    info = collect_auth_log(fake_executor, tmp_path / "missing.log")
    assert info.readable
    assert info.source == "journalctl"
    assert len(info.events) == 1


def test_parse_audit_rules() -> None:
    count, watched = parse_audit_rules(AUDIT_RULES)
    assert count == 3
    assert watched == ("/etc/sudoers", "/etc/ssh/sshd_config")


def test_collect_auditd(tmp_path: Path, fake_executor) -> None:
    rules_dir = tmp_path / "rules.d"
    rules_dir.mkdir()
    (rules_dir / "99-guard.rules").write_text(AUDIT_RULES, encoding="utf-8")
    fake_executor.responses[("systemctl", "is-active", "auditd")] = CommandResult(
        argv=("systemctl", "is-active", "auditd"),
        returncode=0,
        stdout="active\n",
    )

    status = collect_auditd(fake_executor, sources=(rules_dir,))
    assert status.available
    assert status.active
    assert status.rule_count == 3
    assert "/etc/ssh/sshd_config" in status.watched_paths


def test_collect_aide(tmp_path: Path) -> None:
    database = tmp_path / "aide.db"
    database.write_text("db", encoding="utf-8")

    status = collect_aide(candidates=(database,), installed=True)
    assert status.installed
    assert status.database_present
    assert status.database_path == str(database)
    assert status.last_modified

    missing = collect_aide(candidates=(tmp_path / "none.db",), installed=False)
    assert missing.installed is False
    assert missing.database_present is False


def test_classify_process() -> None:
    assert classify_process("/usr/sbin/sshd", "") is None
    assert classify_process("/tmp/evil", "") == "executing from a temporary directory"
    assert classify_process("", "/tmp/evil --x") == "executing from a temporary directory"
    assert classify_process("/usr/bin/x (deleted)", "") == "executable deleted from disk"


def test_detect_suspicious_processes(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    pid_dir = proc / "123"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cmdline").write_bytes(b"/tmp/evil.sh\x00--x\x00")
    clean_dir = proc / "456"
    clean_dir.mkdir()
    (clean_dir / "cmdline").write_bytes(b"/usr/sbin/sshd\x00-D\x00")

    results = detect_suspicious_processes(proc)
    assert len(results) == 1
    assert results[0].pid == 123
    assert results[0].reason == "executing from a temporary directory"


def test_file_baseline_lifecycle(tmp_path: Path) -> None:
    target = tmp_path / "passwd"
    target.write_text("a\n", encoding="utf-8")
    baseline = FileBaseline(tmp_path / "baseline.json")

    assert baseline.exists is False
    assert baseline.initialize((str(target),)) == 1
    assert baseline.exists
    assert baseline.compare((str(target),)) == ()

    target.write_text("b\n", encoding="utf-8")
    changes = baseline.compare((str(target),))
    assert changes[0].status == "changed"
    assert changes[0].old_sha256 != changes[0].new_sha256

    target.unlink()
    new_file = tmp_path / "new.conf"
    new_file.write_text("n\n", encoding="utf-8")
    changes = baseline.compare((str(target), str(new_file)))
    statuses = {change.path: change.status for change in changes}
    assert statuses[str(target)] == "missing"
    assert statuses[str(new_file)] == "added"


def test_event_log_appends_json_lines(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "events.jsonl")
    findings = [
        Finding(
            id="TEST-001",
            title="test",
            severity=Severity.HIGH,
            category="test",
            evidence={"a": 1},
        )
    ]
    assert log.append(findings) == 1
    assert log.append(findings) == 1

    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert '"id": "TEST-001"' in lines[0]
