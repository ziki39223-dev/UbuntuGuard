"""Phase 8: HTML report, Ansible export and systemd integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ubuntuguard.cli.main import main
from ubuntuguard.core.config import Config
from ubuntuguard.exit_codes import ExitCode
from ubuntuguard.integrations import build_ansible_playbook
from ubuntuguard.reporting import render_html_report
from ubuntuguard.systemd import install, uninstall, unit_files, valid_interval


def test_html_report_escapes_and_renders() -> None:
    payload = {
        "schema_version": "1.0",
        "tool_version": "0.1.0",
        "generated_at": "2026-11-17T00:00:00+08:00",
        "host": {"hostname": "h", "os": "Ubuntu 24.04", "kernel": "6.8"},
        "audit": {
            "summary": {"score": 85, "grade": "B", "total": 1},
            "findings": [
                {
                    "id": "SSH-001",
                    "title": "<script>alert(1)</script>",
                    "severity": "high",
                    "evidence": {"key": "PermitRootLogin", "value": "yes"},
                    "remediation": "Set PermitRootLogin no",
                }
            ],
            "skipped": ["authlog: unavailable"],
        },
        "detection": {"findings": [], "skipped": [], "summary": {}},
        "monitoring": {
            "checks": [
                {
                    "name": "cpu",
                    "status": "ok",
                    "value": 12.0,
                    "threshold": 85,
                    "detail": "12.0% <= 85.0%",
                }
            ],
            "metrics": {"errors": []},
        },
    }

    text = render_html_report(payload)
    assert "<!DOCTYPE html>" in text
    assert "SSH-001" in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<script>alert(1)</script>" not in text
    assert "Health checks" in text
    assert "authlog: unavailable" in text


def test_ansible_playbook_generation(config: Config) -> None:
    playbook = build_ansible_playbook(config)
    assert playbook["become"] is True
    names = [task["name"] for task in playbook["tasks"]]
    assert "Deploy SSH hardening drop-in" in names
    assert "Deploy sysctl hardening" in names
    assert "Allow 22/tcp" in names
    assert "Install Fail2ban" in names
    assert any(handler["name"] == "Reload ssh" for handler in playbook["handlers"])

    dumped = yaml.safe_dump(playbook, sort_keys=False)
    assert "PermitRootLogin" in dumped
    assert "ufw --force enable" in dumped


def test_systemd_install_and_uninstall(tmp_path: Path, fake_executor) -> None:
    files = install(
        fake_executor,
        unit_dir=tmp_path,
        interval="12h",
        monitor_interval="10m",
        binary="/usr/bin/ubuntuguard",
    )
    assert len(files) == 4
    for path in files:
        assert Path(path).is_file()

    audit_timer = (tmp_path / "ubuntuguard-audit.timer").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=12h" in audit_timer
    monitor_timer = (tmp_path / "ubuntuguard-monitor.timer").read_text(
        encoding="utf-8"
    )
    assert "OnUnitActiveSec=10m" in monitor_timer

    assert ("systemctl", "daemon-reload") in fake_executor.calls
    assert (
        "systemctl",
        "enable",
        "--now",
        "ubuntuguard-audit.timer",
    ) in fake_executor.calls

    removed = uninstall(fake_executor, unit_dir=tmp_path)
    assert len(removed) == 4
    assert not any((tmp_path / name).exists() for name in unit_files())
    assert (
        "systemctl",
        "disable",
        "--now",
        "ubuntuguard-monitor.timer",
    ) in fake_executor.calls


def test_valid_interval() -> None:
    assert valid_interval("5min") is False
    assert valid_interval("6h") is True
    assert valid_interval("30m") is True
    assert valid_interval("abc") is False


def test_cli_report_files(tmp_path: Path, capsys) -> None:
    json_path = tmp_path / "report.json"
    assert (
        main(["report", "--format", "json", "--out", str(json_path)])
        == ExitCode.OK
    )
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert {"audit", "detection", "monitoring"} <= set(payload)

    html_path = tmp_path / "report.html"
    assert (
        main(["report", "--format", "html", "--out", str(html_path)])
        == ExitCode.OK
    )
    assert "<!DOCTYPE html>" in html_path.read_text(encoding="utf-8")
    capsys.readouterr()


def test_cli_export_ansible(capsys) -> None:
    assert main(["export", "ansible"]) == ExitCode.OK
    output = capsys.readouterr().out
    assert "Deploy SSH hardening drop-in" in output
    assert main(["export"]) == ExitCode.USAGE


def test_cli_systemd_missing_action(capsys) -> None:
    assert main(["systemd"]) == ExitCode.USAGE
    assert "missing systemd action" in capsys.readouterr().err
