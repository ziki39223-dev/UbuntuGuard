"""CLI behavior and exit code tests."""

from __future__ import annotations

import json
from pathlib import Path

from ubuntuguard import __version__
from ubuntuguard.cli.main import main
from ubuntuguard.exit_codes import ExitCode

EXAMPLE_CONFIG = "configs/config.example.yaml"


def test_version(capsys) -> None:
    assert main(["version"]) == ExitCode.OK
    assert __version__ in capsys.readouterr().out


def test_version_json(capsys) -> None:
    assert main(["--json", "version"]) == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "ubuntuguard"


def test_no_command_returns_usage(capsys) -> None:
    assert main([]) == ExitCode.USAGE
    assert "usage" in capsys.readouterr().out.lower()


def test_config_validate_example(capsys) -> None:
    assert main(["--config", EXAMPLE_CONFIG, "config", "validate"]) == ExitCode.OK
    assert "config valid" in capsys.readouterr().out


def test_config_show_json(capsys) -> None:
    assert main(["--json", "--config", EXAMPLE_CONFIG, "config", "show"]) == ExitCode.OK
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == 1
    assert data["firewall"]["allow_ports"] == ["22/tcp"]


def test_invalid_config_maps_to_usage_exit_code(tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "version: 1\nharden:\n  require_confirmation: false\n", encoding="utf-8"
    )
    assert main(["--config", str(path), "config", "validate"]) == ExitCode.USAGE
    assert "security invariant" in capsys.readouterr().err


def test_doctor_json(capsys) -> None:
    code = main(["--json", "doctor"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == __version__
    assert "platform" in payload
    assert code in (ExitCode.OK, ExitCode.UNSUPPORTED)


def test_collect_json(capsys) -> None:
    assert main(["--json", "collect"]) == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert "host" in payload
    assert "cpu" in payload
    assert "errors" in payload


def test_collect_table_output(capsys) -> None:
    assert main(["collect"]) == ExitCode.OK
    output = capsys.readouterr().out
    assert "host      :" in output
    assert "packages  :" in output


def test_audit_json(capsys) -> None:
    code = main(["--json", "audit"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1.0"
    assert "summary" in payload
    assert payload["summary"]["score"] >= 0
    assert code in (ExitCode.OK, ExitCode.AUDIT_FINDINGS, ExitCode.UNSUPPORTED)


def test_audit_text(capsys) -> None:
    code = main(["audit"])
    output = capsys.readouterr().out
    assert "UbuntuGuard audit" in output
    assert "score:" in output
    assert code in (ExitCode.OK, ExitCode.AUDIT_FINDINGS, ExitCode.UNSUPPORTED)


def test_audit_fail_on_critical(capsys) -> None:
    code = main(["audit", "--fail-on", "critical"])
    capsys.readouterr()
    assert code in (ExitCode.OK, ExitCode.AUDIT_FINDINGS, ExitCode.UNSUPPORTED)


def test_harden_plan(capsys) -> None:
    assert main(["harden", "plan"]) == ExitCode.OK
    assert "hardening plan" in capsys.readouterr().out


def test_harden_apply_defaults_to_preview(capsys) -> None:
    assert main(["harden", "apply"]) == ExitCode.OK
    assert "hardening plan" in capsys.readouterr().out


def test_harden_requires_action(capsys) -> None:
    assert main(["harden"]) == ExitCode.USAGE
    assert "missing harden action" in capsys.readouterr().err


def test_harden_rejects_unknown_only(capsys) -> None:
    assert main(["harden", "plan", "--only", "bogus"]) == ExitCode.USAGE
    assert "unknown hardening action" in capsys.readouterr().err


def test_detect_text(capsys) -> None:
    code = main(["detect"])
    output = capsys.readouterr().out
    assert "UbuntuGuard detection" in output
    assert code in (ExitCode.OK, ExitCode.AUDIT_FINDINGS)


def test_detect_json(capsys) -> None:
    code = main(["--json", "detect"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1.0"
    assert "summary" in payload
    assert code in (ExitCode.OK, ExitCode.AUDIT_FINDINGS)


def test_monitor_check_text(capsys) -> None:
    code = main(["monitor", "check", "--no-notify"])
    output = capsys.readouterr().out
    assert "UbuntuGuard monitoring" in output
    assert code in (ExitCode.OK, ExitCode.AUDIT_FINDINGS)


def test_monitor_check_json(capsys) -> None:
    code = main(["--json", "monitor", "check", "--no-notify"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1.0"
    assert "checks" in payload
    assert code in (ExitCode.OK, ExitCode.AUDIT_FINDINGS)


def test_monitor_requires_action(capsys) -> None:
    assert main(["monitor"]) == ExitCode.USAGE
    assert "missing monitor action" in capsys.readouterr().err
