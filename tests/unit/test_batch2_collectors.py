"""Batch 2 collector and Lynis parser tests."""

from __future__ import annotations

from pathlib import Path

from ubuntuguard.collectors.firewall import collect_firewall, parse_ufw
from ubuntuguard.collectors.sysctl import collect_sysctl
from ubuntuguard.errors import CommandExecutionError, CommandFailedError
from ubuntuguard.integrations.lynis import parse_lynis_report
from ubuntuguard.models import CommandResult, Severity

UFW_ACTIVE = """\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
443/tcp (v6)               ALLOW IN    Anywhere (v6)
"""

UFW_INACTIVE = """\
Status: inactive
"""

LYNIS_REPORT = """\
# Lynis report
warning[]=SSH root login is enabled
suggestion[]=Install fail2ban to protect against brute force
suggestion[]=Consider hardening SSH configuration
"""


class _MissingUfwExecutor:
    def run(self, *_args: object, **_kwargs: object) -> CommandResult:
        raise CommandExecutionError("command not found: ufw")


class _DeniedUfwExecutor:
    def run(self, *_args: object, **_kwargs: object) -> CommandResult:
        raise CommandFailedError(
            CommandResult(argv=("ufw", "status"), returncode=1, stderr="need root")
        )


def test_parse_ufw_active() -> None:
    info = parse_ufw(UFW_ACTIVE)
    assert info.available and info.readable
    assert info.active is True
    assert info.default_incoming == "deny"
    assert info.default_outgoing == "allow"
    assert len(info.rules) == 2
    assert info.rules[0].to == "22/tcp"
    assert info.rules[0].action == "ALLOW"
    assert info.rules[1].to == "443/tcp"


def test_parse_ufw_inactive() -> None:
    info = parse_ufw(UFW_INACTIVE)
    assert info.active is False
    assert info.rules == ()


def test_collect_firewall_unavailable_and_denied() -> None:
    missing = collect_firewall(_MissingUfwExecutor())  # type: ignore[arg-type]
    assert missing.available is False
    assert missing.readable is False

    denied = collect_firewall(_DeniedUfwExecutor())  # type: ignore[arg-type]
    assert denied.available is True
    assert denied.readable is False


def test_collect_sysctl_from_proc_root(tmp_path: Path) -> None:
    root = tmp_path / "sys"
    (root / "kernel").mkdir(parents=True)
    (root / "kernel" / "randomize_va_space").write_text("2\n", encoding="utf-8")
    (root / "fs").mkdir()
    (root / "fs" / "protected_links").write_text("1\n", encoding="utf-8")

    info = collect_sysctl(
        keys=("kernel.randomize_va_space", "fs.protected_links", "kernel.missing"),
        root=root,
    )
    assert info.values == {
        "kernel.randomize_va_space": "2",
        "fs.protected_links": "1",
    }


def test_parse_lynis_report() -> None:
    findings = parse_lynis_report(LYNIS_REPORT)
    assert len(findings) == 3
    assert findings[0].severity is Severity.MEDIUM
    assert findings[1].severity is Severity.LOW
    assert findings[0].id.startswith("LYNIS-")
    assert findings[0].id == parse_lynis_report(LYNIS_REPORT)[0].id
    assert findings[1].evidence["text"].startswith("Install fail2ban")
