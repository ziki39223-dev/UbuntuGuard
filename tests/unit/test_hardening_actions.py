"""Hardening action tests (no real system changes)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ubuntuguard.core.config import Config
from ubuntuguard.models import (
    CommandResult,
    FirewallInfo,
    PackageInfo,
    SshInfo,
    SysctlInfo,
    SystemSnapshot,
)
from ubuntuguard.security.fail2ban.actions import Fail2banAction
from ubuntuguard.security.firewall.actions import FirewallHardeningAction
from ubuntuguard.security.ssh.actions import SshHardeningAction
from ubuntuguard.security.system.actions import SysctlHardeningAction


def _ok(argv: tuple[str, ...], stdout: str = "") -> CommandResult:
    return CommandResult(argv=argv, returncode=0, stdout=stdout)


def test_ssh_plan_and_apply(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    config: Config,
    fake_executor,
) -> None:
    target = tmp_path / "sshd_config.d" / "99-ubuntuguard.conf"
    action = SshHardeningAction(target)
    snapshot = make_snapshot(
        ssh=SshInfo(effective={"permitrootlogin": "yes"}, source="sshd -T")
    )

    plan = action.plan(snapshot, config)
    assert plan is not None
    content = plan.changes[0].after
    assert "PermitRootLogin prohibit-password" in content
    assert "PasswordAuthentication no" in content

    desired: dict[str, str] = {}
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        desired[key.lower()] = value.strip().lower()
    effective = "\n".join(f"{key} {value}" for key, value in desired.items())
    effective = effective.replace(
        "permitrootlogin prohibit-password", "permitrootlogin without-password"
    )

    fake_executor.responses[("sshd", "-t")] = _ok(("sshd", "-t"))
    fake_executor.responses[("systemctl", "reload", "ssh")] = _ok(
        ("systemctl", "reload", "ssh")
    )
    fake_executor.responses[("sshd", "-T")] = _ok(("sshd", "-T"), effective)

    outcome = action.apply(plan, fake_executor)  # type: ignore[arg-type]
    assert outcome.verified
    assert target.read_text(encoding="utf-8") == content


def test_ssh_invalid_config_is_not_verified(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    config: Config,
    fake_executor,
) -> None:
    target = tmp_path / "99-ubuntuguard.conf"
    action = SshHardeningAction(target)
    snapshot = make_snapshot(
        ssh=SshInfo(effective={"permitrootlogin": "no"}, source="sshd -T")
    )
    plan = action.plan(snapshot, config)
    assert plan is not None

    fake_executor.responses[("sshd", "-t")] = CommandResult(
        argv=("sshd", "-t"), returncode=1, stderr="bad configuration"
    )
    outcome = action.apply(plan, fake_executor)  # type: ignore[arg-type]
    assert outcome.applied
    assert outcome.verified is False
    assert "sshd -t failed" in outcome.detail


def test_ssh_plan_is_idempotent(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    config: Config,
) -> None:
    target = tmp_path / "99-ubuntuguard.conf"
    action = SshHardeningAction(target)
    snapshot = make_snapshot(ssh=SshInfo(effective={"a": "b"}, source="sshd -T"))

    first = action.plan(snapshot, config)
    assert first is not None
    target.write_text(first.changes[0].after, encoding="utf-8")
    assert action.plan(snapshot, config) is None


def test_sysctl_plan_and_apply(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    config: Config,
    fake_executor,
) -> None:
    target = tmp_path / "99-ubuntuguard.conf"
    action = SysctlHardeningAction(target)
    snapshot = make_snapshot(
        sysctl=SysctlInfo(values={"kernel.randomize_va_space": "2"})
    )

    plan = action.plan(snapshot, config)
    assert plan is not None
    assert "net.ipv4.tcp_syncookies = 1" in plan.changes[0].after

    fake_executor.responses[("sysctl", "-p", str(target))] = _ok(
        ("sysctl", "-p", str(target))
    )
    expected = config.get("sysctl", {})
    for key, value in expected.items():
        argv = ("sysctl", "-n", key)
        fake_executor.responses[argv] = _ok(argv, f"{value}\n")

    outcome = action.apply(plan, fake_executor)  # type: ignore[arg-type]
    assert outcome.verified


def test_firewall_plan_apply_and_rollback(
    make_snapshot: Callable[..., SystemSnapshot],
    config: Config,
    fake_executor,
) -> None:
    action = FirewallHardeningAction()
    snapshot = make_snapshot(
        firewall=FirewallInfo(
            available=True,
            readable=True,
            active=False,
            default_incoming="allow",
        )
    )

    plan = action.plan(snapshot, config)
    assert plan is not None
    commands = [change.after for change in plan.changes]
    assert "ufw --force enable" in commands
    assert "ufw default deny incoming" in commands
    assert "ufw allow 22/tcp" in commands

    status = (
        "Status: active\n"
        "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
    )
    fake_executor.responses[("ufw", "status", "verbose")] = _ok(
        ("ufw", "status", "verbose"), status
    )
    outcome = action.apply(plan, fake_executor)  # type: ignore[arg-type]
    assert outcome.verified

    assert action.rollback(plan, fake_executor) is True  # type: ignore[arg-type]
    assert ("ufw", "--force", "disable") in fake_executor.calls
    assert ("ufw", "delete", "allow", "22/tcp") in fake_executor.calls


def test_fail2ban_plan_and_apply(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    config: Config,
    fake_executor,
) -> None:
    jail = tmp_path / "jail.d" / "99-ubuntuguard.local"
    action = Fail2banAction(jail)
    snapshot = make_snapshot(packages=PackageInfo(fail2ban_installed=False))

    plan = action.plan(snapshot, config)
    assert plan is not None
    assert [change.method for change in plan.changes] == ["package", "dropin"]

    outcome = action.apply(plan, fake_executor)  # type: ignore[arg-type]
    assert outcome.verified
    assert "[sshd]" in jail.read_text(encoding="utf-8")
    assert (
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "install",
        "-y",
        "fail2ban",
    ) in fake_executor.calls
