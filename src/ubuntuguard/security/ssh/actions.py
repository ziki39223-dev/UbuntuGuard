"""SSH hardening through a dedicated drop-in file."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from ...core.config import Config
from ...core.executor import CommandExecutor
from ...models import ActionResult, Change, ChangePlan, SystemSnapshot
from ..hardening.base import HardeningAction

DEFAULT_TARGET = Path("/etc/ssh/sshd_config.d/99-ubuntuguard.conf")

# `sshd -T` prints "without-password" for the "prohibit-password" keyword.
_VALUE_ALIASES = {
    "permitrootlogin": {"without-password": "prohibit-password"},
}


class SshHardeningAction(HardeningAction):
    name = "ssh"

    def __init__(self, target: Path = DEFAULT_TARGET) -> None:
        self._target = target

    def skip_reason(self, snapshot: SystemSnapshot, config: Config) -> str | None:
        if snapshot.ssh.source == "unavailable":
            return "sshd configuration unavailable"
        return None

    def plan(self, snapshot: SystemSnapshot, config: Config) -> ChangePlan | None:
        desired = render_sshd_dropin(config)
        before = _read(self._target)
        if before.strip() == desired.strip():
            return None
        change = Change(
            target=str(self._target),
            method="dropin",
            before=before,
            after=desired,
            note="Writes a dedicated drop-in; the main sshd_config is never edited",
            rollback="Restore the backup file and reload ssh",
        )
        return ChangePlan(
            action=self.name,
            title="SSH server hardening",
            changes=(change,),
            risk=(
                "Disabling password login or limiting users can lock you out. "
                "Verify key-based access before applying."
            ),
            targets=(str(self._target),),
        )

    def apply(self, plan: ChangePlan, executor: CommandExecutor) -> ActionResult:
        change = plan.changes[0]
        target = Path(change.target)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(change.after, encoding="utf-8")
        except OSError as exc:
            return ActionResult(self.name, applied=False, verified=False, detail=str(exc))

        # A fresh install may not have the privilege separation directory yet.
        if os.name == "posix":
            with contextlib.suppress(OSError):
                Path("/run/sshd").mkdir(parents=True, exist_ok=True)

        syntax = executor.run(["sshd", "-t"])
        if not syntax.ok:
            return ActionResult(
                self.name,
                applied=True,
                verified=False,
                detail=f"sshd -t failed: {syntax.stderr.strip() or syntax.stdout.strip()}",
            )
        reload_result = executor.run(["systemctl", "reload", "ssh"])
        if not reload_result.ok:
            return ActionResult(
                self.name,
                applied=True,
                verified=False,
                detail=f"reload failed: {reload_result.stderr.strip()}",
            )

        effective = _parse_effective(executor.run(["sshd", "-T"]).stdout)
        desired = _parse_effective(change.after)
        mismatched = {
            key: value
            for key, value in desired.items()
            if _normalize(key, effective.get(key, "")) != _normalize(key, value)
        }
        if mismatched:
            return ActionResult(
                self.name,
                applied=True,
                verified=False,
                detail=f"effective config mismatch: {mismatched}",
            )
        return ActionResult(self.name, applied=True, verified=True, detail="ssh reloaded")

    def rollback(self, plan: ChangePlan, executor: CommandExecutor) -> bool:
        return executor.run(["systemctl", "reload", "ssh"]).ok


def render_sshd_dropin(config: Config) -> str:
    permit_root = str(config.get("ssh.permit_root_login", "prohibit-password"))
    password_auth = bool(config.get("ssh.password_authentication", False))
    lines = [
        "# Managed by UbuntuGuard. Manual edits will be overwritten.",
        f"PermitRootLogin {permit_root}",
        f"PasswordAuthentication {'yes' if password_auth else 'no'}",
        "PermitEmptyPasswords no",
        "X11Forwarding no",
        "MaxAuthTries 4",
        "IgnoreRhosts yes",
        "HostbasedAuthentication no",
        "PermitUserEnvironment no",
        "StrictModes yes",
        "LoginGraceTime 60",
        "ClientAliveInterval 300",
        "ClientAliveCountMax 3",
    ]
    allow_users = config.get("ssh.allow_users", []) or []
    if allow_users:
        lines.append("AllowUsers " + " ".join(str(user) for user in allow_users))
    return "\n".join(lines) + "\n"


def _parse_effective(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(maxsplit=1)
        values[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else ""
    return values


def _normalize(key: str, value: str) -> str:
    normalized = value.strip().lower()
    return _VALUE_ALIASES.get(key, {}).get(normalized, normalized)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
