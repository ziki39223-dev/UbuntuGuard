"""Fail2ban installation and sshd jail configuration."""

from __future__ import annotations

from pathlib import Path

from ...core.config import Config
from ...core.executor import CommandExecutor
from ...models import ActionResult, Change, ChangePlan, SystemSnapshot
from ..hardening.base import HardeningAction

DEFAULT_JAIL = Path("/etc/fail2ban/jail.d/99-ubuntuguard.local")


class Fail2banAction(HardeningAction):
    name = "fail2ban"

    def __init__(self, jail_path: Path = DEFAULT_JAIL) -> None:
        self._jail_path = jail_path

    def skip_reason(self, snapshot: SystemSnapshot, config: Config) -> str | None:
        if not bool(config.get("fail2ban.enabled", True)):
            return "disabled in config"
        return None

    def plan(self, snapshot: SystemSnapshot, config: Config) -> ChangePlan | None:
        changes: list[Change] = []

        if not snapshot.packages.fail2ban_installed:
            changes.append(
                Change(
                    target="package:fail2ban",
                    method="package",
                    after="apt-get install -y fail2ban",
                    note="Install Fail2ban from the Ubuntu archive",
                    rollback=(
                        "Packages are not removed automatically; run "
                        "'apt-get remove fail2ban' if required"
                    ),
                )
            )

        desired = render_jail(config)
        before = _read(self._jail_path)
        if before.strip() != desired.strip():
            changes.append(
                Change(
                    target=str(self._jail_path),
                    method="dropin",
                    before=before,
                    after=desired,
                    note="Configure the sshd jail with the configured thresholds",
                    rollback="Restore the backup file and restart fail2ban",
                )
            )

        if not changes:
            return None
        return ChangePlan(
            action=self.name,
            title="Fail2ban brute-force protection",
            changes=tuple(changes),
            risk="Installing a package changes the system beyond configuration files.",
            targets=(str(self._jail_path),),
        )

    def apply(self, plan: ChangePlan, executor: CommandExecutor) -> ActionResult:
        installed_by_us = False
        for change in plan.changes:
            if change.method == "package":
                result = executor.run(
                    [
                        "env",
                        "DEBIAN_FRONTEND=noninteractive",
                        "apt-get",
                        "install",
                        "-y",
                        "fail2ban",
                    ],
                    timeout=600.0,
                )
                if not result.ok:
                    return ActionResult(
                        self.name,
                        applied=True,
                        verified=False,
                        detail=f"package install failed: {result.stderr.strip()}",
                    )
                installed_by_us = True
            elif change.method == "dropin":
                target = Path(change.target)
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(change.after, encoding="utf-8")
                except OSError as exc:
                    return ActionResult(
                        self.name, applied=False, verified=False, detail=str(exc)
                    )

        start = executor.run(["systemctl", "enable", "--now", "fail2ban"])
        if not start.ok:
            return ActionResult(
                self.name,
                applied=True,
                verified=False,
                detail=f"service start failed: {start.stderr.strip()}",
            )

        status = executor.run(["fail2ban-client", "status", "sshd"])
        if not status.ok:
            return ActionResult(
                self.name,
                applied=True,
                verified=False,
                detail=f"jail not active: {status.stderr.strip()}",
            )
        detail = "jail active" + (" (package installed)" if installed_by_us else "")
        return ActionResult(self.name, applied=True, verified=True, detail=detail)

    def rollback(self, plan: ChangePlan, executor: CommandExecutor) -> bool:
        result = executor.run(["systemctl", "restart", "fail2ban"])
        if result.ok:
            return True
        missing = "not found" in result.stderr or "not loaded" in result.stderr
        return missing


def render_jail(config: Config) -> str:
    maxretry = config.get("fail2ban.maxretry", 5)
    bantime = config.get("fail2ban.bantime", "1h")
    return (
        "# Managed by UbuntuGuard. Manual edits will be overwritten.\n"
        "[sshd]\n"
        "enabled = true\n"
        f"maxretry = {maxretry}\n"
        f"bantime = {bantime}\n"
    )


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
