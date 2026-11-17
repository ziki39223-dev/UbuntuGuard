"""UFW hardening: default policy, allow list and enablement."""

from __future__ import annotations

import shlex

from ...core.config import Config
from ...core.executor import CommandExecutor
from ...models import ActionResult, Change, ChangePlan, SystemSnapshot
from ..hardening.base import HardeningAction

ACCEPTABLE_INCOMING = frozenset({"deny", "reject"})


class FirewallHardeningAction(HardeningAction):
    name = "firewall"

    def skip_reason(self, snapshot: SystemSnapshot, config: Config) -> str | None:
        if not bool(config.get("firewall.enabled", True)):
            return "disabled in config"
        if not snapshot.firewall.available:
            return "ufw is not installed"
        if not snapshot.firewall.readable:
            return "ufw status not readable (requires root)"
        return None

    def plan(self, snapshot: SystemSnapshot, config: Config) -> ChangePlan | None:
        changes: list[Change] = []

        if not snapshot.firewall.active:
            changes.append(
                Change(
                    target="ufw:enable",
                    method="command",
                    after="ufw --force enable",
                    note="Enable the host firewall",
                    rollback="ufw --force disable",
                )
            )

        if snapshot.firewall.default_incoming not in ACCEPTABLE_INCOMING:
            policy = str(config.get("firewall.default_incoming", "deny"))
            changes.append(
                Change(
                    target="ufw:default",
                    method="command",
                    after=f"ufw default {policy} incoming",
                    note="Deny incoming traffic by default",
                    rollback="Restore the previous default policy manually",
                )
            )

        existing = {rule.to for rule in snapshot.firewall.rules}
        for port in config.get("firewall.allow_ports", []) or []:
            if port not in existing:
                changes.append(
                    Change(
                        target=f"ufw:allow:{port}",
                        method="command",
                        after=f"ufw allow {port}",
                        note=f"Allow {port}",
                        rollback=f"ufw delete allow {port}",
                    )
                )

        if not changes:
            return None
        return ChangePlan(
            action=self.name,
            title="Firewall policy",
            changes=tuple(changes),
            risk="Ensure the SSH port is in allow_ports before enabling the firewall.",
        )

    def apply(self, plan: ChangePlan, executor: CommandExecutor) -> ActionResult:
        for change in plan.changes:
            result = executor.run(shlex.split(change.after))
            if not result.ok:
                return ActionResult(
                    self.name,
                    applied=True,
                    verified=False,
                    detail=f"{change.after} failed: {result.stderr.strip()}",
                )

        status = executor.run(["ufw", "status", "verbose"]).stdout
        active = "Status: active" in status
        incoming_denied = any(
            policy in status for policy in ("deny (incoming)", "reject (incoming)")
        )
        verified = active and incoming_denied
        return ActionResult(
            self.name,
            applied=True,
            verified=verified,
            detail="ufw updated" if verified else "ufw state mismatch after apply",
        )

    def rollback(self, plan: ChangePlan, executor: CommandExecutor) -> bool:
        ok = True
        for change in reversed(plan.changes):
            if change.after.startswith("ufw --force enable"):
                ok = executor.run(["ufw", "--force", "disable"]).ok and ok
            elif change.after.startswith("ufw allow "):
                port = change.after.split()[-1]
                ok = executor.run(["ufw", "delete", "allow", port]).ok and ok
        return ok
