"""sysctl hardening through a dedicated drop-in file."""

from __future__ import annotations

from pathlib import Path

from ...core.config import Config
from ...core.executor import CommandExecutor
from ...models import ActionResult, Change, ChangePlan, SystemSnapshot
from ..hardening.base import HardeningAction

DEFAULT_TARGET = Path("/etc/sysctl.d/99-ubuntuguard.conf")


class SysctlHardeningAction(HardeningAction):
    name = "sysctl"

    def __init__(self, target: Path = DEFAULT_TARGET) -> None:
        self._target = target

    def skip_reason(self, snapshot: SystemSnapshot, config: Config) -> str | None:
        if not snapshot.sysctl.values:
            return "sysctl data unavailable"
        return None

    def plan(self, snapshot: SystemSnapshot, config: Config) -> ChangePlan | None:
        values = config.get("sysctl", {}) or {}
        if not values:
            return None
        desired = render_sysctl_dropin(values)
        before = _read(self._target)
        if before.strip() == desired.strip():
            return None
        change = Change(
            target=str(self._target),
            method="dropin",
            before=before,
            after=desired,
            note="Writes a dedicated sysctl drop-in file",
            rollback="Restore the backup file and reload sysctl",
        )
        return ChangePlan(
            action=self.name,
            title="Kernel parameter hardening",
            changes=(change,),
            risk="Some parameters affect networking; verify remote access after applying.",
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

        applied = executor.run(["sysctl", "-p", str(target)])
        if not applied.ok:
            return ActionResult(
                self.name,
                applied=True,
                verified=False,
                detail=f"sysctl -p failed: {applied.stderr.strip()}",
            )

        expected = _parse_values(change.after)
        mismatched: dict[str, str] = {}
        for key, value in expected.items():
            actual = executor.run(["sysctl", "-n", key]).stdout.strip()
            if actual != value:
                mismatched[key] = actual
        if mismatched:
            return ActionResult(
                self.name,
                applied=True,
                verified=False,
                detail=f"sysctl mismatch: {mismatched}",
            )
        return ActionResult(self.name, applied=True, verified=True, detail="sysctl reloaded")

    def rollback(self, plan: ChangePlan, executor: CommandExecutor) -> bool:
        return executor.run(["sysctl", "--system"]).ok


def render_sysctl_dropin(values: dict[str, object]) -> str:
    lines = ["# Managed by UbuntuGuard. Manual edits will be overwritten."]
    lines.extend(f"{key} = {value}" for key, value in values.items())
    return "\n".join(lines) + "\n"


def _parse_values(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, raw = stripped.partition("=")
        values[key.strip()] = raw.strip()
    return values


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
