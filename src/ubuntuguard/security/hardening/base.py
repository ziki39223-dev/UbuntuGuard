"""Hardening action protocol."""

from __future__ import annotations

from typing import Protocol

from ...core.config import Config
from ...core.executor import CommandExecutor
from ...models import ActionResult, ChangePlan, SystemSnapshot


class HardeningAction(Protocol):
    name: str

    def skip_reason(self, snapshot: SystemSnapshot, config: Config) -> str | None:
        """Return why this action cannot run, or None when it can."""

    def plan(self, snapshot: SystemSnapshot, config: Config) -> ChangePlan | None:
        """Build a previewable plan, or None when nothing needs changing."""

    def apply(self, plan: ChangePlan, executor: CommandExecutor) -> ActionResult:
        """Write the changes and verify they took effect."""

    def rollback(self, plan: ChangePlan, executor: CommandExecutor) -> bool:
        """Best-effort runtime rollback after files were restored."""
