"""Hardening orchestrator: plan, apply, verify and roll back."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ...backup import SnapshotStore
from ...core.config import Config
from ...core.executor import CommandExecutor
from ...models import ActionResult, ChangePlan, SystemSnapshot
from ..fail2ban.actions import Fail2banAction
from ..firewall.actions import FirewallHardeningAction
from ..ssh.actions import SshHardeningAction
from ..system.actions import SysctlHardeningAction
from .base import HardeningAction

ACTIONS: tuple[HardeningAction, ...] = (
    SshHardeningAction(),
    SysctlHardeningAction(),
    FirewallHardeningAction(),
    Fail2banAction(),
)
ACTION_MAP: dict[str, HardeningAction] = {action.name: action for action in ACTIONS}
ACTION_NAMES: tuple[str, ...] = tuple(action.name for action in ACTIONS)


@dataclass(frozen=True)
class HardeningPlanSet:
    plans: tuple[ChangePlan, ...]
    skipped: tuple[str, ...]


@dataclass(frozen=True)
class HardeningResult:
    plans: tuple[ChangePlan, ...]
    results: tuple[ActionResult, ...]
    skipped: tuple[str, ...]
    snapshot_id: str | None = None
    rolled_back: bool = False
    rollback_failed: bool = False


def build_plans(
    snapshot: SystemSnapshot,
    config: Config,
    only: Sequence[str] | None = None,
) -> HardeningPlanSet:
    if snapshot.host.os_id != "ubuntu":
        return HardeningPlanSet(
            (), (f"hardening: unsupported platform ({snapshot.host.os_id})",)
        )

    selected = [action for action in ACTIONS if only is None or action.name in only]
    plans: list[ChangePlan] = []
    skipped: list[str] = []
    for action in selected:
        reason = action.skip_reason(snapshot, config)
        if reason:
            skipped.append(f"{action.name}: {reason}")
            continue
        plan = action.plan(snapshot, config)
        if plan is None:
            skipped.append(f"{action.name}: nothing to change")
            continue
        plans.append(plan)
    return HardeningPlanSet(tuple(plans), tuple(skipped))


def apply_plans(
    plan_set: HardeningPlanSet,
    executor: CommandExecutor,
    store: SnapshotStore,
    actions: Mapping[str, HardeningAction] | None = None,
) -> HardeningResult:
    registry = dict(actions) if actions is not None else ACTION_MAP

    targets: list[Path] = []
    for plan in plan_set.plans:
        for raw_target in plan.targets:
            path = Path(raw_target)
            if path not in targets:
                targets.append(path)
    snapshot = store.create(targets, label="harden") if targets else None

    results: list[ActionResult] = []
    completed: list[ChangePlan] = []
    for plan in plan_set.plans:
        action = registry.get(plan.action)
        if action is None:
            outcome = ActionResult(
                plan.action,
                applied=False,
                verified=False,
                detail="no action registered",
            )
        else:
            try:
                outcome = action.apply(plan, executor)
            except Exception as exc:  # isolate action failures for rollback handling
                outcome = ActionResult(
                    plan.action,
                    applied=False,
                    verified=False,
                    detail=f"apply failed: {exc}",
                )
        results.append(outcome)
        completed.append(plan)

        if outcome.verified:
            continue

        rollback_failed = False
        if snapshot is not None:
            try:
                store.restore(snapshot)
            except OSError:
                rollback_failed = True
        for done in reversed(completed):
            handler = registry.get(done.action)
            if handler is None:
                rollback_failed = True
                continue
            try:
                if not handler.rollback(done, executor):
                    rollback_failed = True
            except Exception:
                rollback_failed = True

        return HardeningResult(
            plans=plan_set.plans,
            results=tuple(results),
            skipped=plan_set.skipped,
            snapshot_id=snapshot.snapshot_id if snapshot is not None else None,
            rolled_back=True,
            rollback_failed=rollback_failed,
        )

    return HardeningResult(
        plans=plan_set.plans,
        results=tuple(results),
        skipped=plan_set.skipped,
        snapshot_id=snapshot.snapshot_id if snapshot is not None else None,
    )
