"""Hardening engine tests (plan selection, apply, rollback)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ubuntuguard.backup import SnapshotStore
from ubuntuguard.core.config import Config
from ubuntuguard.models import (
    ActionResult,
    Change,
    ChangePlan,
    HostInfo,
    PackageInfo,
    SystemSnapshot,
)
from ubuntuguard.security.hardening import HardeningPlanSet, apply_plans, build_plans


class _FailingAction:
    name = "fake"

    def __init__(self, rollback_ok: bool = True) -> None:
        self.rollback_ok = rollback_ok
        self.rolled_back = False

    def skip_reason(self, snapshot: SystemSnapshot, config: Config) -> str | None:
        return None

    def plan(self, snapshot: SystemSnapshot, config: Config) -> ChangePlan | None:
        return None

    def apply(self, plan: ChangePlan, executor: object) -> ActionResult:
        for change in plan.changes:
            Path(change.target).write_text(change.after, encoding="utf-8")
        return ActionResult(self.name, applied=True, verified=False, detail="boom")

    def rollback(self, plan: ChangePlan, executor: object) -> bool:
        self.rolled_back = True
        return self.rollback_ok


class _GoodAction(_FailingAction):
    def apply(self, plan: ChangePlan, executor: object) -> ActionResult:
        return ActionResult(self.name, applied=True, verified=True, detail="ok")


def test_build_plans_rejects_unsupported_platform(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        host=HostInfo(
            hostname="debian",
            os_id="debian",
            os_version="12",
            os_pretty_name="Debian 12",
            kernel="6.1",
        )
    )
    plan_set = build_plans(snapshot, config)
    assert plan_set.plans == ()
    assert any("unsupported platform" in reason for reason in plan_set.skipped)


def test_build_plans_respects_only_filter(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(packages=PackageInfo(fail2ban_installed=True))
    plan_set = build_plans(snapshot, config, only=("fail2ban",))
    assert [plan.action for plan in plan_set.plans] == ["fail2ban"]


def test_apply_restores_files_on_failure(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    fake_executor,
) -> None:
    target = tmp_path / "app.conf"
    target.write_text("before\n", encoding="utf-8")
    plan = ChangePlan(
        action="fake",
        title="fake",
        changes=(
            Change(target=str(target), method="dropin", after="tampered\n"),
        ),
        targets=(str(target),),
    )
    plan_set = HardeningPlanSet(plans=(plan,), skipped=())

    action = _FailingAction(rollback_ok=True)
    store = SnapshotStore(tmp_path / "snapshots")
    result = apply_plans(plan_set, fake_executor, store, actions={"fake": action})

    assert result.rolled_back
    assert result.rollback_failed is False
    assert action.rolled_back
    assert result.snapshot_id is not None
    assert target.read_text(encoding="utf-8") == "before\n"


def test_apply_reports_rollback_failure(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    fake_executor,
) -> None:
    target = tmp_path / "app.conf"
    target.write_text("before\n", encoding="utf-8")
    plan = ChangePlan(
        action="fake",
        title="fake",
        changes=(
            Change(target=str(target), method="dropin", after="tampered\n"),
        ),
        targets=(str(target),),
    )
    plan_set = HardeningPlanSet(plans=(plan,), skipped=())
    action = _FailingAction(rollback_ok=False)

    result = apply_plans(
        plan_set,
        fake_executor,
        SnapshotStore(tmp_path / "snapshots"),
        actions={"fake": action},
    )
    assert result.rolled_back
    assert result.rollback_failed is True


def test_apply_success_keeps_changes(
    tmp_path: Path,
    make_snapshot: Callable[..., SystemSnapshot],
    fake_executor,
) -> None:
    target = tmp_path / "app.conf"
    target.write_text("before\n", encoding="utf-8")
    plan = ChangePlan(
        action="fake",
        title="fake",
        changes=(Change(target=str(target), method="dropin", after="after\n"),),
        targets=(str(target),),
    )
    plan_set = HardeningPlanSet(plans=(plan,), skipped=())
    action = _GoodAction()

    result = apply_plans(
        plan_set,
        fake_executor,
        SnapshotStore(tmp_path / "snapshots"),
        actions={"fake": action},
    )
    assert result.rolled_back is False
    assert result.results[0].verified is True
    assert result.snapshot_id is not None
