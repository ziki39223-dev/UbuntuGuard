"""Hardening plan and result rendering."""

from __future__ import annotations

import difflib
from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..models import Change, ChangePlan
from ..security.hardening.engine import HardeningPlanSet, HardeningResult

_MAX_DIFF_LINES = 60


def build_hardening_report(
    plan_set: HardeningPlanSet,
    result: HardeningResult | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "tool_version": __version__,
        "generated_at": datetime.now(tz=timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds"),
        "plans": [_plan_to_dict(plan) for plan in plan_set.plans],
        "skipped": list(plan_set.skipped),
    }
    if result is not None:
        payload["result"] = {
            "snapshot_id": result.snapshot_id,
            "rolled_back": result.rolled_back,
            "rollback_failed": result.rollback_failed,
            "actions": [
                {
                    "action": item.action,
                    "applied": item.applied,
                    "verified": item.verified,
                    "detail": item.detail,
                }
                for item in result.results
            ],
        }
    return payload


def render_plan(plan_set: HardeningPlanSet) -> str:
    lines = ["UbuntuGuard hardening plan", ""]
    if not plan_set.plans:
        lines.append("no changes planned")
    for plan in plan_set.plans:
        lines.append(f"[{plan.action}] {plan.title}")
        if plan.risk:
            lines.append(f"  risk: {plan.risk}")
        for change in plan.changes:
            lines.extend(_render_change(change))
        lines.append("")

    if plan_set.skipped:
        lines.append("skipped:")
        lines.extend(f"  {reason}" for reason in plan_set.skipped)
    return "\n".join(lines).rstrip()


def render_result(result: HardeningResult, plan_set: HardeningPlanSet) -> str:
    lines = [render_plan(plan_set), "", "apply result:"]
    for item in result.results:
        lines.append(
            f"  [{item.action}] applied={item.applied} verified={item.verified} "
            f"{item.detail}"
        )
    if result.snapshot_id:
        lines.append(f"  snapshot: {result.snapshot_id}")
    if result.rolled_back:
        state = "failed" if result.rollback_failed else "succeeded"
        lines.append(f"  rollback: {state}")
    return "\n".join(lines)


def _plan_to_dict(plan: ChangePlan) -> dict[str, Any]:
    return {
        "action": plan.action,
        "title": plan.title,
        "risk": plan.risk,
        "changes": [
            {
                "target": change.target,
                "method": change.method,
                "before": change.before,
                "after": change.after,
                "note": change.note,
                "rollback": change.rollback,
            }
            for change in plan.changes
        ],
    }


def _render_change(change: Change) -> list[str]:
    if change.method == "dropin":
        lines = [f"  ~ {change.target}"]
        diff = list(
            difflib.unified_diff(
                change.before.splitlines(),
                change.after.splitlines(),
                fromfile="current",
                tofile="desired",
                lineterm="",
            )
        )
        if not diff:
            lines.append("    (no content change)")
            return lines
        truncated = diff[:_MAX_DIFF_LINES]
        lines.extend(f"    {line}" for line in truncated)
        if len(diff) > _MAX_DIFF_LINES:
            lines.append("    ... (diff truncated)")
        return lines
    if change.method == "package":
        return [f"  + package: {change.after}", f"    note: {change.note}"]
    return [f"  $ {change.after}"]
