"""Hardening report rendering tests."""

from __future__ import annotations

from ubuntuguard.models import ActionResult, Change, ChangePlan
from ubuntuguard.reporting import build_hardening_report, render_plan, render_result
from ubuntuguard.security.hardening import HardeningPlanSet, HardeningResult

PLAN = ChangePlan(
    action="ssh",
    title="SSH server hardening",
    changes=(
        Change(
            target="/etc/ssh/sshd_config.d/99-ubuntuguard.conf",
            method="dropin",
            before="PermitRootLogin yes\n",
            after="PermitRootLogin no\n",
            note="drop-in",
            rollback="restore backup",
        ),
    ),
    risk="lockout risk",
    targets=("/etc/ssh/sshd_config.d/99-ubuntuguard.conf",),
)


def test_render_plan_contains_diff_and_skips() -> None:
    text = render_plan(
        HardeningPlanSet(
            plans=(PLAN,), skipped=("firewall: ufw is not installed",)
        )
    )
    assert "[ssh] SSH server hardening" in text
    assert "risk: lockout risk" in text
    assert "--- current" in text
    assert "+++ desired" in text
    assert "firewall: ufw is not installed" in text


def test_build_report_and_render_result() -> None:
    result = HardeningResult(
        plans=(PLAN,),
        results=(ActionResult("ssh", applied=True, verified=True, detail="ok"),),
        skipped=(),
        snapshot_id="20261117T000000Z-harden",
    )
    payload = build_hardening_report(HardeningPlanSet((PLAN,), ()), result)

    assert payload["plans"][0]["action"] == "ssh"
    assert payload["plans"][0]["changes"][0]["method"] == "dropin"
    assert payload["result"]["snapshot_id"] == "20261117T000000Z-harden"

    text = render_result(result, HardeningPlanSet((PLAN,), ()))
    assert "applied=True verified=True" in text
    assert "snapshot: 20261117T000000Z-harden" in text
