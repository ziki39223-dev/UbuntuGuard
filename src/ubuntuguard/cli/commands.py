"""CLI command handlers."""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

import yaml

from .. import __version__
from ..audit import run_detection
from ..backup import (
    DEFAULT_BACKUP_PATHS,
    FileDiff,
    SnapshotInfo,
    SnapshotStore,
    expand_paths,
)
from ..collectors import collect_system
from ..core.config import Config
from ..core.executor import CommandExecutor
from ..core.permissions import check_environment, require_root
from ..errors import UbuntuGuardError
from ..exit_codes import ExitCode
from ..integrations import LynisEngine, build_ansible_playbook
from ..models import Finding, SystemSnapshot
from ..monitoring import collect_metrics, evaluate_health
from ..notifications import WebhookNotifier
from ..reporting import (
    build_detection_report,
    build_hardening_report,
    build_monitoring_report,
    build_report,
    render_detection_text,
    render_html_report,
    render_monitoring_text,
    render_plan,
    render_result,
    render_text,
)
from ..security.baseline import meets_threshold, run_audit
from ..security.hardening import ACTION_NAMES, apply_plans, build_plans
from ..systemd import install as install_units
from ..systemd import uninstall as uninstall_units
from ..systemd import valid_interval

REQUIRED_DEPENDENCIES = ("ufw", "fail2ban-client", "auditctl", "aide")


def cmd_version(as_json: bool) -> int:
    if as_json:
        print(json.dumps({"name": "ubuntuguard", "version": __version__}))
    else:
        print(f"ubuntuguard {__version__}")
    return int(ExitCode.OK)


def cmd_doctor(config: Config, as_json: bool) -> int:
    status = check_environment(REQUIRED_DEPENDENCIES)
    config_path = str(config.path) if config.path is not None else None

    if as_json:
        payload = {
            "version": __version__,
            "platform": status.as_dict(),
            "config": {
                "path": config_path,
                "source": config.source,
                "warnings": config.warnings,
            },
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("UbuntuGuard doctor")
        print(f"  version      : {__version__}")
        print(
            f"  platform     : {status.os_id} {status.version_id} "
            f"(supported: {'yes' if status.supported else 'no'})"
        )
        print(f"  root         : {'yes' if status.is_root else 'no'}")
        print(f"  python       : {status.python_version}")
        print(f"  config       : {config_path or 'built-in defaults'} ({config.source})")
        print("  dependencies :")
        for name in REQUIRED_DEPENDENCIES:
            state = "missing" if name in status.missing_dependencies else "ok"
            print(f"    {name:<16} {state}")
        for warning in config.warnings:
            print(f"  warning      : {warning}")

    return int(ExitCode.OK if status.supported else ExitCode.UNSUPPORTED)


def cmd_collect(config: Config, as_json: bool, output: str) -> int:
    timeout = float(config.get("general.timeout_seconds", 30))
    snapshot = collect_system(CommandExecutor(timeout=timeout))
    if as_json or output == "json":
        print(json.dumps(asdict(snapshot), ensure_ascii=False, indent=2))
    else:
        _print_snapshot(snapshot)
    return int(ExitCode.OK)


def cmd_audit(
    config: Config,
    as_json: bool,
    fail_on: str | None,
    engine: str | None,
) -> int:
    timeout = float(config.get("general.timeout_seconds", 30))
    executor = CommandExecutor(timeout=timeout)
    snapshot = collect_system(executor)
    selected_engine = engine or str(config.get("audit.engine", "native"))

    extra_findings: list[Finding] = []
    extra_skipped: list[str] = []
    extra_evaluated = 0

    if selected_engine in {"lynis", "all"}:
        lynis = LynisEngine(executor)
        if lynis.available():
            extra_findings = lynis.collect_findings()
            extra_evaluated = 1
        else:
            extra_skipped.append("LYNIS: lynis is not installed")

    if selected_engine == "lynis":
        result = run_audit(
            snapshot,
            config,
            rules=(),
            extra_findings=extra_findings,
            extra_skipped=extra_skipped,
            extra_evaluated=extra_evaluated,
        )
    else:
        result = run_audit(
            snapshot,
            config,
            extra_findings=extra_findings,
            extra_skipped=extra_skipped,
            extra_evaluated=extra_evaluated,
        )

    if as_json:
        print(json.dumps(build_report(result, snapshot), ensure_ascii=False, indent=2))
    else:
        print(render_text(result, snapshot))

    level = fail_on or str(config.get("audit.fail_on", "high"))
    evaluated = result.passed + len(result.findings) + extra_evaluated
    if evaluated == 0:
        return int(ExitCode.UNSUPPORTED)
    if meets_threshold(result.findings, level):
        return int(ExitCode.AUDIT_FINDINGS)
    return int(ExitCode.OK)


def cmd_harden(
    config: Config,
    as_json: bool,
    action: str,
    only: str | None,
    apply_changes: bool,
    assume_yes: bool,
    dry_run: bool,
) -> int:
    only_names: tuple[str, ...] | None = None
    if only:
        only_names = tuple(part.strip() for part in only.split(",") if part.strip())
        unknown = [name for name in only_names if name not in ACTION_NAMES]
        if unknown:
            print(
                "ubuntuguard: error: unknown hardening action(s): "
                f"{', '.join(unknown)}; choose from {', '.join(ACTION_NAMES)}",
                file=sys.stderr,
            )
            return int(ExitCode.USAGE)

    timeout = float(config.get("general.timeout_seconds", 30))
    executor = CommandExecutor(timeout=timeout)
    snapshot = collect_system(executor)
    plan_set = build_plans(snapshot, config, only_names)

    preview = action == "plan" or dry_run or not (apply_changes and assume_yes)
    if preview or not plan_set.plans:
        if as_json:
            print(
                json.dumps(
                    build_hardening_report(plan_set), ensure_ascii=False, indent=2
                )
            )
        else:
            print(render_plan(plan_set))
        if action == "apply" and not plan_set.plans:
            return int(ExitCode.OK)
        if action == "apply":
            print(
                "preview only; re-run with --apply --yes to modify the system",
                file=sys.stderr,
            )
        return int(ExitCode.OK)

    require_root("hardening apply")
    state_dir = Path(
        str(config.get("general.state_dir", "/var/lib/ubuntuguard"))
    ) / "snapshots"
    result = apply_plans(plan_set, executor, SnapshotStore(state_dir))

    if as_json:
        print(
            json.dumps(
                build_hardening_report(plan_set, result),
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(render_result(result, plan_set))

    if result.rollback_failed:
        return int(ExitCode.ROLLBACK_FAILED)
    if result.rolled_back:
        return int(ExitCode.ROLLED_BACK)
    if any(not item.verified for item in result.results):
        return int(ExitCode.PARTIAL)
    return int(ExitCode.OK)


def cmd_detect(
    config: Config,
    as_json: bool,
    fail_on: str | None,
    init_baseline: bool,
) -> int:
    timeout = float(config.get("general.timeout_seconds", 30))
    executor = CommandExecutor(timeout=timeout)
    state_dir = None
    if os.name == "posix":
        state_dir = Path(
            str(config.get("general.state_dir", "/var/lib/ubuntuguard"))
        )

    result = run_detection(
        executor,
        config,
        state_dir=state_dir,
        init_baseline=init_baseline,
    )

    if as_json:
        print(
            json.dumps(
                build_detection_report(result), ensure_ascii=False, indent=2
            )
        )
    else:
        print(render_detection_text(result))

    level = fail_on or str(config.get("audit.fail_on", "high"))
    if meets_threshold(result.findings, level):
        return int(ExitCode.AUDIT_FINDINGS)
    return int(ExitCode.OK)


def cmd_monitor(
    config: Config,
    as_json: bool,
    action: str,
    notify: bool,
    fail_on: str | None,
) -> int:
    if action != "check":
        print(
            "ubuntuguard: error: missing monitor action (check)",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)

    timeout = float(config.get("general.timeout_seconds", 30))
    executor = CommandExecutor(timeout=timeout)
    metrics = collect_metrics(config, executor)
    state_dir = None
    if os.name == "posix":
        state_dir = Path(
            str(config.get("general.state_dir", "/var/lib/ubuntuguard"))
        )

    report = evaluate_health(metrics, config, state_dir)
    payload = build_monitoring_report(report)
    payload["host"] = socket.gethostname()

    notification: tuple[bool, str] | None = None
    if notify and bool(config.get("monitoring.webhook.enabled", False)):
        if report.findings:
            notifier = WebhookNotifier(
                str(config.get("monitoring.webhook.url", "")),
                timeout=float(
                    config.get("monitoring.webhook.timeout_seconds", 5)
                ),
                retries=int(config.get("notifications.retry", 2)),
                retry_interval=float(
                    config.get("notifications.retry_interval_seconds", 3)
                ),
            )
            notification = notifier.send(payload)
        else:
            notification = (False, "no findings; notification skipped")
        payload["notification"] = {
            "sent": notification[0],
            "detail": notification[1],
        }

    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_monitoring_text(report))
        if notification is not None:
            state = "sent" if notification[0] else "not sent"
            print(f"notification: {state} - {notification[1]}")

    level = fail_on or str(config.get("audit.fail_on", "high"))
    if meets_threshold(report.findings, level):
        return int(ExitCode.AUDIT_FINDINGS)
    return int(ExitCode.OK)


def cmd_backup(
    config: Config,
    as_json: bool,
    action: str,
    snapshot_id: str | None,
    paths: str | None,
    label: str,
    force: bool,
) -> int:
    valid_actions = {"create", "list", "verify", "restore", "drill"}
    if action not in valid_actions:
        print(
            "ubuntuguard: error: missing backup action "
            "(create|list|verify|restore|drill)",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)
    if os.name != "posix" and config.source != "file":
        print(
            "ubuntuguard: error: backup requires Linux paths; "
            "provide a config file with explicit state/backup directories",
            file=sys.stderr,
        )
        return int(ExitCode.UNSUPPORTED)

    backup_dir = Path(
        str(config.get("backup.dir", "/var/lib/ubuntuguard/backups"))
    )
    store = SnapshotStore(backup_dir)

    if action == "create":
        require_root("backup create")
        patterns = (
            tuple(part.strip() for part in paths.split(","))
            if paths
            else DEFAULT_BACKUP_PATHS
        )
        files = expand_paths(patterns, include_missing=True)
        if not files:
            print(
                "ubuntuguard: error: no files matched the backup paths",
                file=sys.stderr,
            )
            return int(ExitCode.INTERNAL)
        compress = bool(config.get("backup.compress", True))
        snapshot = store.create(files, label=label or "backup", compress=compress)
        removed = store.prune(
            int(config.get("backup.retention_days", 30)),
            int(config.get("backup.retention_count", 20)),
        )
        payload = {
            "snapshot_id": snapshot.snapshot_id,
            "files": len(files),
            "compressed": compress,
            "removed": list(removed),
        }
        if as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"snapshot : {snapshot.snapshot_id}")
            print(f"files    : {len(files)}")
            print(f"compressed: {compress}")
            if removed:
                print(f"pruned   : {', '.join(removed)}")
        return int(ExitCode.OK)

    if action == "list":
        infos = store.list()
        if as_json:
            print(
                json.dumps(
                    {"snapshots": [_snapshot_info(info) for info in infos]},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            if not infos:
                print("no snapshots")
            for info in infos:
                print(
                    f"{info.snapshot_id}  files={info.files}  "
                    f"compressed={info.compressed}  created={info.created_at}"
                )
        return int(ExitCode.OK)

    if not snapshot_id:
        print("ubuntuguard: error: snapshot id required", file=sys.stderr)
        return int(ExitCode.USAGE)
    try:
        snapshot = store.load(snapshot_id)
    except OSError as exc:
        print(f"ubuntuguard: error: {exc}", file=sys.stderr)
        return int(ExitCode.INTERNAL)

    if action == "verify":
        valid = store.verify(snapshot)
        if as_json:
            print(
                json.dumps(
                    {"snapshot_id": snapshot.snapshot_id, "valid": valid},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            state = "valid" if valid else "INVALID"
            print(f"snapshot {snapshot.snapshot_id}: {state}")
        return int(ExitCode.OK) if valid else int(ExitCode.INTERNAL)

    if action == "drill":
        with tempfile.TemporaryDirectory(prefix="ubuntuguard-drill-") as tmp:
            try:
                restored = store.drill(snapshot, Path(tmp))
            except OSError as exc:
                print(f"ubuntuguard: error: {exc}", file=sys.stderr)
                return int(ExitCode.INTERNAL)
        if as_json:
            print(
                json.dumps(
                    {
                        "snapshot_id": snapshot.snapshot_id,
                        "files": restored,
                        "ok": True,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(
                f"drill ok: restored {restored} file(s) to a temporary "
                "directory and verified SHA256"
            )
        return int(ExitCode.OK)

    require_root("backup restore")
    changes = [item for item in store.diff(snapshot) if item.status != "unchanged"]
    if changes and not force:
        if as_json:
            print(
                json.dumps(
                    {
                        "snapshot_id": snapshot.snapshot_id,
                        "restored": False,
                        "changes": [_diff_dict(item) for item in changes],
                        "hint": "re-run with --force to restore",
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print("restore would change these files:")
            for item in changes:
                print(f"  {item.status:<9} {item.path}")
            print("re-run with --force to restore")
        return int(ExitCode.USAGE)

    try:
        store.restore(snapshot)
    except OSError as exc:
        print(f"ubuntuguard: error: {exc}", file=sys.stderr)
        return int(ExitCode.INTERNAL)

    remaining = [item for item in store.diff(snapshot) if item.status != "unchanged"]
    verified = not remaining
    if as_json:
        print(
            json.dumps(
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "restored": True,
                    "changes": [_diff_dict(item) for item in changes],
                    "verified": verified,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        state = "ok" if verified else "FAILED"
        print(f"restored {snapshot.snapshot_id}; verification: {state}")
    return int(ExitCode.OK) if verified else int(ExitCode.INTERNAL)


def _snapshot_info(info: SnapshotInfo) -> dict[str, object]:
    return {
        "snapshot_id": info.snapshot_id,
        "created_at": info.created_at,
        "files": info.files,
        "compressed": info.compressed,
    }


def _diff_dict(item: FileDiff) -> dict[str, object]:
    return {
        "path": item.path,
        "status": item.status,
        "snapshot_sha256": item.snapshot_sha256,
        "current_sha256": item.current_sha256,
    }


def cmd_report(
    config: Config,
    as_json: bool,
    report_format: str,
    out: str | None,
) -> int:
    timeout = float(config.get("general.timeout_seconds", 30))
    executor = CommandExecutor(timeout=timeout)
    snapshot = collect_system(executor)
    audit_result = run_audit(snapshot, config)

    state_dir = None
    if os.name == "posix":
        state_dir = Path(
            str(config.get("general.state_dir", "/var/lib/ubuntuguard"))
        )
    detection = run_detection(executor, config, state_dir=state_dir)
    health = evaluate_health(collect_metrics(config, executor), config, state_dir)

    host = snapshot.host
    payload = {
        "schema_version": "1.0",
        "tool_version": __version__,
        "generated_at": audit_result.generated_at,
        "host": {
            "hostname": host.hostname,
            "os": host.os_pretty_name or f"{host.os_id} {host.os_version}",
            "kernel": host.kernel,
        },
        "audit": build_report(audit_result, snapshot),
        "detection": build_detection_report(detection),
        "monitoring": build_monitoring_report(health),
    }

    if as_json or report_format == "json":
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        text = render_html_report(payload)

    if out:
        target = Path(out)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"ubuntuguard: error: {exc}", file=sys.stderr)
            return int(ExitCode.INTERNAL)
        print(f"report written: {target}")
    else:
        print(text)
    return int(ExitCode.OK)


def cmd_export(
    config: Config,
    as_json: bool,
    action: str,
    out: str | None,
) -> int:
    if action != "ansible":
        print(
            "ubuntuguard: error: missing export action (ansible)",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)

    playbook = build_ansible_playbook(config)
    text = yaml.safe_dump(playbook, sort_keys=False, allow_unicode=True)
    if out:
        target = Path(out)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"ubuntuguard: error: {exc}", file=sys.stderr)
            return int(ExitCode.INTERNAL)
        print(f"playbook written: {target}")
    else:
        print(text, end="")
    return int(ExitCode.OK)


def cmd_systemd(
    config: Config,
    as_json: bool,
    action: str,
    interval: str,
    monitor_interval: str,
) -> int:
    if action not in {"install", "uninstall"}:
        print(
            "ubuntuguard: error: missing systemd action (install|uninstall)",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)
    if os.name != "posix":
        print(
            "ubuntuguard: error: systemd integration requires Linux",
            file=sys.stderr,
        )
        return int(ExitCode.UNSUPPORTED)
    for value in (interval, monitor_interval):
        if value and not valid_interval(value):
            print(
                f"ubuntuguard: error: invalid interval: {value!r} "
                "(expected e.g. 30m, 6h, 1d)",
                file=sys.stderr,
            )
            return int(ExitCode.USAGE)

    require_root(f"systemd {action}")
    executor = CommandExecutor(
        timeout=float(config.get("general.timeout_seconds", 30))
    )

    try:
        if action == "install":
            binary = shutil.which("ubuntuguard") or "/usr/bin/ubuntuguard"
            files = install_units(
                executor,
                interval=interval or "6h",
                monitor_interval=monitor_interval or "5min",
                binary=binary,
            )
            payload = {"action": "install", "files": list(files)}
            if not as_json:
                print("systemd units installed:")
                for path in files:
                    print(f"  {path}")
                print("timers enabled: ubuntuguard-audit.timer, "
                      "ubuntuguard-monitor.timer")
        else:
            removed = uninstall_units(executor)
            payload = {"action": "uninstall", "removed": list(removed)}
            if not as_json:
                print("systemd units removed:")
                for path in removed:
                    print(f"  {path}")
        if as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
    except (OSError, UbuntuGuardError) as exc:
        print(f"ubuntuguard: error: {exc}", file=sys.stderr)
        return int(ExitCode.INTERNAL)
    return int(ExitCode.OK)


def _print_snapshot(snapshot: SystemSnapshot) -> None:
    host = snapshot.host
    print(f"host      : {host.hostname}")
    os_label = host.os_pretty_name or f"{host.os_id} {host.os_version}"
    print(f"os        : {os_label}")
    print(f"kernel    : {host.kernel}")
    if host.uptime_seconds is not None:
        print(f"uptime    : {_format_uptime(host.uptime_seconds)}")

    load = "/".join(f"{value:.2f}" for value in snapshot.cpu.load_average) or "n/a"
    print(f"cpu       : {snapshot.cpu.cores} cores, load {load}, {snapshot.cpu.model}")

    memory = snapshot.memory
    print(
        f"memory    : {_format_bytes(memory.used_bytes)} / "
        f"{_format_bytes(memory.total_bytes)} ({memory.used_percent}%)"
    )

    for disk in snapshot.disks:
        print(
            f"disk      : {disk.mountpoint} [{disk.fstype}] "
            f"{_format_bytes(disk.used_bytes)}/{_format_bytes(disk.total_bytes)} "
            f"({disk.used_percent}%)"
        )

    for interface in snapshot.network.interfaces:
        addresses = ", ".join(interface.addresses) or "-"
        print(
            f"network   : {interface.name} {addresses} "
            f"state={interface.state or '-'} mac={interface.mac or '-'}"
        )
    for gateway in snapshot.network.default_gateways:
        print(f"gateway   : {gateway}")

    print(f"users     : {len(snapshot.users)}")
    print(f"services  : {len(snapshot.services)} running")
    print(f"ports     : {len(snapshot.ports)} listening")
    for port in snapshot.ports[:10]:
        print(
            f"  {port.protocol:<4} {port.local_address}:{port.port:<5} "
            f"{port.state:<8} {port.process or '-'}"
        )
    print(
        f"packages  : {snapshot.packages.installed} installed, "
        f"{snapshot.packages.upgradable} upgradable, "
        f"reboot_required={snapshot.packages.reboot_required}"
    )
    for error in snapshot.errors:
        print(f"warning   : {error}")


_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def _format_bytes(value: int) -> str:
    size = float(value)
    for unit in _UNITS:
        if size < 1024 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


def _format_uptime(seconds: float) -> str:
    total = int(seconds)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def cmd_config_show(config: Config, as_json: bool) -> int:
    if as_json:
        print(json.dumps(config.data, ensure_ascii=False, indent=2))
    else:
        print(yaml.safe_dump(config.data, sort_keys=False, allow_unicode=True), end="")
    return int(ExitCode.OK)


def cmd_config_validate(config: Config, as_json: bool) -> int:
    location = str(config.path) if config.path is not None else "built-in defaults"
    config_path = str(config.path) if config.path is not None else None
    if as_json:
        payload = {
            "valid": True,
            "source": config.source,
            "path": config_path,
            "warnings": config.warnings,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"config valid: {location} ({len(config.warnings)} warning(s))")
        for warning in config.warnings:
            print(f"  warning: {warning}")
    return int(ExitCode.OK)
