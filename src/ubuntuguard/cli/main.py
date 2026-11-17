"""CLI entry point."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from .. import __version__
from ..core.config import load_config
from ..core.logger import setup_logging
from ..errors import UbuntuGuardError
from ..exit_codes import ExitCode
from . import commands

_EPILOG = """examples:
  ubuntuguard doctor
  ubuntuguard config validate
  ubuntuguard --config ./configs/config.example.yaml config show
  ubuntuguard --json doctor
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ubuntuguard",
        description="Ubuntu security baseline audit and reversible hardening.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="config file (default: /etc/ubuntuguard/config.yaml)",
    )
    parser.add_argument(
        "--log-level",
        choices=("debug", "info", "warning", "error"),
        help="override general.log_level from config",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON on stdout")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="force preview mode for mutating commands",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip interactive confirmation (requires --apply)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ubuntuguard {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.add_parser("version", help="print version and exit")
    subparsers.add_parser(
        "doctor", help="check platform, privileges and dependencies"
    )
    collect_parser = subparsers.add_parser(
        "collect", help="collect host inventory (read-only)"
    )
    collect_parser.add_argument(
        "--output",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    audit_parser = subparsers.add_parser(
        "audit", help="run the security baseline audit (read-only)"
    )
    audit_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        help="exit with code 4 when findings reach this severity",
    )
    audit_parser.add_argument(
        "--engine",
        choices=("native", "lynis", "all"),
        help="audit engine: built-in rules, Lynis backend, or both",
    )

    detect_parser = subparsers.add_parser(
        "detect", help="analyze authentication, integrity and process anomalies"
    )
    detect_parser.add_argument(
        "--init-baseline",
        action="store_true",
        help="write the critical file checksum baseline",
    )
    detect_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        help="exit with code 4 when findings reach this severity",
    )

    monitor_parser = subparsers.add_parser(
        "monitor", help="system health monitoring and alerts"
    )
    monitor_actions = monitor_parser.add_subparsers(
        dest="monitor_action", metavar="ACTION"
    )
    monitor_check = monitor_actions.add_parser(
        "check", help="evaluate health metrics and send alerts"
    )
    monitor_check.add_argument(
        "--no-notify",
        action="store_true",
        help="skip the webhook notification",
    )
    monitor_check.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        help="exit with code 4 when findings reach this severity",
    )

    backup_parser = subparsers.add_parser(
        "backup", help="create, verify and restore configuration backups"
    )
    backup_actions = backup_parser.add_subparsers(
        dest="backup_action", metavar="ACTION"
    )
    backup_create = backup_actions.add_parser(
        "create", help="create a configuration backup (requires root)"
    )
    backup_create.add_argument(
        "--paths",
        metavar="PATHS",
        help="comma separated files, directories or glob patterns",
    )
    backup_create.add_argument(
        "--label", default="backup", help="snapshot label (default: backup)"
    )
    backup_actions.add_parser("list", help="list snapshots")
    backup_verify = backup_actions.add_parser(
        "verify", help="verify snapshot checksums"
    )
    backup_verify.add_argument("snapshot_id")
    backup_restore = backup_actions.add_parser(
        "restore", help="restore a snapshot (requires root)"
    )
    backup_restore.add_argument("snapshot_id")
    backup_restore.add_argument(
        "--force",
        action="store_true",
        help="restore even when files differ from the snapshot",
    )
    backup_drill = backup_actions.add_parser(
        "drill", help="restore into a temporary directory and verify"
    )
    backup_drill.add_argument("snapshot_id")

    report_parser = subparsers.add_parser(
        "report", help="generate a combined audit, detection and health report"
    )
    report_parser.add_argument(
        "--format", choices=("html", "json"), default="html",
        help="output format (default: html)",
    )
    report_parser.add_argument(
        "--out", metavar="PATH", help="write to a file instead of stdout"
    )

    export_parser = subparsers.add_parser(
        "export", help="export configuration to other tooling"
    )
    export_actions = export_parser.add_subparsers(
        dest="export_action", metavar="TARGET"
    )
    export_ansible = export_actions.add_parser(
        "ansible", help="export an Ansible hardening playbook"
    )
    export_ansible.add_argument("--out", metavar="PATH")

    systemd_parser = subparsers.add_parser(
        "systemd", help="install or remove systemd timers"
    )
    systemd_actions = systemd_parser.add_subparsers(
        dest="systemd_action", metavar="ACTION"
    )
    systemd_install = systemd_actions.add_parser(
        "install", help="install units and enable timers (requires root)"
    )
    systemd_install.add_argument(
        "--interval", default="6h", help="audit report interval (default: 6h)"
    )
    systemd_install.add_argument(
        "--monitor-interval",
        default="5min",
        help="health check interval (default: 5min)",
    )
    systemd_actions.add_parser(
        "uninstall", help="disable timers and remove units (requires root)"
    )

    harden_parser = subparsers.add_parser(
        "harden", help="plan or apply security hardening"
    )
    harden_actions = harden_parser.add_subparsers(
        dest="harden_action", metavar="ACTION"
    )
    plan_parser = harden_actions.add_parser(
        "plan", help="preview changes without touching the system"
    )
    plan_parser.add_argument(
        "--only", metavar="ACTIONS", help="comma separated: ssh,sysctl,firewall,fail2ban"
    )
    apply_parser = harden_actions.add_parser(
        "apply", help="apply changes; requires --apply --yes"
    )
    apply_parser.add_argument(
        "--only", metavar="ACTIONS", help="comma separated: ssh,sysctl,firewall,fail2ban"
    )
    apply_parser.add_argument(
        "--apply", action="store_true", help="actually write changes"
    )
    apply_parser.add_argument(
        "--yes",
        action="store_true",
        default=argparse.SUPPRESS,
        help="skip confirmation (same as the global --yes)",
    )
    apply_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="preview only, even with --apply --yes",
    )

    config_parser = subparsers.add_parser(
        "config", help="inspect or validate configuration"
    )
    config_actions = config_parser.add_subparsers(
        dest="config_action", metavar="ACTION"
    )
    config_actions.add_parser("show", help="print effective configuration")
    config_actions.add_parser("validate", help="validate configuration")

    web_parser = subparsers.add_parser(
        "web", help="start the local read/write web console"
    )
    web_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address (default: 127.0.0.1)",
    )
    web_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="listen port (default: 8080)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return int(ExitCode.USAGE)

    if args.command == "version":
        return commands.cmd_version(args.json)

    if args.command == "web":
        from ..web.server import serve

        return serve(args.host, args.port, args.config)

    try:
        config = load_config(args.config)
        log_level = args.log_level or str(config.get("general.log_level", "info"))
        log_dir = config.get("general.log_dir") if os.name == "posix" else None
        logger = setup_logging(level=log_level, log_dir=log_dir)
        for warning in config.warnings:
            logger.warning(warning)

        if args.command == "doctor":
            return commands.cmd_doctor(config, args.json)

        if args.command == "collect":
            return commands.cmd_collect(config, args.json, args.output)

        if args.command == "audit":
            return commands.cmd_audit(config, args.json, args.fail_on, args.engine)

        if args.command == "detect":
            return commands.cmd_detect(
                config, args.json, args.fail_on, args.init_baseline
            )

        if args.command == "monitor":
            return commands.cmd_monitor(
                config,
                args.json,
                args.monitor_action,
                not getattr(args, "no_notify", False),
                getattr(args, "fail_on", None),
            )

        if args.command == "backup":
            return commands.cmd_backup(
                config,
                args.json,
                args.backup_action,
                getattr(args, "snapshot_id", None),
                getattr(args, "paths", None),
                getattr(args, "label", "backup"),
                getattr(args, "force", False),
            )

        if args.command == "report":
            return commands.cmd_report(config, args.json, args.format, args.out)

        if args.command == "export":
            return commands.cmd_export(
                config, args.json, args.export_action, getattr(args, "out", None)
            )

        if args.command == "systemd":
            return commands.cmd_systemd(
                config,
                args.json,
                args.systemd_action,
                getattr(args, "interval", "6h"),
                getattr(args, "monitor_interval", "5min"),
            )

        if args.command == "harden":
            if args.harden_action not in {"plan", "apply"}:
                print(
                    "ubuntuguard: error: missing harden action (plan|apply)",
                    file=sys.stderr,
                )
                return int(ExitCode.USAGE)
            return commands.cmd_harden(
                config,
                args.json,
                args.harden_action,
                args.only,
                getattr(args, "apply", False),
                getattr(args, "yes", False),
                getattr(args, "dry_run", False),
            )

        if args.command == "config":
            if args.config_action == "show":
                return commands.cmd_config_show(config, args.json)
            if args.config_action == "validate":
                return commands.cmd_config_validate(config, args.json)
            print(
                "ubuntuguard: error: missing config action (show|validate)",
                file=sys.stderr,
            )
            return int(ExitCode.USAGE)
    except UbuntuGuardError as exc:
        print(f"ubuntuguard: error: {exc}", file=sys.stderr)
        return int(exc.exit_code)
    except KeyboardInterrupt:
        print("ubuntuguard: interrupted", file=sys.stderr)
        return 130

    return int(ExitCode.USAGE)


if __name__ == "__main__":
    sys.exit(main())
