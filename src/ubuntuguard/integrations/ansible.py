"""Ansible playbook export derived from the UbuntuGuard configuration.

This is the supported way to hand hardening to an existing Ansible workflow.
"""

from __future__ import annotations

from typing import Any

from ..core.config import Config
from ..security.fail2ban.actions import render_jail
from ..security.ssh.actions import render_sshd_dropin
from ..security.system.actions import render_sysctl_dropin


def build_ansible_playbook(
    config: Config, hosts: str = "all"
) -> dict[str, Any]:
    tasks: list[dict[str, Any]] = []
    handlers: list[dict[str, Any]] = []

    tasks.append(
        {
            "name": "Deploy SSH hardening drop-in",
            "ansible.builtin.copy": {
                "dest": "/etc/ssh/sshd_config.d/00-ubuntuguard.conf",
                "content": render_sshd_dropin(config),
                "owner": "root",
                "group": "root",
                "mode": "0644",
            },
            "notify": "Reload ssh",
        }
    )
    handlers.append(
        {
            "name": "Reload ssh",
            "ansible.builtin.service": {"name": "ssh", "state": "reloaded"},
        }
    )

    sysctl = config.get("sysctl", {}) or {}
    if sysctl:
        tasks.append(
            {
                "name": "Deploy sysctl hardening",
                "ansible.builtin.copy": {
                    "dest": "/etc/sysctl.d/99-ubuntuguard.conf",
                    "content": render_sysctl_dropin(sysctl),
                    "owner": "root",
                    "group": "root",
                    "mode": "0644",
                },
                "notify": "Reload sysctl",
            }
        )
        handlers.append(
            {
                "name": "Reload sysctl",
                "ansible.builtin.command": {"cmd": "sysctl --system"},
            }
        )

    firewall = config.get("firewall", {}) or {}
    if firewall.get("enabled", True):
        tasks.append(
            {
                "name": "Set firewall default incoming policy",
                "ansible.builtin.command": {
                    "cmd": (
                        "ufw default "
                        f"{firewall.get('default_incoming', 'deny')} incoming"
                    )
                },
                "changed_when": False,
            }
        )
        for port in firewall.get("allow_ports", []) or []:
            tasks.append(
                {
                    "name": f"Allow {port}",
                    "ansible.builtin.command": {"cmd": f"ufw allow {port}"},
                    "changed_when": False,
                }
            )
        tasks.append(
            {
                "name": "Enable UFW",
                "ansible.builtin.command": {"cmd": "ufw --force enable"},
                "changed_when": False,
            }
        )

    fail2ban = config.get("fail2ban", {}) or {}
    if fail2ban.get("enabled", True):
        tasks.append(
            {
                "name": "Install Fail2ban",
                "ansible.builtin.apt": {
                    "name": "fail2ban",
                    "state": "present",
                    "update_cache": True,
                },
            }
        )
        tasks.append(
            {
                "name": "Deploy Fail2ban jail",
                "ansible.builtin.copy": {
                    "dest": "/etc/fail2ban/jail.d/99-ubuntuguard.local",
                    "content": render_jail(config),
                    "owner": "root",
                    "group": "root",
                    "mode": "0644",
                },
                "notify": "Restart fail2ban",
            }
        )
        handlers.append(
            {
                "name": "Restart fail2ban",
                "ansible.builtin.service": {
                    "name": "fail2ban",
                    "state": "restarted",
                },
            }
        )

    return {
        "name": "UbuntuGuard hardening",
        "hosts": hosts,
        "become": True,
        "tasks": tasks,
        "handlers": handlers,
    }
