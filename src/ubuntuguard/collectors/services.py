"""Running systemd service collector."""

from __future__ import annotations

from ..core.executor import CommandExecutor
from ..models import ServiceInfo


def collect_services(executor: CommandExecutor) -> tuple[ServiceInfo, ...]:
    output = executor.run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        check=True,
    ).stdout
    return parse_services(output)


def parse_services(text: str) -> tuple[ServiceInfo, ...]:
    services: list[ServiceInfo] = []
    for line in text.splitlines():
        cleaned = line.lstrip("\u25cf*\u00d7 ").strip()
        if not cleaned:
            continue
        parts = cleaned.split(maxsplit=4)
        if len(parts) < 4:
            continue
        services.append(
            ServiceInfo(
                name=parts[0],
                load=parts[1],
                active=parts[2],
                sub=parts[3],
                description=parts[4] if len(parts) > 4 else "",
            )
        )
    return tuple(services)
