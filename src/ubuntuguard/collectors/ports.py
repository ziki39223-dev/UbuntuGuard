"""Listening port collector based on `ss`."""

from __future__ import annotations

import re

from ..core.executor import CommandExecutor
from ..models import PortInfo

_PROCESS_RE = re.compile(r'\(\("([^"]+)",pid=(\d+)')


def collect_ports(executor: CommandExecutor) -> tuple[PortInfo, ...]:
    output = executor.run(["ss", "-tulpn"], check=True).stdout
    return parse_ss(output)


def parse_ss(text: str) -> tuple[PortInfo, ...]:
    ports: list[PortInfo] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("Netid"):
            continue
        parts = line.split(maxsplit=6)
        if len(parts) < 5:
            continue
        protocol = parts[0]
        state = parts[1]
        local = parts[4]
        address, port = _split_local(local)
        if port is None:
            continue
        process = None
        if len(parts) > 6:
            match = _PROCESS_RE.search(parts[6])
            if match:
                process = f"{match.group(1)}({match.group(2)})"
        ports.append(
            PortInfo(
                protocol=protocol,
                local_address=address,
                port=port,
                state=state,
                process=process,
            )
        )
    return tuple(ports)


def _split_local(value: str) -> tuple[str, int | None]:
    address, _, raw_port = value.rpartition(":")
    address = address.split("%")[0]
    if not address or not raw_port.isdigit():
        return value, None
    return address, int(raw_port)
