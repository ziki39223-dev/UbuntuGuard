"""Network interface and address collector."""

from __future__ import annotations

from ..core.executor import CommandExecutor
from ..models import NetworkInfo, NetworkInterface


def collect_network(executor: CommandExecutor) -> NetworkInfo:
    address_output = executor.run(["ip", "-o", "addr", "show"], check=True).stdout
    link_output = executor.run(["ip", "-o", "link", "show"], check=True).stdout
    route_output = executor.run(
        ["ip", "-4", "route", "show", "default"], check=True
    ).stdout
    return NetworkInfo(
        interfaces=parse_interfaces(address_output, link_output),
        default_gateways=parse_default_gateways(route_output),
    )


def parse_interfaces(addr_text: str, link_text: str) -> tuple[NetworkInterface, ...]:
    states, macs = _parse_link(link_text)

    addresses: dict[str, list[str]] = {}
    for line in addr_text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = _clean_name(parts[1])
        family = parts[2]
        if family not in {"inet", "inet6"}:
            continue
        addresses.setdefault(name, []).append(parts[3])

    names = list(states) + [name for name in addresses if name not in states]
    return tuple(
        NetworkInterface(
            name=name,
            addresses=tuple(addresses.get(name, ())),
            mac=macs.get(name),
            state=states.get(name),
        )
        for name in names
    )


def parse_default_gateways(text: str) -> tuple[str, ...]:
    gateways: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        if "via" in parts:
            index = parts.index("via")
            if index + 1 < len(parts) and parts[index + 1] not in gateways:
                gateways.append(parts[index + 1])
    return tuple(gateways)


def _parse_link(text: str) -> tuple[dict[str, str], dict[str, str]]:
    states: dict[str, str] = {}
    macs: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = _clean_name(parts[1])
        states.setdefault(name, "")
        for index, token in enumerate(parts):
            if index + 1 >= len(parts):
                continue
            if token == "state" and not states[name]:
                states[name] = parts[index + 1]
            elif token == "link/ether" and name not in macs:
                macs[name] = parts[index + 1]
    return states, macs


def _clean_name(value: str) -> str:
    return value.rstrip(":").split("@")[0]
