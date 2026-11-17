"""Listening port exposure rules."""

from __future__ import annotations

from ...models import Finding, Severity, SystemSnapshot
from ..baseline.rules import Rule, finding

CIS_REF = "CIS Ubuntu 22.04/24.04 §2 Services"

# Legacy or unauthenticated-by-default services that must not listen publicly.
DANGEROUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    111: "rpcbind",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

WILDCARD_ADDRESSES = frozenset({"0.0.0.0", "::", "[::]", "*", ""})


def _ports_available(snapshot: SystemSnapshot) -> str | None:
    if any(error.startswith("ports:") for error in snapshot.errors):
        return "listening port data unavailable"
    return None


PORT_DANGEROUS = Rule(
    id="PORT-001",
    title="Dangerous services are exposed on all interfaces",
    severity=Severity.HIGH,
    category="ports",
    references=(CIS_REF,),
    prerequisite=_ports_available,
    evaluate=lambda snapshot, _config: _check_dangerous_ports(snapshot),
)

NETWORK_RULES = (PORT_DANGEROUS,)


def _check_dangerous_ports(snapshot: SystemSnapshot) -> Finding | None:
    exposed: list[dict[str, object]] = []
    for port in snapshot.ports:
        if port.local_address not in WILDCARD_ADDRESSES:
            continue
        service = DANGEROUS_PORTS.get(port.port)
        if service is None:
            continue
        exposed.append(
            {
                "port": port.port,
                "protocol": port.protocol,
                "service": service,
                "process": port.process,
            }
        )
    if not exposed:
        return None
    return finding(
        PORT_DANGEROUS,
        {"exposed": exposed},
        "Bind the service to loopback, restrict it with the firewall, "
        "or disable it if unused",
    )
