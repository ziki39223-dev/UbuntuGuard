"""UFW firewall baseline rules."""

from __future__ import annotations

from ...models import Finding, Severity, SystemSnapshot
from ..baseline.rules import Rule, finding

CIS_REF = "CIS Ubuntu 22.04/24.04 §3.5 Firewall Configuration"

ACCEPTABLE_INCOMING = frozenset({"deny", "reject"})


def _firewall_available(snapshot: SystemSnapshot) -> str | None:
    if not snapshot.firewall.available:
        return "ufw is not installed"
    if not snapshot.firewall.readable:
        return "ufw status not readable (requires root)"
    return None


FW_ACTIVE = Rule(
    id="FW-001",
    title="Host firewall is not active",
    severity=Severity.HIGH,
    category="firewall",
    references=(CIS_REF,),
    prerequisite=_firewall_available,
    evaluate=lambda snapshot, _config: _check_active(snapshot),
)

FW_DEFAULT_INCOMING = Rule(
    id="FW-002",
    title="Firewall default incoming policy is not deny",
    severity=Severity.HIGH,
    category="firewall",
    references=(CIS_REF,),
    prerequisite=_firewall_available,
    evaluate=lambda snapshot, _config: _check_default_incoming(snapshot),
)

FIREWALL_RULES = (FW_ACTIVE, FW_DEFAULT_INCOMING)


def _check_active(snapshot: SystemSnapshot) -> Finding | None:
    firewall = snapshot.firewall
    if firewall.active:
        return None
    return finding(
        FW_ACTIVE,
        {
            "active": firewall.active,
            "default_incoming": firewall.default_incoming or "unknown",
            "rules": len(firewall.rules),
        },
        "Enable the firewall: 'ufw default deny incoming' then 'ufw enable'",
    )


def _check_default_incoming(snapshot: SystemSnapshot) -> Finding | None:
    firewall = snapshot.firewall
    if not firewall.active:
        return None
    if firewall.default_incoming in ACCEPTABLE_INCOMING:
        return None
    return finding(
        FW_DEFAULT_INCOMING,
        {"default_incoming": firewall.default_incoming or "unknown"},
        "Set the default incoming policy: 'ufw default deny incoming'",
    )
