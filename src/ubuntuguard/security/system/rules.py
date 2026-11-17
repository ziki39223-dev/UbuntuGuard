"""Kernel parameter (sysctl) baseline rules."""

from __future__ import annotations

from ...models import Finding, Severity, SystemSnapshot
from ..baseline.rules import Rule, finding

CIS_REF = "CIS Ubuntu 22.04/24.04 §1.5 Kernel Parameters"


def _sysctl_available(snapshot: SystemSnapshot) -> str | None:
    if not snapshot.sysctl.values:
        return "sysctl data unavailable (/proc/sys not readable)"
    return None


SYS_ASLR: Rule = Rule(
    id="SYS-001",
    title="ASLR is not fully enabled",
    severity=Severity.MEDIUM,
    category="sysctl",
    references=(CIS_REF,),
    prerequisite=_sysctl_available,
    evaluate=lambda snapshot, _config: _check(
        snapshot,
        SYS_ASLR,
        {"kernel.randomize_va_space": {2}},
        "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d/99-ubuntuguard.conf",
    ),
)

SYS_SYNCOOKIES: Rule = Rule(
    id="SYS-002",
    title="TCP SYN cookies are disabled",
    severity=Severity.MEDIUM,
    category="sysctl",
    references=(CIS_REF,),
    prerequisite=_sysctl_available,
    evaluate=lambda snapshot, _config: _check(
        snapshot,
        SYS_SYNCOOKIES,
        {"net.ipv4.tcp_syncookies": {1}},
        "Set 'net.ipv4.tcp_syncookies = 1'",
    ),
)

SYS_RP_FILTER: Rule = Rule(
    id="SYS-003",
    title="IPv4 reverse path filtering is not enabled",
    severity=Severity.LOW,
    category="sysctl",
    references=(CIS_REF,),
    prerequisite=_sysctl_available,
    evaluate=lambda snapshot, _config: _check(
        snapshot,
        SYS_RP_FILTER,
        {
            "net.ipv4.conf.all.rp_filter": {1},
            "net.ipv4.conf.default.rp_filter": {1},
        },
        "Set rp_filter = 1 for all and default interfaces",
    ),
)

SYS_REDIRECTS: Rule = Rule(
    id="SYS-004",
    title="ICMP redirects are accepted or sent",
    severity=Severity.MEDIUM,
    category="sysctl",
    references=(CIS_REF,),
    prerequisite=_sysctl_available,
    evaluate=lambda snapshot, _config: _check(
        snapshot,
        SYS_REDIRECTS,
        {
            "net.ipv4.conf.all.accept_redirects": {0},
            "net.ipv4.conf.all.send_redirects": {0},
        },
        "Set accept_redirects = 0 and send_redirects = 0",
    ),
)

SYS_SOURCE_ROUTE: Rule = Rule(
    id="SYS-005",
    title="IPv4 source routing, martian logging or broadcast ICMP is not hardened",
    severity=Severity.MEDIUM,
    category="sysctl",
    references=(CIS_REF,),
    prerequisite=_sysctl_available,
    evaluate=lambda snapshot, _config: _check(
        snapshot,
        SYS_SOURCE_ROUTE,
        {
            "net.ipv4.conf.all.accept_source_route": {0},
            "net.ipv4.conf.all.log_martians": {1},
            "net.ipv4.icmp_echo_ignore_broadcasts": {1},
        },
        "Set accept_source_route = 0, log_martians = 1 "
        "and icmp_echo_ignore_broadcasts = 1",
    ),
)

SYS_INFO_LEAK: Rule = Rule(
    id="SYS-006",
    title="Kernel information leak protections are disabled",
    severity=Severity.LOW,
    category="sysctl",
    references=(CIS_REF,),
    prerequisite=_sysctl_available,
    evaluate=lambda snapshot, _config: _check(
        snapshot,
        SYS_INFO_LEAK,
        {"kernel.dmesg_restrict": {1}, "kernel.kptr_restrict": {1, 2}},
        "Set dmesg_restrict = 1 and kptr_restrict = 1",
    ),
)

SYS_LINK_PROTECTION: Rule = Rule(
    id="SYS-007",
    title="Kernel link protection is disabled",
    severity=Severity.MEDIUM,
    category="sysctl",
    references=(CIS_REF,),
    prerequisite=_sysctl_available,
    evaluate=lambda snapshot, _config: _check(
        snapshot,
        SYS_LINK_PROTECTION,
        {"fs.protected_hardlinks": {1}, "fs.protected_symlinks": {1}},
        "Set protected_hardlinks = 1 and protected_symlinks = 1",
    ),
)

SYSCTL_RULES = (
    SYS_ASLR,
    SYS_SYNCOOKIES,
    SYS_RP_FILTER,
    SYS_REDIRECTS,
    SYS_SOURCE_ROUTE,
    SYS_INFO_LEAK,
    SYS_LINK_PROTECTION,
)


def _check(
    snapshot: SystemSnapshot,
    rule: Rule,
    expected: dict[str, set[int]],
    remediation: str,
) -> Finding | None:
    mismatched: dict[str, str] = {}
    for key, acceptable in expected.items():
        raw = snapshot.sysctl.values.get(key)
        if raw is None:
            mismatched[key] = "unset"
            continue
        try:
            value = int(raw)
        except ValueError:
            mismatched[key] = raw
            continue
        if value not in acceptable:
            mismatched[key] = raw
    if not mismatched:
        return None
    return finding(rule, {"mismatched": mismatched}, remediation)
