"""Batch 2 rule tests: firewall, ports and sysctl."""

from __future__ import annotations

from collections.abc import Callable

from ubuntuguard.core.config import Config
from ubuntuguard.models import (
    Finding,
    FirewallInfo,
    PortInfo,
    Severity,
    SysctlInfo,
    SystemSnapshot,
)
from ubuntuguard.security.baseline import run_audit
from ubuntuguard.security.firewall.rules import FW_ACTIVE, FW_DEFAULT_INCOMING
from ubuntuguard.security.network.rules import PORT_DANGEROUS
from ubuntuguard.security.system.rules import SYS_ASLR, SYS_RP_FILTER, SYSCTL_RULES

CLEAN_SYSCTL = {
    "kernel.randomize_va_space": "2",
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "1",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
}


def test_firewall_inactive_is_reported(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        firewall=FirewallInfo(available=True, readable=True, active=False)
    )
    result = FW_ACTIVE.evaluate(snapshot, config)
    assert result is not None
    assert result.severity is Severity.HIGH


def test_firewall_clean_config_passes(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        firewall=FirewallInfo(
            available=True,
            readable=True,
            active=True,
            default_incoming="deny",
            default_outgoing="allow",
        )
    )
    assert FW_ACTIVE.evaluate(snapshot, config) is None
    assert FW_DEFAULT_INCOMING.evaluate(snapshot, config) is None


def test_firewall_default_allow_is_reported(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        firewall=FirewallInfo(
            available=True,
            readable=True,
            active=True,
            default_incoming="allow",
        )
    )
    result = FW_DEFAULT_INCOMING.evaluate(snapshot, config)
    assert result is not None
    assert result.evidence["default_incoming"] == "allow"


def test_firewall_unavailable_has_prerequisite(
    make_snapshot: Callable[..., SystemSnapshot],
) -> None:
    snapshot = make_snapshot()
    assert FW_ACTIVE.prerequisite is not None
    assert FW_ACTIVE.prerequisite(snapshot)


def test_dangerous_port_exposed(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        ports=(
            PortInfo(
                protocol="tcp", local_address="0.0.0.0", port=23, state="LISTEN"
            ),
        )
    )
    result = PORT_DANGEROUS.evaluate(snapshot, config)
    assert result is not None
    assert result.severity is Severity.HIGH
    assert result.evidence["exposed"][0]["service"] == "Telnet"


def test_loopback_database_port_passes(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        ports=(
            PortInfo(
                protocol="tcp", local_address="127.0.0.1", port=6379, state="LISTEN"
            ),
        )
    )
    assert PORT_DANGEROUS.evaluate(snapshot, config) is None


def test_ports_unavailable_has_prerequisite(
    make_snapshot: Callable[..., SystemSnapshot],
) -> None:
    snapshot = make_snapshot(errors=("ports: command not found: ss",))
    assert PORT_DANGEROUS.prerequisite is not None
    assert PORT_DANGEROUS.prerequisite(snapshot)


def test_sysctl_clean_config_passes(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(sysctl=SysctlInfo(values=dict(CLEAN_SYSCTL)))
    for rule in SYSCTL_RULES:
        assert rule.evaluate(snapshot, config) is None, rule.id


def test_sysctl_aslr_and_rp_filter(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    values = dict(CLEAN_SYSCTL)
    values["kernel.randomize_va_space"] = "1"
    values["net.ipv4.conf.default.rp_filter"] = "2"
    snapshot = make_snapshot(sysctl=SysctlInfo(values=values))

    aslr = SYS_ASLR.evaluate(snapshot, config)
    assert aslr is not None
    assert aslr.evidence["mismatched"]["kernel.randomize_va_space"] == "1"

    rp_filter = SYS_RP_FILTER.evaluate(snapshot, config)
    assert rp_filter is not None
    assert "net.ipv4.conf.default.rp_filter" in rp_filter.evidence["mismatched"]


def test_sysctl_unavailable_has_prerequisite(
    make_snapshot: Callable[..., SystemSnapshot],
) -> None:
    snapshot = make_snapshot()
    assert SYS_ASLR.prerequisite is not None
    assert SYS_ASLR.prerequisite(snapshot)


def test_engine_merges_external_findings(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    extra = Finding(
        id="LYNIS-test",
        title="external finding",
        severity=Severity.HIGH,
        category="lynis",
    )
    result = run_audit(
        make_snapshot(),
        config,
        rules=(),
        extra_findings=(extra,),
        extra_skipped=("LYNIS: example skip",),
        extra_evaluated=1,
    )
    assert result.findings == (extra,)
    assert result.score == 85
    assert "LYNIS: example skip" in result.skipped


def test_extra_evaluated_avoids_na_score(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    result = run_audit(
        make_snapshot(), config, rules=(), extra_evaluated=1
    )
    assert result.score == 100
    assert result.grade == "A"
