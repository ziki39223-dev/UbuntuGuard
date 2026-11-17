"""SSH baseline rule tests."""

from __future__ import annotations

from collections.abc import Callable

from ubuntuguard.core.config import Config
from ubuntuguard.models import Severity, SshInfo, SystemSnapshot
from ubuntuguard.security.ssh.rules import (
    SSH_ACCESS_LIMITED,
    SSH_BANNER,
    SSH_EMPTY_PASSWORDS,
    SSH_MAX_AUTH_TRIES,
    SSH_PASSWORD_AUTH,
    SSH_ROOT_LOGIN,
    SSH_RULES,
    SSH_WEAK_CIPHERS,
)

CLEAN_SSH = {
    "permitrootlogin": "no",
    "passwordauthentication": "no",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "maxauthtries": "4",
    "ignorerhosts": "yes",
    "hostbasedauthentication": "no",
    "permituserenvironment": "no",
    "strictmodes": "yes",
    "logingracetime": "60",
    "clientaliveinterval": "300",
    "allowusers": "deploy",
    "banner": "/etc/issue.net",
    "ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    "macs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
    "kexalgorithms": "curve25519-sha256,diffie-hellman-group16-sha512",
}


def _ssh(**overrides: str) -> SshInfo:
    effective = dict(CLEAN_SSH)
    effective.update({key.lower(): value for key, value in overrides.items()})
    return SshInfo(effective=effective, source="sshd -T")


def test_clean_config_passes_all_rules(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh())
    for rule in SSH_RULES:
        assert rule.evaluate(snapshot, config) is None, rule.id


def test_root_login_is_reported(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh(PermitRootLogin="yes"))
    result = SSH_ROOT_LOGIN.evaluate(snapshot, config)
    assert result is not None
    assert result.severity is Severity.HIGH
    assert result.evidence["value"] == "yes"


def test_password_authentication_is_reported(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh(PasswordAuthentication="yes"))
    result = SSH_PASSWORD_AUTH.evaluate(snapshot, config)
    assert result is not None
    assert result.id == "SSH-002"


def test_empty_passwords_are_critical(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh(PermitEmptyPasswords="yes"))
    result = SSH_EMPTY_PASSWORDS.evaluate(snapshot, config)
    assert result is not None
    assert result.severity is Severity.CRITICAL


def test_max_auth_tries_above_four(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh(MaxAuthTries="10"))
    result = SSH_MAX_AUTH_TRIES.evaluate(snapshot, config)
    assert result is not None
    assert result.evidence["value"] == "10"


def test_missing_banner_is_reported(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh(Banner="none"))
    result = SSH_BANNER.evaluate(snapshot, config)
    assert result is not None
    assert result.id == "SSH-013"


def test_weak_cipher_is_reported(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh(Ciphers="aes128-cbc,aes256-gcm@openssh.com"))
    result = SSH_WEAK_CIPHERS.evaluate(snapshot, config)
    assert result is not None
    assert "aes128-cbc" in result.evidence["value"]

    clean = make_snapshot(ssh=_ssh())
    assert SSH_WEAK_CIPHERS.evaluate(clean, config) is None


def test_unlimited_ssh_access_is_reported(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(ssh=_ssh(AllowUsers="", AllowGroups=""))
    result = SSH_ACCESS_LIMITED.evaluate(snapshot, config)
    assert result is not None
    assert result.id == "SSH-012"


def test_unavailable_ssh_has_prerequisite_reason(
    make_snapshot: Callable[..., SystemSnapshot],
) -> None:
    snapshot = make_snapshot()
    assert SSH_ROOT_LOGIN.prerequisite is not None
    assert SSH_ROOT_LOGIN.prerequisite(snapshot)
