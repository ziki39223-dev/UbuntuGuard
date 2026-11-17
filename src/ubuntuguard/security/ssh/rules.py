"""SSH server baseline rules (CIS section 5.2)."""

from __future__ import annotations

from ...models import Finding, Severity, SystemSnapshot
from ..baseline.rules import Rule, finding

CIS_REF = "CIS Ubuntu 22.04/24.04 §5.2 SSH Server"

# OpenSSH / Ubuntu defaults, used only when the effective config lacks a key.
SSH_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "x11forwarding": "yes",
    "maxauthtries": "6",
    "ignorerhosts": "yes",
    "hostbasedauthentication": "no",
    "permituserenvironment": "no",
    "strictmodes": "yes",
    "logingracetime": "120",
    "clientaliveinterval": "0",
    "banner": "none",
    "allowusers": "",
    "allowgroups": "",
}

WEAK_CIPHERS = frozenset(
    {
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "rijndael-cbc@lysator.liu.se",
    }
)

WEAK_MACS = frozenset(
    {
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-ripemd160",
        "umac-64@openssh.com",
    }
)

WEAK_KEX = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    }
)


def _require_ssh(snapshot: SystemSnapshot) -> str | None:
    if snapshot.ssh.source == "unavailable" or not snapshot.ssh.effective:
        return "sshd configuration unavailable"
    return None


def _ssh_value(snapshot: SystemSnapshot, key: str) -> str | None:
    value = snapshot.ssh.get(key)
    if value is None:
        value = SSH_DEFAULTS.get(key)
    return value.strip().lower() if value is not None else None


def _ssh_int(snapshot: SystemSnapshot, key: str) -> int | None:
    value = _ssh_value(snapshot, key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


SSH_ROOT_LOGIN = Rule(
    id="SSH-001",
    title="SSH root login is not disabled",
    severity=Severity.HIGH,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_root_login(snapshot),
)

SSH_PASSWORD_AUTH = Rule(
    id="SSH-002",
    title="SSH password authentication is enabled",
    severity=Severity.HIGH,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_password_auth(snapshot),
)

SSH_EMPTY_PASSWORDS = Rule(
    id="SSH-003",
    title="SSH permits empty passwords",
    severity=Severity.CRITICAL,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_empty_passwords(snapshot),
)

SSH_X11_FORWARDING = Rule(
    id="SSH-004",
    title="SSH X11 forwarding is enabled",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_x11(snapshot),
)

SSH_MAX_AUTH_TRIES = Rule(
    id="SSH-005",
    title="SSH MaxAuthTries exceeds 4",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_max_auth_tries(snapshot),
)

SSH_IGNORE_RHOSTS = Rule(
    id="SSH-006",
    title="SSH IgnoreRhosts is disabled",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_ignore_rhosts(snapshot),
)

SSH_HOSTBASED_AUTH = Rule(
    id="SSH-007",
    title="SSH host-based authentication is enabled",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_hostbased(snapshot),
)

SSH_USER_ENVIRONMENT = Rule(
    id="SSH-008",
    title="SSH PermitUserEnvironment is enabled",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_user_environment(snapshot),
)

SSH_STRICT_MODES = Rule(
    id="SSH-009",
    title="SSH StrictModes is disabled",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_strict_modes(snapshot),
)

SSH_LOGIN_GRACE_TIME = Rule(
    id="SSH-010",
    title="SSH LoginGraceTime exceeds 60 seconds",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_login_grace_time(snapshot),
)

SSH_CLIENT_ALIVE = Rule(
    id="SSH-011",
    title="SSH idle timeout is not configured",
    severity=Severity.LOW,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_client_alive(snapshot),
)

SSH_ACCESS_LIMITED = Rule(
    id="SSH-012",
    title="SSH access is not limited to specific users or groups",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_access_limited(snapshot),
)

SSH_BANNER = Rule(
    id="SSH-013",
    title="SSH warning banner is not configured",
    severity=Severity.LOW,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_banner(snapshot),
)

SSH_WEAK_CIPHERS = Rule(
    id="SSH-014",
    title="SSH allows weak ciphers",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_weak_ciphers(snapshot),
)

SSH_WEAK_MACS = Rule(
    id="SSH-015",
    title="SSH allows weak MAC algorithms",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_weak_macs(snapshot),
)

SSH_WEAK_KEX = Rule(
    id="SSH-016",
    title="SSH allows weak key exchange algorithms",
    severity=Severity.MEDIUM,
    category="ssh",
    references=(CIS_REF,),
    prerequisite=_require_ssh,
    evaluate=lambda snapshot, _config: _check_weak_kex(snapshot),
)

SSH_RULES = (
    SSH_ROOT_LOGIN,
    SSH_PASSWORD_AUTH,
    SSH_EMPTY_PASSWORDS,
    SSH_X11_FORWARDING,
    SSH_MAX_AUTH_TRIES,
    SSH_IGNORE_RHOSTS,
    SSH_HOSTBASED_AUTH,
    SSH_USER_ENVIRONMENT,
    SSH_STRICT_MODES,
    SSH_LOGIN_GRACE_TIME,
    SSH_CLIENT_ALIVE,
    SSH_ACCESS_LIMITED,
    SSH_BANNER,
    SSH_WEAK_CIPHERS,
    SSH_WEAK_MACS,
    SSH_WEAK_KEX,
)


def _check_root_login(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "permitrootlogin")
    if value is None or value == "no":
        return None
    return finding(
        SSH_ROOT_LOGIN,
        _evidence(snapshot, "PermitRootLogin", value),
        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.d/00-ubuntuguard.conf",
    )


def _check_password_auth(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "passwordauthentication")
    if value != "yes":
        return None
    return finding(
        SSH_PASSWORD_AUTH,
        _evidence(snapshot, "PasswordAuthentication", value),
        "Set 'PasswordAuthentication no' and require SSH keys before applying",
    )


def _check_empty_passwords(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "permitemptypasswords")
    if value != "yes":
        return None
    return finding(
        SSH_EMPTY_PASSWORDS,
        _evidence(snapshot, "PermitEmptyPasswords", value),
        "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.d/00-ubuntuguard.conf",
    )


def _check_x11(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "x11forwarding")
    if value != "yes":
        return None
    return finding(
        SSH_X11_FORWARDING,
        _evidence(snapshot, "X11Forwarding", value),
        "Set 'X11Forwarding no' unless X11 tunneling is a documented requirement",
    )


def _check_max_auth_tries(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_int(snapshot, "maxauthtries")
    if value is None or value <= 4:
        return None
    return finding(
        SSH_MAX_AUTH_TRIES,
        _evidence(snapshot, "MaxAuthTries", str(value)),
        "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.d/00-ubuntuguard.conf",
    )


def _check_ignore_rhosts(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "ignorerhosts")
    if value != "no":
        return None
    return finding(
        SSH_IGNORE_RHOSTS,
        _evidence(snapshot, "IgnoreRhosts", value),
        "Set 'IgnoreRhosts yes'",
    )


def _check_hostbased(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "hostbasedauthentication")
    if value != "yes":
        return None
    return finding(
        SSH_HOSTBASED_AUTH,
        _evidence(snapshot, "HostbasedAuthentication", value),
        "Set 'HostbasedAuthentication no'",
    )


def _check_user_environment(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "permituserenvironment")
    if value != "yes":
        return None
    return finding(
        SSH_USER_ENVIRONMENT,
        _evidence(snapshot, "PermitUserEnvironment", value),
        "Set 'PermitUserEnvironment no'",
    )


def _check_strict_modes(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "strictmodes")
    if value != "no":
        return None
    return finding(
        SSH_STRICT_MODES,
        _evidence(snapshot, "StrictModes", value),
        "Set 'StrictModes yes'",
    )


def _check_login_grace_time(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_int(snapshot, "logingracetime")
    if value is None or 0 < value <= 60:
        return None
    return finding(
        SSH_LOGIN_GRACE_TIME,
        _evidence(snapshot, "LoginGraceTime", str(value)),
        "Set 'LoginGraceTime 60' or less",
    )


def _check_client_alive(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_int(snapshot, "clientaliveinterval")
    if value is not None and 0 < value <= 300:
        return None
    return finding(
        SSH_CLIENT_ALIVE,
        _evidence(snapshot, "ClientAliveInterval", str(value)),
        "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3'",
    )


def _check_access_limited(snapshot: SystemSnapshot) -> Finding | None:
    allow_users = _ssh_value(snapshot, "allowusers") or ""
    allow_groups = _ssh_value(snapshot, "allowgroups") or ""
    if allow_users.strip() or allow_groups.strip():
        return None
    return finding(
        SSH_ACCESS_LIMITED,
        {
            "key": "AllowUsers/AllowGroups",
            "value": f"AllowUsers='{allow_users}' AllowGroups='{allow_groups}'",
            "source": snapshot.ssh.source,
        },
        "Restrict SSH access with 'AllowUsers' or 'AllowGroups'",
    )


def _check_banner(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "banner")
    if value is not None and value.strip() not in {"", "none"}:
        return None
    return finding(
        SSH_BANNER,
        _evidence(snapshot, "Banner", value or "none"),
        "Set 'Banner /etc/issue.net' and maintain the banner text",
    )


def _check_weak_ciphers(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "ciphers") or ""
    weak = sorted(set(_split_list(value)) & WEAK_CIPHERS)
    if not weak:
        return None
    return finding(
        SSH_WEAK_CIPHERS,
        _evidence(snapshot, "Ciphers", ", ".join(weak)),
        "Remove CBC/RC4 ciphers and use AEAD ciphers such as chacha20-poly1305",
    )


def _check_weak_macs(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "macs") or ""
    weak = sorted(set(_split_list(value)) & WEAK_MACS)
    if not weak:
        return None
    return finding(
        SSH_WEAK_MACS,
        _evidence(snapshot, "MACs", ", ".join(weak)),
        "Use ETM HMAC-SHA2 MAC algorithms only",
    )


def _check_weak_kex(snapshot: SystemSnapshot) -> Finding | None:
    value = _ssh_value(snapshot, "kexalgorithms") or ""
    weak = sorted(set(_split_list(value)) & WEAK_KEX)
    if not weak:
        return None
    return finding(
        SSH_WEAK_KEX,
        _evidence(snapshot, "KexAlgorithms", ", ".join(weak)),
        "Use curve25519-sha256 or diffie-hellman-group16-sha512 and newer",
    )


def _evidence(
    snapshot: SystemSnapshot, key: str, value: str
) -> dict[str, object]:
    return {"key": key, "value": value, "source": snapshot.ssh.source}


def _split_list(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]
