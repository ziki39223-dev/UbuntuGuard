"""Account, sudo, file-permission and password-policy baseline rules."""

from __future__ import annotations

from collections.abc import Callable

from ...models import FilePermission, Finding, Severity, SystemSnapshot
from ..baseline.rules import Rule, finding

CIS_ACCOUNT_REF = "CIS Ubuntu 22.04/24.04 §5.4 User Accounts"
CIS_SUDO_REF = "CIS Ubuntu 22.04/24.04 §5.3 Sudo"
CIS_PERM_REF = "CIS Ubuntu 22.04/24.04 §6.1 File Permissions"
CIS_PASSWORD_REF = "CIS Ubuntu 22.04/24.04 §5.4.1 Password Policy"

NON_LOGIN_SHELLS = frozenset(
    {
        "",
        "/bin/false",
        "/usr/bin/false",
        "/bin/sync",
        "/usr/bin/sync",
        "/sbin/nologin",
        "/usr/sbin/nologin",
    }
)


def _users_available(snapshot: SystemSnapshot) -> str | None:
    if not snapshot.users:
        return "account database unavailable (/etc/passwd not readable)"
    return None


def _shadow_available(snapshot: SystemSnapshot) -> str | None:
    if not snapshot.shadow.readable:
        return "shadow not readable (requires root)"
    return None


def _sudoers_available(snapshot: SystemSnapshot) -> str | None:
    if not snapshot.sudoers.readable:
        return "sudoers not readable (requires root)"
    return None


def _login_defs_available(snapshot: SystemSnapshot) -> str | None:
    if not snapshot.login_defs.readable:
        return "/etc/login.defs not readable"
    return None


def _mode_prereq(path: str) -> Callable[[SystemSnapshot], str | None]:
    def check(snapshot: SystemSnapshot) -> str | None:
        entry = _permission(snapshot, path)
        if entry is None or entry.mode is None:
            return f"{path} metadata unavailable"
        return None

    return check


def _permission(snapshot: SystemSnapshot, path: str) -> FilePermission | None:
    for entry in snapshot.file_permissions:
        if entry.path == path:
            return entry
    return None


ACC_UID_ZERO = Rule(
    id="ACC-001",
    title="Additional UID 0 account exists",
    severity=Severity.CRITICAL,
    category="accounts",
    references=(CIS_ACCOUNT_REF,),
    prerequisite=_users_available,
    evaluate=lambda snapshot, _config: _check_uid_zero(snapshot),
)

ACC_DUPLICATE_UID = Rule(
    id="ACC-002",
    title="Duplicate user IDs exist",
    severity=Severity.MEDIUM,
    category="accounts",
    references=(CIS_ACCOUNT_REF,),
    prerequisite=_users_available,
    evaluate=lambda snapshot, _config: _check_duplicate_uids(snapshot),
)

ACC_SYSTEM_SHELL = Rule(
    id="ACC-003",
    title="System accounts have interactive login shells",
    severity=Severity.MEDIUM,
    category="accounts",
    references=(CIS_ACCOUNT_REF,),
    prerequisite=_users_available,
    evaluate=lambda snapshot, _config: _check_system_shells(snapshot),
)

ACC_ROOT_GROUP = Rule(
    id="ACC-004",
    title="Non-root users are members of the root group",
    severity=Severity.MEDIUM,
    category="accounts",
    references=(CIS_ACCOUNT_REF,),
    prerequisite=_users_available,
    evaluate=lambda snapshot, _config: _check_root_group(snapshot),
)

ACC_EMPTY_PASSWORD = Rule(
    id="ACC-005",
    title="Accounts with empty passwords exist",
    severity=Severity.CRITICAL,
    category="accounts",
    references=(CIS_ACCOUNT_REF,),
    prerequisite=_shadow_available,
    evaluate=lambda snapshot, _config: _check_empty_passwords(snapshot),
)

PERM_PASSWD = Rule(
    id="PERM-001",
    title="/etc/passwd is writable by group or others",
    severity=Severity.MEDIUM,
    category="permissions",
    references=(CIS_PERM_REF,),
    prerequisite=_mode_prereq("/etc/passwd"),
    evaluate=lambda snapshot, _config: _check_passwd_mode(snapshot),
)

PERM_GROUP = Rule(
    id="PERM-002",
    title="/etc/group is writable by group or others",
    severity=Severity.MEDIUM,
    category="permissions",
    references=(CIS_PERM_REF,),
    prerequisite=_mode_prereq("/etc/group"),
    evaluate=lambda snapshot, _config: _check_group_mode(snapshot),
)

PERM_SHADOW = Rule(
    id="PERM-003",
    title="/etc/shadow is accessible by non-root users",
    severity=Severity.CRITICAL,
    category="permissions",
    references=(CIS_PERM_REF,),
    prerequisite=_mode_prereq("/etc/shadow"),
    evaluate=lambda snapshot, _config: _check_shadow_mode(snapshot),
)

SUDO_NOPASSWD = Rule(
    id="SUDO-001",
    title="sudo grants passwordless command execution",
    severity=Severity.HIGH,
    category="sudo",
    references=(CIS_SUDO_REF,),
    prerequisite=_sudoers_available,
    evaluate=lambda snapshot, _config: _check_nopasswd(snapshot),
)

SUDO_PERMISSIONS = Rule(
    id="SUDO-002",
    title="/etc/sudoers permissions are too permissive",
    severity=Severity.MEDIUM,
    category="sudo",
    references=(CIS_SUDO_REF,),
    prerequisite=_mode_prereq("/etc/sudoers"),
    evaluate=lambda snapshot, _config: _check_sudoers_mode(snapshot),
)

LOGIN_MAX_DAYS = Rule(
    id="LOGIN-001",
    title="Password maximum age exceeds 365 days or is unset",
    severity=Severity.MEDIUM,
    category="password_policy",
    references=(CIS_PASSWORD_REF,),
    prerequisite=_login_defs_available,
    evaluate=lambda snapshot, _config: _check_pass_max_days(snapshot),
)

LOGIN_MIN_DAYS = Rule(
    id="LOGIN-002",
    title="Password minimum age is less than 1 day",
    severity=Severity.LOW,
    category="password_policy",
    references=(CIS_PASSWORD_REF,),
    prerequisite=_login_defs_available,
    evaluate=lambda snapshot, _config: _check_pass_min_days(snapshot),
)

LOGIN_WARN_AGE = Rule(
    id="LOGIN-003",
    title="Password expiry warning is less than 7 days",
    severity=Severity.LOW,
    category="password_policy",
    references=(CIS_PASSWORD_REF,),
    prerequisite=_login_defs_available,
    evaluate=lambda snapshot, _config: _check_pass_warn_age(snapshot),
)

LOGIN_UMASK = Rule(
    id="LOGIN-004",
    title="Default UMASK is weaker than 027",
    severity=Severity.MEDIUM,
    category="password_policy",
    references=(CIS_PASSWORD_REF,),
    prerequisite=_login_defs_available,
    evaluate=lambda snapshot, _config: _check_umask(snapshot),
)

ACCOUNT_RULES = (
    ACC_UID_ZERO,
    ACC_DUPLICATE_UID,
    ACC_SYSTEM_SHELL,
    ACC_ROOT_GROUP,
    ACC_EMPTY_PASSWORD,
    PERM_PASSWD,
    PERM_GROUP,
    PERM_SHADOW,
    SUDO_NOPASSWD,
    SUDO_PERMISSIONS,
    LOGIN_MAX_DAYS,
    LOGIN_MIN_DAYS,
    LOGIN_WARN_AGE,
    LOGIN_UMASK,
)


def _check_uid_zero(snapshot: SystemSnapshot) -> Finding | None:
    accounts = sorted(
        user.name for user in snapshot.users if user.uid == 0 and user.name != "root"
    )
    if not accounts:
        return None
    return finding(
        ACC_UID_ZERO,
        {"uid": 0, "accounts": accounts},
        "Assign a non-zero UID to these accounts or remove them",
    )


def _check_duplicate_uids(snapshot: SystemSnapshot) -> Finding | None:
    by_uid: dict[int, list[str]] = {}
    for user in snapshot.users:
        by_uid.setdefault(user.uid, []).append(user.name)
    duplicates = {
        str(uid): sorted(names) for uid, names in by_uid.items() if len(names) > 1
    }
    if not duplicates:
        return None
    return finding(
        ACC_DUPLICATE_UID,
        {"duplicate_uids": duplicates},
        "Ensure every account has a unique UID",
    )


def _check_system_shells(snapshot: SystemSnapshot) -> Finding | None:
    accounts = sorted(
        user.name
        for user in snapshot.users
        if user.uid < 1000
        and user.name != "root"
        and user.shell not in NON_LOGIN_SHELLS
    )
    if not accounts:
        return None
    return finding(
        ACC_SYSTEM_SHELL,
        {"accounts": accounts},
        "Set the shell to /usr/sbin/nologin for system accounts",
    )


def _check_root_group(snapshot: SystemSnapshot) -> Finding | None:
    members = sorted(
        user.name
        for user in snapshot.users
        if user.name != "root"
        and (user.gid == 0 or "root" in user.supplemental_groups)
    )
    if not members:
        return None
    return finding(
        ACC_ROOT_GROUP,
        {"accounts": members},
        "Remove non-root accounts from the root group (gid 0)",
    )


def _check_empty_passwords(snapshot: SystemSnapshot) -> Finding | None:
    accounts = sorted(
        entry.name for entry in snapshot.shadow.entries if entry.password == ""
    )
    if not accounts:
        return None
    return finding(
        ACC_EMPTY_PASSWORD,
        {"accounts": accounts},
        "Set a password or lock the account with 'usermod -L'",
    )


def _check_passwd_mode(snapshot: SystemSnapshot) -> Finding | None:
    return _check_writable(snapshot, "/etc/passwd", PERM_PASSWD)


def _check_group_mode(snapshot: SystemSnapshot) -> Finding | None:
    return _check_writable(snapshot, "/etc/group", PERM_GROUP)


def _check_writable(
    snapshot: SystemSnapshot, path: str, rule: Rule
) -> Finding | None:
    entry = _permission(snapshot, path)
    if entry is None or entry.mode is None:
        return None
    if not entry.mode & 0o022:
        return None
    return finding(
        rule,
        {"path": path, "mode": oct(entry.mode)},
        f"Restrict {path} to mode 0644 (chmod 644 {path})",
    )


def _check_shadow_mode(snapshot: SystemSnapshot) -> Finding | None:
    entry = _permission(snapshot, "/etc/shadow")
    if entry is None or entry.mode is None:
        return None
    mode_issue = bool(entry.mode & 0o027)
    owner_issue = entry.uid not in (0, None)
    if not mode_issue and not owner_issue:
        return None
    return finding(
        PERM_SHADOW,
        {"path": "/etc/shadow", "mode": oct(entry.mode), "uid": entry.uid},
        "Set /etc/shadow to root:shadow 0640 (chown root:shadow, chmod 640)",
    )


def _check_nopasswd(snapshot: SystemSnapshot) -> Finding | None:
    entries = [
        {"file": entry.file, "line": entry.line, "text": entry.text}
        for entry in snapshot.sudoers.entries
        if entry.nopasswd
    ]
    if not entries:
        return None
    return finding(
        SUDO_NOPASSWD,
        {"entries": entries},
        "Require re-authentication for sudo; remove NOPASSWD unless documented",
    )


def _check_sudoers_mode(snapshot: SystemSnapshot) -> Finding | None:
    entry = _permission(snapshot, "/etc/sudoers")
    if entry is None or entry.mode is None:
        return None
    if not entry.mode & 0o027:
        return None
    return finding(
        SUDO_PERMISSIONS,
        {"path": "/etc/sudoers", "mode": oct(entry.mode)},
        "Set /etc/sudoers to mode 0440 (chmod 440 /etc/sudoers)",
    )


def _login_value(snapshot: SystemSnapshot, key: str) -> str | None:
    return snapshot.login_defs.values.get(key)


def _check_pass_max_days(snapshot: SystemSnapshot) -> Finding | None:
    return _check_int_policy(
        snapshot,
        LOGIN_MAX_DAYS,
        "PASS_MAX_DAYS",
        lambda value: value <= 365,
        "Set 'PASS_MAX_DAYS 365' in /etc/login.defs",
    )


def _check_pass_min_days(snapshot: SystemSnapshot) -> Finding | None:
    return _check_int_policy(
        snapshot,
        LOGIN_MIN_DAYS,
        "PASS_MIN_DAYS",
        lambda value: value >= 1,
        "Set 'PASS_MIN_DAYS 1' in /etc/login.defs",
    )


def _check_pass_warn_age(snapshot: SystemSnapshot) -> Finding | None:
    return _check_int_policy(
        snapshot,
        LOGIN_WARN_AGE,
        "PASS_WARN_AGE",
        lambda value: value >= 7,
        "Set 'PASS_WARN_AGE 7' in /etc/login.defs",
    )


def _check_int_policy(
    snapshot: SystemSnapshot,
    rule: Rule,
    key: str,
    is_acceptable: Callable[[int], bool],
    remediation: str,
) -> Finding | None:
    raw = _login_value(snapshot, key)
    if raw is None:
        return finding(rule, {"key": key, "value": "unset"}, remediation)
    try:
        value = int(raw)
    except ValueError:
        return finding(rule, {"key": key, "value": raw}, remediation)
    if is_acceptable(value):
        return None
    return finding(rule, {"key": key, "value": raw}, remediation)


def _check_umask(snapshot: SystemSnapshot) -> Finding | None:
    raw = _login_value(snapshot, "UMASK")
    if raw is None:
        return finding(LOGIN_UMASK, {"key": "UMASK", "value": "unset"}, "Set 'UMASK 027'")
    try:
        mask = int(raw, 8)
    except ValueError:
        return finding(LOGIN_UMASK, {"key": "UMASK", "value": raw}, "Set 'UMASK 027'")
    if (mask & 0o027) == 0o027:
        return None
    return finding(
        LOGIN_UMASK,
        {"key": "UMASK", "value": raw},
        "Set 'UMASK 027' in /etc/login.defs",
    )
