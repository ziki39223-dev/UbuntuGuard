"""Account, sudo, permission and password policy rule tests."""

from __future__ import annotations

from collections.abc import Callable

from ubuntuguard.core.config import Config
from ubuntuguard.models import (
    FilePermission,
    LoginDefsInfo,
    Severity,
    ShadowEntry,
    ShadowInfo,
    SudoEntry,
    SudoersInfo,
    SystemSnapshot,
    UserInfo,
)
from ubuntuguard.security.users.rules import (
    ACC_DUPLICATE_UID,
    ACC_EMPTY_PASSWORD,
    ACC_ROOT_GROUP,
    ACC_SYSTEM_SHELL,
    ACC_UID_ZERO,
    LOGIN_MAX_DAYS,
    LOGIN_UMASK,
    PERM_PASSWD,
    PERM_SHADOW,
    SUDO_NOPASSWD,
    SUDO_PERMISSIONS,
)

CLEAN_USERS = (
    UserInfo(
        name="root", uid=0, gid=0, group="root", home="/root", shell="/bin/bash"
    ),
    UserInfo(
        name="ubuntu",
        uid=1000,
        gid=1000,
        group="ubuntu",
        home="/home/ubuntu",
        shell="/bin/bash",
        supplemental_groups=("sudo",),
    ),
    UserInfo(
        name="daemon", uid=1, gid=1, group="daemon", home="/usr/sbin", shell="/usr/sbin/nologin"
    ),
)


def test_clean_accounts_have_no_findings(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        users=CLEAN_USERS,
        shadow=ShadowInfo(
            readable=True,
            entries=(ShadowEntry(name="root", password="!"),),
        ),
        sudoers=SudoersInfo(
            readable=True,
            entries=(
                SudoEntry(
                    file="/etc/sudoers",
                    line=1,
                    text="root ALL=(ALL:ALL) ALL",
                    nopasswd=False,
                ),
            ),
        ),
        login_defs=LoginDefsInfo(
            readable=True,
            values={
                "PASS_MAX_DAYS": "365",
                "PASS_MIN_DAYS": "1",
                "PASS_WARN_AGE": "7",
                "UMASK": "027",
            },
        ),
        file_permissions=(
            FilePermission(path="/etc/passwd", mode=0o644, uid=0, gid=0),
            FilePermission(path="/etc/group", mode=0o644, uid=0, gid=0),
            FilePermission(path="/etc/shadow", mode=0o640, uid=0, gid=42),
            FilePermission(path="/etc/sudoers", mode=0o440, uid=0, gid=0),
        ),
    )
    for rule in (
        ACC_UID_ZERO,
        ACC_DUPLICATE_UID,
        ACC_SYSTEM_SHELL,
        ACC_ROOT_GROUP,
        ACC_EMPTY_PASSWORD,
        PERM_PASSWD,
        PERM_SHADOW,
        SUDO_NOPASSWD,
        SUDO_PERMISSIONS,
        LOGIN_MAX_DAYS,
        LOGIN_UMASK,
    ):
        assert rule.evaluate(snapshot, config) is None, rule.id


def test_extra_uid_zero(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    users = CLEAN_USERS + (
        UserInfo(
            name="toor", uid=0, gid=0, group="root", home="/root", shell="/bin/bash"
        ),
    )
    result = ACC_UID_ZERO.evaluate(make_snapshot(users=users), config)
    assert result is not None
    assert result.severity is Severity.CRITICAL
    assert result.evidence["accounts"] == ["toor"]


def test_duplicate_uid(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    users = CLEAN_USERS + (
        UserInfo(
            name="clone",
            uid=1000,
            gid=1000,
            group="ubuntu",
            home="/home/clone",
            shell="/bin/bash",
        ),
    )
    result = ACC_DUPLICATE_UID.evaluate(make_snapshot(users=users), config)
    assert result is not None
    assert result.evidence["duplicate_uids"] == {"1000": ["clone", "ubuntu"]}


def test_system_account_with_login_shell(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    users = (
        UserInfo(name="root", uid=0, gid=0, group="root", home="/root", shell="/bin/bash"),
        UserInfo(name="sync2", uid=2, gid=2, group="bin", home="/bin", shell="/bin/bash"),
    )
    result = ACC_SYSTEM_SHELL.evaluate(make_snapshot(users=users), config)
    assert result is not None
    assert result.evidence["accounts"] == ["sync2"]


def test_root_group_membership(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    users = (
        UserInfo(name="root", uid=0, gid=0, group="root", home="/root", shell="/bin/bash"),
        UserInfo(
            name="alice",
            uid=1001,
            gid=1001,
            group="alice",
            home="/home/alice",
            shell="/bin/bash",
            supplemental_groups=("root",),
        ),
    )
    result = ACC_ROOT_GROUP.evaluate(make_snapshot(users=users), config)
    assert result is not None
    assert result.evidence["accounts"] == ["alice"]


def test_empty_shadow_password(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        users=CLEAN_USERS,
        shadow=ShadowInfo(
            readable=True,
            entries=(
                ShadowEntry(name="alice", password=""),
                ShadowEntry(name="root", password="!"),
            ),
        ),
    )
    result = ACC_EMPTY_PASSWORD.evaluate(snapshot, config)
    assert result is not None
    assert result.severity is Severity.CRITICAL
    assert result.evidence["accounts"] == ["alice"]


def test_shadow_permissions(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    permissive = make_snapshot(
        file_permissions=(
            FilePermission(path="/etc/shadow", mode=0o644, uid=0, gid=0),
        )
    )
    result = PERM_SHADOW.evaluate(permissive, config)
    assert result is not None
    assert result.severity is Severity.CRITICAL

    strict = make_snapshot(
        file_permissions=(
            FilePermission(path="/etc/shadow", mode=0o640, uid=0, gid=42),
        )
    )
    assert PERM_SHADOW.evaluate(strict, config) is None


def test_passwd_writable_by_group(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        file_permissions=(
            FilePermission(path="/etc/passwd", mode=0o664, uid=0, gid=0),
        )
    )
    result = PERM_PASSWD.evaluate(snapshot, config)
    assert result is not None
    assert result.evidence["mode"] == "0o664"


def test_sudoers_nopasswd_and_permissions(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    snapshot = make_snapshot(
        sudoers=SudoersInfo(
            readable=True,
            entries=(
                SudoEntry(
                    file="/etc/sudoers.d/deploy",
                    line=2,
                    text="deploy ALL=(ALL) NOPASSWD: ALL",
                    nopasswd=True,
                ),
            ),
        ),
        file_permissions=(
            FilePermission(path="/etc/sudoers", mode=0o444, uid=0, gid=0),
        ),
    )
    nopasswd = SUDO_NOPASSWD.evaluate(snapshot, config)
    assert nopasswd is not None
    assert nopasswd.severity is Severity.HIGH
    assert nopasswd.evidence["entries"][0]["line"] == 2

    permissions = SUDO_PERMISSIONS.evaluate(snapshot, config)
    assert permissions is not None
    assert permissions.evidence["mode"] == "0o444"


def test_password_policy_rules(
    make_snapshot: Callable[..., SystemSnapshot], config: Config
) -> None:
    loose = make_snapshot(
        login_defs=LoginDefsInfo(
            readable=True,
            values={"PASS_MAX_DAYS": "9999", "PASS_MIN_DAYS": "0", "UMASK": "022"},
        )
    )
    assert LOGIN_MAX_DAYS.evaluate(loose, config) is not None
    assert LOGIN_UMASK.evaluate(loose, config) is not None

    unset = make_snapshot(login_defs=LoginDefsInfo(readable=True, values={}))
    assert LOGIN_MAX_DAYS.evaluate(unset, config) is not None
    assert LOGIN_UMASK.evaluate(unset, config) is not None
