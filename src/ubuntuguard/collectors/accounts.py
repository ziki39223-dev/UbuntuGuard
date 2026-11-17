"""Local account, password policy and sudoers collector."""

from __future__ import annotations

from pathlib import Path

from ..models import (
    LoginDefsInfo,
    ShadowEntry,
    ShadowInfo,
    SudoEntry,
    SudoersInfo,
    UserInfo,
)

DEFAULT_SHADOW_PATH = Path("/etc/shadow")
DEFAULT_LOGIN_DEFS_PATH = Path("/etc/login.defs")
DEFAULT_SUDOERS_PATH = Path("/etc/sudoers")
DEFAULT_SUDOERS_DIR = Path("/etc/sudoers.d")


def collect_users(
    passwd_path: Path = Path("/etc/passwd"),
    group_path: Path = Path("/etc/group"),
) -> tuple[UserInfo, ...]:
    entries = parse_passwd(passwd_path.read_text(encoding="utf-8"))
    group_names, memberships = parse_group(group_path.read_text(encoding="utf-8"))

    users: list[UserInfo] = []
    for name, uid, gid, home, shell in entries:
        primary = group_names.get(gid, str(gid))
        supplemental = tuple(
            group for group in memberships.get(name, ()) if group != primary
        )
        users.append(
            UserInfo(
                name=name,
                uid=uid,
                gid=gid,
                group=primary,
                home=home,
                shell=shell,
                supplemental_groups=supplemental,
            )
        )
    return tuple(users)


def parse_passwd(text: str) -> tuple[tuple[str, int, int, str, str], ...]:
    entries: list[tuple[str, int, int, str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _, raw_uid, raw_gid, _, home, shell = parts[:7]
        try:
            entries.append((name, int(raw_uid), int(raw_gid), home, shell))
        except ValueError:
            continue
    return tuple(entries)


def parse_group(
    text: str,
) -> tuple[dict[int, str], dict[str, tuple[str, ...]]]:
    names: dict[int, str] = {}
    members: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name = parts[0]
        try:
            gid = int(parts[2])
        except ValueError:
            continue
        names[gid] = name
        for member in parts[3].split(","):
            member = member.strip()
            if member:
                members.setdefault(member, []).append(name)
    memberships: dict[str, tuple[str, ...]] = {
        name: tuple(groups) for name, groups in members.items()
    }
    return names, memberships


def collect_shadow(path: Path = DEFAULT_SHADOW_PATH) -> ShadowInfo:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ShadowInfo(readable=False)
    return ShadowInfo(readable=True, entries=parse_shadow(text))


def parse_shadow(text: str) -> tuple[ShadowEntry, ...]:
    entries: list[ShadowEntry] = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 2 or not parts[0]:
            continue
        entries.append(
            ShadowEntry(
                name=parts[0],
                password=parts[1],
                max_days=parts[4] if len(parts) > 4 else "",
                warn_days=parts[5] if len(parts) > 5 else "",
            )
        )
    return tuple(entries)


def collect_sudoers(
    main_path: Path = DEFAULT_SUDOERS_PATH,
    dropin_dir: Path = DEFAULT_SUDOERS_DIR,
) -> SudoersInfo:
    paths = [main_path]
    if dropin_dir.is_dir():
        paths.extend(sorted(path for path in dropin_dir.iterdir() if path.is_file()))

    entries: list[SudoEntry] = []
    readable = False
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        readable = True
        entries.extend(parse_sudoers(text, str(path)))
    return SudoersInfo(readable=readable, entries=tuple(entries))


def parse_sudoers(text: str, file: str = "(inline)") -> tuple[SudoEntry, ...]:
    entries: list[SudoEntry] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(
            SudoEntry(
                file=file,
                line=line_number,
                text=stripped,
                nopasswd="NOPASSWD" in stripped.upper(),
            )
        )
    return tuple(entries)


def collect_login_defs(path: Path = DEFAULT_LOGIN_DEFS_PATH) -> LoginDefsInfo:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return LoginDefsInfo(readable=False)
    return LoginDefsInfo(readable=True, values=parse_login_defs(text))


def parse_login_defs(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) == 2:
            values[parts[0]] = parts[1].strip()
    return values
