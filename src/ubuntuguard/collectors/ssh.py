"""SSH server configuration collector.

Preferred source is `sshd -T` (effective configuration). When that is not
available the main config plus `sshd_config.d/*.conf` are parsed as a fallback.
"""

from __future__ import annotations

from pathlib import Path

from ..core.executor import CommandExecutor
from ..errors import UbuntuGuardError
from ..models import SshInfo

DEFAULT_SSH_CONFIG = Path("/etc/ssh/sshd_config")
DEFAULT_DROPIN_DIR = Path("/etc/ssh/sshd_config.d")


def collect_ssh(
    executor: CommandExecutor,
    config_path: Path = DEFAULT_SSH_CONFIG,
    dropin_dir: Path = DEFAULT_DROPIN_DIR,
) -> SshInfo:
    try:
        output = executor.run(["sshd", "-T"], check=True).stdout
    except UbuntuGuardError:
        output = ""
    effective = parse_sshd_effective(output)
    if effective:
        return SshInfo(effective=effective, source="sshd -T")

    files, fallback = read_sshd_files(config_path, dropin_dir)
    return SshInfo(
        effective=fallback,
        source="files" if files else "unavailable",
        config_files=files,
    )


def parse_sshd_effective(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(maxsplit=1)
        if not parts:
            continue
        values[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else ""
    return values


def read_sshd_files(
    config_path: Path = DEFAULT_SSH_CONFIG,
    dropin_dir: Path = DEFAULT_DROPIN_DIR,
) -> tuple[tuple[str, ...], dict[str, str]]:
    files: list[str] = []
    values: dict[str, str] = {}

    try:
        main_text = config_path.read_text(encoding="utf-8")
    except OSError:
        main_text = None
    if main_text is not None:
        files.append(str(config_path))
        values.update(parse_sshd_config(main_text))

    if dropin_dir.is_dir():
        for path in sorted(dropin_dir.glob("*.conf")):
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            files.append(str(path))
            values.update(parse_sshd_config(text))

    return tuple(files), values


def parse_sshd_config(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    in_match_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keyword = stripped.split(maxsplit=1)[0].lower()
        if keyword == "match":
            in_match_block = True
            continue
        if keyword == "include":
            continue
        if in_match_block:
            continue
        parts = stripped.split(maxsplit=1)
        values[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else ""
    return values
