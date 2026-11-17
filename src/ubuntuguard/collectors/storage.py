"""Filesystem usage collector."""

from __future__ import annotations

import os
from pathlib import Path

from ..models import DiskInfo

# Only real filesystems are reported; tmpfs, cgroups, overlay and friends are noise.
_REAL_FILESYSTEMS = frozenset(
    {
        "ext2",
        "ext3",
        "ext4",
        "xfs",
        "btrfs",
        "vfat",
        "ntfs",
        "ntfs3",
        "zfs",
        "f2fs",
        "nfs",
        "nfs4",
        "cifs",
    }
)

_ESCAPES = {
    "\\040": " ",
    "\\011": "\t",
    "\\012": "\n",
    "\\134": "\\",
}


def parse_mounts(text: str) -> tuple[tuple[str, str, str], ...]:
    entries: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        device, mountpoint, fstype = parts[0], _unescape(parts[1]), parts[2]
        if fstype in _REAL_FILESYSTEMS:
            entries.append((device, mountpoint, fstype))
    return tuple(entries)


def collect_disks(mounts_path: Path = Path("/proc/mounts")) -> tuple[DiskInfo, ...]:
    text = mounts_path.read_text(encoding="utf-8")
    return read_disk_usage(parse_mounts(text))


def read_disk_usage(mounts: tuple[tuple[str, str, str], ...]) -> tuple[DiskInfo, ...]:
    statvfs = getattr(os, "statvfs", None)
    if statvfs is None:
        return ()
    disks: list[DiskInfo] = []
    seen_mountpoints: set[str] = set()
    for device, mountpoint, fstype in mounts:
        if mountpoint in seen_mountpoints:
            continue
        try:
            stats = statvfs(mountpoint)
        except OSError:
            continue
        if stats.f_blocks <= 0:
            continue
        total = stats.f_blocks * stats.f_frsize
        used = total - stats.f_bfree * stats.f_frsize
        seen_mountpoints.add(mountpoint)
        disks.append(
            DiskInfo(
                device=device,
                mountpoint=mountpoint,
                fstype=fstype,
                total_bytes=total,
                used_bytes=used,
                used_percent=round(used / total * 100, 1),
            )
        )
    return tuple(disks)


def _unescape(value: str) -> str:
    for escaped, raw in _ESCAPES.items():
        value = value.replace(escaped, raw)
    return value
