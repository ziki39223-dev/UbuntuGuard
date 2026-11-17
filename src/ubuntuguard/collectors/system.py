"""Host, CPU and memory collectors (read-only /proc parsing)."""

from __future__ import annotations

import os
import platform
import socket
from pathlib import Path

from ..core.permissions import read_os_release
from ..models import CpuInfo, HostInfo, MemoryInfo

_KIB = 1024


def collect_host() -> HostInfo:
    release = read_os_release()
    return HostInfo(
        hostname=socket.gethostname(),
        os_id=release.get("ID", "unknown"),
        os_version=release.get("VERSION_ID", "unknown"),
        os_pretty_name=release.get("PRETTY_NAME", ""),
        kernel=platform.release(),
        uptime_seconds=read_uptime(),
    )


def read_uptime(path: Path = Path("/proc/uptime")) -> float | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None


def collect_cpu() -> CpuInfo:
    return CpuInfo(
        model=read_cpu_model(),
        cores=os.cpu_count() or 0,
        load_average=read_load_average(),
    )


def read_cpu_model(path: Path = Path("/proc/cpuinfo")) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        key, separator, value = line.partition(":")
        if separator and key.strip() == "model name":
            return value.strip()
    return ""


def read_load_average(path: Path = Path("/proc/loadavg")) -> tuple[float, ...]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ()
    return parse_loadavg(text)


def parse_loadavg(text: str) -> tuple[float, ...]:
    parts = text.split()
    if len(parts) < 3:
        return ()
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        return ()


def collect_memory(path: Path = Path("/proc/meminfo")) -> MemoryInfo:
    return parse_meminfo(path.read_text(encoding="utf-8"))


def parse_meminfo(text: str) -> MemoryInfo:
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, separator, rest = line.partition(":")
        if not separator:
            continue
        parts = rest.split()
        if not parts:
            continue
        try:
            values[key.strip()] = int(parts[0]) * _KIB
        except ValueError:
            continue

    total = values.get("MemTotal", 0)
    if total <= 0:
        raise ValueError("MemTotal missing in /proc/meminfo")

    available = values.get("MemAvailable")
    if available is None:
        available = (
            values.get("MemFree", 0)
            + values.get("Buffers", 0)
            + values.get("Cached", 0)
        )
    used = max(total - available, 0)

    swap_total = values.get("SwapTotal", 0)
    swap_free = values.get("SwapFree", 0)
    swap_used = max(swap_total - swap_free, 0)

    return MemoryInfo(
        total_bytes=total,
        available_bytes=available,
        used_bytes=used,
        used_percent=round(used / total * 100, 1),
        swap_total_bytes=swap_total,
        swap_used_bytes=swap_used,
    )
