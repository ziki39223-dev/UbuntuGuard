"""Health metric collection from /proc or an optional node_exporter endpoint."""

from __future__ import annotations

import os
import re
import shutil
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.config import Config
from ..core.executor import CommandExecutor
from ..errors import UbuntuGuardError

_PROM_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([0-9.eE+-]+)")

PROC_STAT = Path("/proc/stat")
PROC_MEMINFO = Path("/proc/meminfo")
PROC_LOADAVG = Path("/proc/loadavg")


@dataclass(frozen=True)
class MetricSample:
    name: str
    labels: dict[str, str]
    value: float


@dataclass(frozen=True)
class Metrics:
    source: str = "unavailable"
    cpu_percent: float | None = None
    memory_percent: float | None = None
    load_per_core: float | None = None
    disk_usage: tuple[tuple[str, float], ...] = ()
    services: tuple[tuple[str, bool | None], ...] = ()
    errors: tuple[str, ...] = ()


def collect_metrics(
    config: Config,
    executor: CommandExecutor,
    sample_interval: float = 0.3,
    opener: Callable[..., Any] | None = None,
) -> Metrics:
    mounts = tuple(config.get("monitoring.disk_mounts", ["/"])) or ("/",)
    services = tuple(config.get("monitoring.services", ["ssh"]))
    errors: list[str] = []

    node_enabled = bool(config.get("monitoring.node_exporter.enabled", False))
    if node_enabled:
        url = str(config.get("monitoring.node_exporter.url", ""))
        try:
            text = fetch_text(url, opener=opener)
        except OSError as exc:
            errors.append(f"node_exporter: {exc}")
            text = ""
        if text:
            samples = parse_prometheus(text)
            service_states = check_services(executor, services, errors)
            return Metrics(
                source="node_exporter",
                cpu_percent=node_cpu_percent(samples),
                memory_percent=node_memory_percent(samples),
                load_per_core=node_load_per_core(samples),
                disk_usage=node_disk_usage(samples, mounts),
                services=service_states,
                errors=tuple(errors),
            )

    cpu_percent = collect_cpu_percent(sample_interval)
    memory_percent = read_memory_percent()
    load_per_core = read_load_per_core()
    disk_usage = disk_usages(mounts)
    service_states = check_services(executor, services, errors)

    any_metric = (
        cpu_percent is not None
        or memory_percent is not None
        or load_per_core is not None
        or bool(disk_usage)
    )
    return Metrics(
        source="proc" if any_metric else "unavailable",
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        load_per_core=load_per_core,
        disk_usage=disk_usage,
        services=service_states,
        errors=tuple(errors),
    )


def parse_proc_stat(text: str) -> tuple[int, int]:
    for line in text.splitlines():
        if not line.startswith("cpu "):
            continue
        try:
            values = [int(item) for item in line.split()[1:9]]
        except ValueError:
            return 0, 0
        if len(values) < 4:
            return 0, 0
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return idle, sum(values)
    return 0, 0


def compute_cpu_percent(
    first: tuple[int, int], second: tuple[int, int]
) -> float | None:
    idle_delta = second[0] - first[0]
    total_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    return round(100.0 * (1 - idle_delta / total_delta), 1)


def collect_cpu_percent(
    interval: float = 0.3, stat_path: Path = PROC_STAT
) -> float | None:
    try:
        first = parse_proc_stat(stat_path.read_text(encoding="utf-8"))
        time.sleep(max(interval, 0.0))
        second = parse_proc_stat(stat_path.read_text(encoding="utf-8"))
    except OSError:
        return None
    return compute_cpu_percent(first, second)


def read_memory_percent(path: Path = PROC_MEMINFO) -> float | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if not parts:
            continue
        try:
            values[key.strip()] = int(parts[0])
        except ValueError:
            continue
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable")
    if available is None:
        available = (
            values.get("MemFree", 0)
            + values.get("Buffers", 0)
            + values.get("Cached", 0)
        )
    if total <= 0:
        return None
    used = max(total - available, 0)
    return round(used / total * 100, 1)


def read_load_per_core(
    path: Path = PROC_LOADAVG, cores: int | None = None
) -> float | None:
    core_count = cores if cores is not None else (os.cpu_count() or 0)
    if core_count <= 0:
        return None
    try:
        first = path.read_text(encoding="utf-8").split()
        load = float(first[0])
    except (OSError, IndexError, ValueError):
        return None
    return round(load / core_count, 2)


def disk_usages(
    mounts: tuple[str, ...],
    usage_func: Callable[[str], Any] = shutil.disk_usage,
) -> tuple[tuple[str, float], ...]:
    results: list[tuple[str, float]] = []
    for mount in mounts:
        try:
            usage = usage_func(mount)
        except OSError:
            continue
        if usage.total <= 0:
            continue
        results.append((mount, round(usage.used / usage.total * 100, 1)))
    return tuple(results)


def fetch_text(
    url: str,
    opener: Callable[..., Any] | None = None,
    timeout: float = 5.0,
) -> str:
    if not url:
        raise OSError("metrics url is empty")
    request = urllib.request.Request(url, headers={"User-Agent": "ubuntuguard"})
    open_func = opener or urllib.request.urlopen
    with open_func(request, timeout=timeout) as response:
        raw = response.read()
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def parse_prometheus(text: str) -> tuple[MetricSample, ...]:
    samples: list[MetricSample] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _PROM_RE.match(stripped)
        if not match:
            continue
        try:
            value = float(match.group(3))
        except ValueError:
            continue
        samples.append(
            MetricSample(
                name=match.group(1),
                labels=_parse_labels(match.group(2) or ""),
                value=value,
            )
        )
    return tuple(samples)


def node_cpu_percent(samples: tuple[MetricSample, ...]) -> float | None:
    idle = 0.0
    total = 0.0
    for sample in samples:
        if sample.name != "node_cpu_seconds_total":
            continue
        total += sample.value
        if sample.labels.get("mode") == "idle":
            idle += sample.value
    if total <= 0:
        return None
    return round(100.0 * (1 - idle / total), 1)


def node_memory_percent(samples: tuple[MetricSample, ...]) -> float | None:
    total = _metric_value(samples, "node_memory_MemTotal_bytes")
    available = _metric_value(samples, "node_memory_MemAvailable_bytes")
    if total is None or available is None or total <= 0:
        return None
    return round((1 - available / total) * 100, 1)


def node_load_per_core(samples: tuple[MetricSample, ...]) -> float | None:
    load = _metric_value(samples, "node_load1")
    cores = os.cpu_count() or 0
    if load is None or cores <= 0:
        return None
    return round(load / cores, 2)


def node_disk_usage(
    samples: tuple[MetricSample, ...], mounts: tuple[str, ...]
) -> tuple[tuple[str, float], ...]:
    results: list[tuple[str, float]] = []
    for mount in mounts:
        size = _metric_value(
            samples, "node_filesystem_size_bytes", {"mountpoint": mount}
        )
        available = _metric_value(
            samples, "node_filesystem_avail_bytes", {"mountpoint": mount}
        )
        if size is None or available is None or size <= 0:
            continue
        results.append((mount, round((1 - available / size) * 100, 1)))
    return tuple(results)


def check_services(
    executor: CommandExecutor,
    services: tuple[str, ...],
    errors: list[str],
) -> tuple[tuple[str, bool | None], ...]:
    states: list[tuple[str, bool | None]] = []
    for service in services:
        try:
            result = executor.run(["systemctl", "is-active", service])
        except UbuntuGuardError as exc:
            errors.append(f"services: {exc}")
            states.append((service, None))
            continue
        states.append((service, result.stdout.strip() == "active"))
    return tuple(states)


def _metric_value(
    samples: tuple[MetricSample, ...],
    name: str,
    labels: dict[str, str] | None = None,
) -> float | None:
    for sample in samples:
        if sample.name != name:
            continue
        if labels and any(sample.labels.get(key) != value for key, value in labels.items()):
            continue
        return sample.value
    return None


def _parse_labels(raw: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for pair in raw.split(","):
        key, separator, value = pair.partition("=")
        if not separator:
            continue
        labels[key.strip()] = value.strip().strip('"')
    return labels
