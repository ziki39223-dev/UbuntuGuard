"""Process collector based on `ps`."""

from __future__ import annotations

from ..core.executor import CommandExecutor
from ..models import ProcessInfo

DEFAULT_LIMIT = 20


def collect_processes(
    executor: CommandExecutor, limit: int = DEFAULT_LIMIT
) -> tuple[ProcessInfo, ...]:
    output = executor.run(
        ["ps", "-eo", "pid=,ppid=,user=,pcpu=,pmem=,args="], check=True
    ).stdout
    return parse_ps(output, limit=limit)


def parse_ps(text: str, limit: int = DEFAULT_LIMIT) -> tuple[ProcessInfo, ...]:
    processes: list[ProcessInfo] = []
    for line in text.splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            cpu_percent = float(parts[3])
            mem_percent = float(parts[4])
        except ValueError:
            continue
        processes.append(
            ProcessInfo(
                pid=pid,
                ppid=ppid,
                user=parts[2],
                cpu_percent=cpu_percent,
                mem_percent=mem_percent,
                command=parts[5] if len(parts) > 5 else "",
            )
        )
    processes.sort(key=lambda process: process.cpu_percent, reverse=True)
    return tuple(processes[:limit])
