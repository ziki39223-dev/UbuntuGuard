"""Suspicious process detection based on /proc."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


@dataclass(frozen=True)
class SuspiciousProcess:
    pid: int
    exe: str
    command: str
    reason: str


def classify_process(exe: str, command: str) -> str | None:
    binary = exe or (command.split()[0] if command else "")
    if not binary:
        return None
    if binary.endswith(" (deleted)"):
        return "executable deleted from disk"
    if binary.startswith(TEMP_PREFIXES):
        return "executing from a temporary directory"
    return None


def detect_suspicious_processes(
    proc_root: Path = Path("/proc"), limit: int = 20
) -> tuple[SuspiciousProcess, ...]:
    if not proc_root.is_dir():
        return ()

    results: list[SuspiciousProcess] = []
    for entry in sorted(proc_root.iterdir(), key=lambda item: item.name):
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        command = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        exe = ""
        try:
            exe = os.readlink(entry / "exe")
        except OSError:
            exe = ""
        reason = classify_process(exe, command)
        if reason is None:
            continue
        binary = exe or (command.split()[0] if command else "")
        results.append(
            SuspiciousProcess(
                pid=int(entry.name),
                exe=binary,
                command=command,
                reason=reason,
            )
        )
        if len(results) >= limit:
            break
    return tuple(results)
