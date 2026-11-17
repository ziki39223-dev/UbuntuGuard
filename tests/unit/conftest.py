"""Shared fixtures for unit tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ubuntuguard.core.config import Config, load_config
from ubuntuguard.models import CommandResult, CpuInfo, HostInfo, MemoryInfo, SystemSnapshot


class FakeExecutor:
    """Records commands and returns canned results; no process is spawned."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.responses: dict[tuple[str, ...], CommandResult] = {}
        self.default = CommandResult(argv=(), returncode=0)

    def run(
        self,
        argv: Any,
        timeout: float | None = None,
        check: bool = False,
        dry_run: bool | None = None,
    ) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        result = self.responses.get(key, self.default)
        if result.argv == ():
            return CommandResult(
                argv=key,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                timed_out=result.timed_out,
                dry_run=result.dry_run,
            )
        return result


@pytest.fixture
def fake_executor() -> FakeExecutor:
    return FakeExecutor()


@pytest.fixture
def config() -> Config:
    return load_config(Path("/nonexistent/ubuntuguard-test-config.yaml"))


@pytest.fixture
def make_snapshot() -> Callable[..., SystemSnapshot]:
    def _make(**overrides: Any) -> SystemSnapshot:
        values: dict[str, Any] = {
            "collected_at": "2026-11-17T00:00:00+08:00",
            "host": HostInfo(
                hostname="test-host",
                os_id="ubuntu",
                os_version="24.04",
                os_pretty_name="Ubuntu 24.04 LTS",
                kernel="6.8.0-test",
                uptime_seconds=3600.0,
            ),
            "cpu": CpuInfo(model="test-cpu", cores=4),
            "memory": MemoryInfo(
                total_bytes=1024,
                available_bytes=512,
                used_bytes=512,
                used_percent=50.0,
            ),
        }
        values.update(overrides)
        return SystemSnapshot(**values)

    return _make
