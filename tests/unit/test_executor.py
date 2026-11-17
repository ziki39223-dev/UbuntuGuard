"""Safe command executor tests."""

from __future__ import annotations

import sys

import pytest

from ubuntuguard.core.executor import CommandExecutor
from ubuntuguard.errors import CommandExecutionError, CommandFailedError


def test_dry_run_does_not_execute() -> None:
    result = CommandExecutor(dry_run=True).run(["definitely-not-a-real-command"])
    assert result.dry_run
    assert result.returncode == 0
    assert result.ok


def test_runs_command_and_captures_output() -> None:
    result = CommandExecutor().run([sys.executable, "-c", "print('hello')"])
    assert result.ok
    assert "hello" in result.stdout
    assert result.argv[0] == sys.executable


def test_rejects_shell_string() -> None:
    with pytest.raises(TypeError):
        CommandExecutor().run("echo hi")  # type: ignore[arg-type]


def test_rejects_empty_argv() -> None:
    with pytest.raises(ValueError):
        CommandExecutor().run([])


def test_missing_command_raises() -> None:
    with pytest.raises(CommandExecutionError):
        CommandExecutor().run(["ubuntuguard-command-that-does-not-exist"])


def test_nonzero_exit_and_check() -> None:
    argv = [sys.executable, "-c", "import sys; sys.exit(3)"]
    result = CommandExecutor().run(argv)
    assert result.returncode == 3
    assert not result.ok
    with pytest.raises(CommandFailedError):
        CommandExecutor().run(argv, check=True)


def test_timeout_returns_124() -> None:
    result = CommandExecutor(timeout=0.2).run(
        [sys.executable, "-c", "import time; time.sleep(2)"]
    )
    assert result.timed_out
    assert result.returncode == 124
