"""Exception hierarchy with fixed exit code mapping."""

from __future__ import annotations

from .exit_codes import ExitCode
from .models import CommandResult


class UbuntuGuardError(Exception):
    """Base error carrying the CLI exit code for this failure."""

    exit_code: ExitCode = ExitCode.INTERNAL


class ConfigError(UbuntuGuardError):
    exit_code = ExitCode.USAGE


class PermissionDeniedError(UbuntuGuardError):
    exit_code = ExitCode.PERMISSION


class MissingDependencyError(UbuntuGuardError):
    exit_code = ExitCode.MISSING_DEPENDENCY


class UnsupportedPlatformError(UbuntuGuardError):
    exit_code = ExitCode.UNSUPPORTED


class CommandExecutionError(UbuntuGuardError):
    """A command could not be started (not found, not executable, OS error)."""


class CommandFailedError(UbuntuGuardError):
    """A command ran and returned a non-zero exit status."""

    def __init__(self, result: CommandResult) -> None:
        self.result = result
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        super().__init__(
            f"command failed with exit {result.returncode}: {' '.join(result.argv)}: {detail}"
        )
