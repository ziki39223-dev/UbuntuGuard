"""Safe system command executor.

All system commands must go through this module. Never pass shell strings:
argv is always a sequence of arguments and shell=False is enforced.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from collections.abc import Mapping, Sequence

from ...errors import CommandExecutionError, CommandFailedError
from ...models import CommandResult

TIMEOUT_EXIT_CODE = 124


class CommandExecutor:
    def __init__(
        self,
        timeout: float = 30.0,
        dry_run: bool = False,
        logger: logging.Logger | None = None,
        env_overrides: Mapping[str, str] | None = None,
    ) -> None:
        self._timeout = timeout
        self._dry_run = dry_run
        self._logger = logger or logging.getLogger("ubuntuguard.executor")
        self._env_overrides = dict(env_overrides or {})

    def run(
        self,
        argv: Sequence[str],
        timeout: float | None = None,
        check: bool = False,
        dry_run: bool | None = None,
    ) -> CommandResult:
        args = _validate_argv(argv)
        effective_dry_run = self._dry_run if dry_run is None else dry_run

        if effective_dry_run:
            self._logger.info("dry-run: %s", " ".join(args))
            return CommandResult(argv=tuple(args), returncode=0, dry_run=True)

        effective_timeout = self._timeout if timeout is None else timeout
        started = time.monotonic()
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                shell=False,
                env=self._build_env(),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = _elapsed_ms(started)
            self._logger.warning(
                "command timed out after %ss: %s", effective_timeout, " ".join(args)
            )
            return CommandResult(
                argv=tuple(args),
                returncode=TIMEOUT_EXIT_CODE,
                stdout=_to_text(exc.stdout),
                stderr=_to_text(exc.stderr),
                duration_ms=duration_ms,
                timed_out=True,
            )
        except FileNotFoundError as exc:
            raise CommandExecutionError(f"command not found: {args[0]}") from exc
        except PermissionError as exc:
            raise CommandExecutionError(f"permission denied executing: {args[0]}") from exc
        except OSError as exc:
            raise CommandExecutionError(f"cannot execute {args[0]}: {exc}") from exc

        result = CommandResult(
            argv=tuple(args),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=_elapsed_ms(started),
        )
        self._logger.debug(
            "command finished: %s (exit=%s, %sms)",
            " ".join(args),
            result.returncode,
            result.duration_ms,
        )
        if check and not result.ok:
            raise CommandFailedError(result)
        return result

    def _build_env(self) -> dict[str, str]:
        env = dict(os.environ)
        # Stable, parseable output regardless of the caller's locale.
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env.update(self._env_overrides)
        return env


def _validate_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, str | bytes):
        raise TypeError("argv must be a sequence of arguments, not a string")
    args = list(argv)
    if not args:
        raise ValueError("argv must not be empty")
    for item in args:
        if not isinstance(item, str):
            raise TypeError(f"argv items must be strings, got {type(item).__name__}")
        if "\x00" in item:
            raise ValueError("argv must not contain NUL characters")
    return args


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
