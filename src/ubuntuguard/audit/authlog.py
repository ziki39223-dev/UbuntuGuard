"""SSH authentication log parsing and collection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..core.executor import CommandExecutor
from ..errors import UbuntuGuardError

DEFAULT_AUTH_LOG = Path("/var/log/auth.log")
DEFAULT_JOURNAL_LINES = 2000

_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    kind: str
    user: str
    source_ip: str
    method: str = ""


@dataclass(frozen=True)
class AuthLogInfo:
    readable: bool = False
    source: str = "unavailable"
    events: tuple[AuthEvent, ...] = ()
    note: str = ""


def collect_auth_log(
    executor: CommandExecutor,
    path: Path = DEFAULT_AUTH_LOG,
    journal_lines: int = DEFAULT_JOURNAL_LINES,
) -> AuthLogInfo:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    if text.strip():
        return AuthLogInfo(
            readable=True, source=str(path), events=parse_auth_log(text)
        )

    try:
        result = executor.run(
            ["journalctl", "-u", "ssh", "--no-pager", "-n", str(journal_lines)]
        )
    except UbuntuGuardError as exc:
        return AuthLogInfo(readable=False, note=str(exc))
    if result.ok and result.stdout.strip():
        return AuthLogInfo(
            readable=True,
            source="journalctl",
            events=parse_auth_log(result.stdout),
        )
    return AuthLogInfo(
        readable=False, note="auth.log not readable and journalctl returned no data"
    )


def parse_auth_log(text: str) -> tuple[AuthEvent, ...]:
    events: list[AuthEvent] = []
    for line in text.splitlines():
        timestamp = line[:15] if len(line) > 15 and line[:3].isalpha() else ""

        failed = _FAILED_RE.search(line)
        if failed:
            events.append(
                AuthEvent(
                    timestamp=timestamp,
                    kind="failed_password",
                    user=failed.group("user"),
                    source_ip=failed.group("ip"),
                    method="password",
                )
            )
            continue

        invalid = _INVALID_USER_RE.search(line)
        if invalid:
            events.append(
                AuthEvent(
                    timestamp=timestamp,
                    kind="invalid_user",
                    user=invalid.group("user"),
                    source_ip=invalid.group("ip"),
                )
            )
            continue

        accepted = _ACCEPTED_RE.search(line)
        if accepted:
            events.append(
                AuthEvent(
                    timestamp=timestamp,
                    kind="accepted",
                    user=accepted.group("user"),
                    source_ip=accepted.group("ip"),
                    method=accepted.group("method"),
                )
            )
    return tuple(events)


def summarize_auth(events: tuple[AuthEvent, ...]) -> dict[str, object]:
    failed = [event for event in events if event.kind != "accepted"]
    accepted = [event for event in events if event.kind == "accepted"]

    failures_by_ip: dict[str, int] = {}
    for event in failed:
        failures_by_ip[event.source_ip] = failures_by_ip.get(event.source_ip, 0) + 1
    top_ips = sorted(failures_by_ip.items(), key=lambda item: item[1], reverse=True)[:5]

    return {
        "total_events": len(events),
        "failed": len(failed),
        "accepted": len(accepted),
        "distinct_invalid_users": len(
            {event.user for event in events if event.kind == "invalid_user"}
        ),
        "top_failure_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
    }
