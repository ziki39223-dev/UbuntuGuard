"""Append-only security event log (JSON lines)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..models import Finding


class EventLog:
    def __init__(self, path: Path) -> None:
        self._path = path

    def append(self, findings: Iterable[Finding]) -> int:
        items = list(findings)
        if not items:
            return 0
        self._path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = (
            datetime.now(tz=timezone.utc).astimezone().isoformat(timespec="seconds")
        )
        with self._path.open("a", encoding="utf-8") as handle:
            for finding in items:
                record = {
                    "ts": timestamp,
                    "tool_version": __version__,
                    "id": finding.id,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "title": finding.title,
                    "evidence": finding.evidence,
                }
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return len(items)
