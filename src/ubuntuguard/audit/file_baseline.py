"""Lightweight checksum baseline for critical files."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_WATCHED_FILES = (
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/00-ubuntuguard.conf",
)


@dataclass(frozen=True)
class FileChange:
    path: str
    status: str
    old_sha256: str | None = None
    new_sha256: str | None = None


class FileBaseline:
    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def exists(self) -> bool:
        return self._path.is_file()

    def initialize(
        self, files: tuple[str, ...] = DEFAULT_WATCHED_FILES
    ) -> int:
        entries: dict[str, str] = {}
        for raw in files:
            path = Path(raw)
            if not path.is_file():
                continue
            try:
                entries[raw] = _sha256(path)
            except OSError:
                # Unreadable files (for example /etc/shadow as non-root) are skipped.
                continue
        payload = {
            "schema_version": 1,
            "created_at": datetime.now(tz=timezone.utc)
            .astimezone()
            .isoformat(timespec="seconds"),
            "files": entries,
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return len(entries)

    def compare(
        self, files: tuple[str, ...] = DEFAULT_WATCHED_FILES
    ) -> tuple[FileChange, ...]:
        baseline = self._load()
        changes: list[FileChange] = []

        for raw, expected in baseline.items():
            path = Path(raw)
            if not path.is_file():
                changes.append(
                    FileChange(path=raw, status="missing", old_sha256=expected)
                )
                continue
            try:
                current = _sha256(path)
            except OSError:
                # Cannot read the file, so no trustworthy comparison is possible.
                continue
            if current != expected:
                changes.append(
                    FileChange(
                        path=raw,
                        status="changed",
                        old_sha256=expected,
                        new_sha256=current,
                    )
                )

        for raw in files:
            if raw in baseline:
                continue
            path = Path(raw)
            if path.is_file():
                try:
                    digest = _sha256(path)
                except OSError:
                    continue
                changes.append(
                    FileChange(
                        path=raw,
                        status="added",
                        new_sha256=digest,
                    )
                )
        return tuple(changes)

    def _load(self) -> dict[str, str]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        files = raw.get("files")
        if not isinstance(files, dict):
            return {}
        return {
            str(key): str(value)
            for key, value in files.items()
            if isinstance(key, str) and isinstance(value, str)
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
