"""Configuration backup snapshots.

Layout::

    <root>/<timestamp>-<label>/
        manifest.json            # entries, sha256, created_at
        files/<storage key>      # copied files
        archive.tar.gz           # optional compressed copy of files/

Restore and drill both verify SHA256 from the manifest.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__


@dataclass(frozen=True)
class SnapshotEntry:
    path: str
    existed: bool
    stored: str | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    directory: Path
    entries: tuple[SnapshotEntry, ...]


@dataclass(frozen=True)
class SnapshotInfo:
    snapshot_id: str
    created_at: str
    directory: Path
    files: int
    compressed: bool


@dataclass(frozen=True)
class FileDiff:
    path: str
    status: str
    snapshot_sha256: str | None = None
    current_sha256: str | None = None


class SnapshotStore:
    def __init__(self, root: Path) -> None:
        self._root = root

    def create(
        self,
        paths: list[Path] | tuple[Path, ...],
        label: str = "harden",
        compress: bool = False,
    ) -> Snapshot:
        directory = self._new_directory(label)
        files_dir = directory / "files"
        files_dir.mkdir(parents=True, exist_ok=True)

        entries: list[SnapshotEntry] = []
        for path in paths:
            if path.is_file():
                key = _storage_key(path)
                stored = files_dir / key
                stored.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, stored)
                entries.append(
                    SnapshotEntry(
                        path=str(path),
                        existed=True,
                        stored=key,
                        sha256=_sha256(stored),
                    )
                )
            else:
                entries.append(SnapshotEntry(path=str(path), existed=False))

        archive_name: str | None = None
        if compress:
            archive_path = directory / "archive.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(files_dir, arcname="files")
            archive_name = archive_path.name

        manifest = {
            "schema_version": 1,
            "tool_version": __version__,
            "snapshot_id": directory.name,
            "created_at": _now(),
            "archive": archive_name,
            "entries": [
                {
                    "path": entry.path,
                    "existed": entry.existed,
                    "stored": entry.stored,
                    "sha256": entry.sha256,
                }
                for entry in entries
            ],
        }
        (directory / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return Snapshot(
            snapshot_id=directory.name,
            directory=directory,
            entries=tuple(entries),
        )

    def list(self) -> tuple[SnapshotInfo, ...]:
        if not self._root.is_dir():
            return ()
        infos: list[SnapshotInfo] = []
        for directory in sorted(self._root.iterdir()):
            if not directory.is_dir():
                continue
            manifest = self._read_manifest(directory)
            if manifest is None:
                continue
            entries = manifest.get("entries", [])
            infos.append(
                SnapshotInfo(
                    snapshot_id=str(manifest.get("snapshot_id", directory.name)),
                    created_at=str(manifest.get("created_at", "")),
                    directory=directory,
                    files=sum(
                        1
                        for entry in entries
                        if isinstance(entry, dict) and entry.get("existed")
                    ),
                    compressed=bool(manifest.get("archive")),
                )
            )
        return tuple(infos)

    def load(self, snapshot_id: str) -> Snapshot:
        if not snapshot_id or "/" in snapshot_id or "\\" in snapshot_id:
            raise OSError(f"invalid snapshot id: {snapshot_id}")
        directory = self._root / snapshot_id
        manifest = self._read_manifest(directory)
        if manifest is None:
            raise OSError(f"snapshot not found: {snapshot_id}")

        entries: list[SnapshotEntry] = []
        for raw in manifest.get("entries", []):
            if not isinstance(raw, dict):
                continue
            entries.append(
                SnapshotEntry(
                    path=str(raw.get("path", "")),
                    existed=bool(raw.get("existed", False)),
                    stored=raw.get("stored"),
                    sha256=raw.get("sha256"),
                )
            )
        return Snapshot(
            snapshot_id=str(manifest.get("snapshot_id", directory.name)),
            directory=directory,
            entries=tuple(entries),
        )

    def verify(self, snapshot: Snapshot) -> bool:
        files_dir = snapshot.directory / "files"
        for entry in snapshot.entries:
            if not entry.existed:
                continue
            if entry.stored is None or entry.sha256 is None:
                return False
            source = files_dir / entry.stored
            if not source.is_file():
                return False
            if _sha256(source) != entry.sha256:
                return False
        return True

    def diff(self, snapshot: Snapshot) -> tuple[FileDiff, ...]:
        diffs: list[FileDiff] = []
        for entry in snapshot.entries:
            current = Path(entry.path)
            if entry.existed:
                if not current.is_file():
                    diffs.append(
                        FileDiff(
                            path=entry.path,
                            status="missing",
                            snapshot_sha256=entry.sha256,
                        )
                    )
                    continue
                current_hash = _sha256(current)
                if current_hash != entry.sha256:
                    diffs.append(
                        FileDiff(
                            path=entry.path,
                            status="changed",
                            snapshot_sha256=entry.sha256,
                            current_sha256=current_hash,
                        )
                    )
                else:
                    diffs.append(
                        FileDiff(
                            path=entry.path,
                            status="unchanged",
                            snapshot_sha256=entry.sha256,
                            current_sha256=current_hash,
                        )
                    )
            elif current.is_file():
                diffs.append(
                    FileDiff(
                        path=entry.path,
                        status="added",
                        current_sha256=_sha256(current),
                    )
                )
        return tuple(diffs)

    def restore(self, snapshot: Snapshot) -> None:
        files_dir = self._ensure_files(snapshot)
        for entry in reversed(snapshot.entries):
            target = Path(entry.path)
            if entry.existed:
                if entry.stored is None:
                    raise OSError(f"snapshot entry missing stored file: {entry.path}")
                source = files_dir / entry.stored
                if not source.is_file():
                    raise OSError(f"snapshot file missing: {source}")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            elif target.is_file():
                target.unlink()

    def drill(self, snapshot: Snapshot, target: Path) -> int:
        """Restore into an isolated directory and verify hashes (no system changes)."""
        files_dir = self._ensure_files(snapshot)
        target.mkdir(parents=True, exist_ok=True)
        restored = 0
        for entry in snapshot.entries:
            if not entry.existed or entry.stored is None:
                continue
            source = files_dir / entry.stored
            if not source.is_file():
                raise OSError(f"snapshot file missing: {source}")
            destination = target / entry.stored
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            if entry.sha256 is None or _sha256(destination) != entry.sha256:
                raise OSError(f"hash mismatch while restoring {entry.path}")
            restored += 1
        return restored

    def prune(
        self, days: int, count: int, now: datetime | None = None
    ) -> tuple[str, ...]:
        current = now or datetime.now(tz=timezone.utc)
        infos = sorted(self.list(), key=lambda info: info.directory.name, reverse=True)
        removed: list[str] = []
        for index, info in enumerate(infos):
            if index < count:
                continue
            modified = datetime.fromtimestamp(
                info.directory.stat().st_mtime, tz=timezone.utc
            )
            age_days = (current - modified).total_seconds() / 86400
            if age_days <= days:
                continue
            shutil.rmtree(info.directory)
            removed.append(info.snapshot_id)
        return tuple(removed)

    def _new_directory(self, label: str) -> Path:
        self._root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base = f"{stamp}-{label}"
        candidate = base
        index = 2
        while (self._root / candidate).exists():
            candidate = f"{base}-{index}"
            index += 1
        (self._root / candidate).mkdir(parents=True)
        return self._root / candidate

    def _ensure_files(self, snapshot: Snapshot) -> Path:
        files_dir = snapshot.directory / "files"
        if files_dir.is_dir():
            return files_dir
        archive_path = snapshot.directory / "archive.tar.gz"
        if not archive_path.is_file():
            raise OSError(f"snapshot has no files or archive: {snapshot.snapshot_id}")
        _safe_extract(archive_path, snapshot.directory)
        if not files_dir.is_dir():
            raise OSError(f"archive did not contain files/: {snapshot.snapshot_id}")
        return files_dir

    @staticmethod
    def _read_manifest(directory: Path) -> dict[str, Any] | None:
        try:
            raw = json.loads(
                (directory / "manifest.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return None
        return raw if isinstance(raw, dict) else None


def _safe_extract(archive_path: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if root not in target.parents and target != root:
                continue
            archive.extract(member, destination)


def _storage_key(path: Path) -> str:
    return path.as_posix().lstrip("/").replace(":", "_")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(tz=timezone.utc).astimezone().isoformat(timespec="seconds")
