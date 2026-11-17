"""Configuration backup and restore."""

from .paths import DEFAULT_BACKUP_PATHS, expand_paths
from .snapshot import (
    FileDiff,
    Snapshot,
    SnapshotEntry,
    SnapshotInfo,
    SnapshotStore,
)

__all__ = [
    "DEFAULT_BACKUP_PATHS",
    "FileDiff",
    "Snapshot",
    "SnapshotEntry",
    "SnapshotInfo",
    "SnapshotStore",
    "expand_paths",
]
