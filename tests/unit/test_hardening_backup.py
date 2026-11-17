"""Snapshot store tests."""

from __future__ import annotations

from pathlib import Path

from ubuntuguard.backup import SnapshotStore


def test_snapshot_verify_and_restore(tmp_path: Path) -> None:
    target = tmp_path / "etc" / "app.conf"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    store = SnapshotStore(tmp_path / "snapshots")
    snapshot = store.create([target], label="test")

    assert snapshot.entries[0].existed
    assert store.verify(snapshot)

    target.write_text("after\n", encoding="utf-8")
    store.restore(snapshot)
    assert target.read_text(encoding="utf-8") == "before\n"


def test_snapshot_restore_removes_file_that_did_not_exist(tmp_path: Path) -> None:
    new_file = tmp_path / "new.conf"
    store = SnapshotStore(tmp_path / "snapshots")

    snapshot = store.create([new_file], label="test")
    assert snapshot.entries[0].existed is False

    new_file.write_text("created later\n", encoding="utf-8")
    store.restore(snapshot)
    assert not new_file.exists()


def test_manifest_is_written(tmp_path: Path) -> None:
    target = tmp_path / "app.conf"
    target.write_text("x\n", encoding="utf-8")
    store = SnapshotStore(tmp_path / "snapshots")
    snapshot = store.create([target], label="harden")

    assert (snapshot.directory / "manifest.json").is_file()
    assert (snapshot.directory / "files").is_dir()
