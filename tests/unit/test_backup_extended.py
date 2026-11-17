"""Phase 7 backup and restore tests."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from ubuntuguard.backup import SnapshotStore, expand_paths
from ubuntuguard.cli.main import main
from ubuntuguard.exit_codes import ExitCode


def _make_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "etc"
    (root / "sshd_config.d").mkdir(parents=True)
    passwd = root / "passwd"
    passwd.write_text("root:x:0:0\n", encoding="utf-8")
    sshd = root / "sshd_config.d" / "99-ubuntuguard.conf"
    sshd.write_text("PermitRootLogin no\n", encoding="utf-8")
    group = root / "group"
    group.write_text("root:x:0:\n", encoding="utf-8")
    return passwd, sshd, group


def test_expand_paths_files_dirs_and_glob(tmp_path: Path) -> None:
    passwd, sshd, group = _make_files(tmp_path)
    files = expand_paths(
        [
            str(tmp_path / "etc"),
            str(passwd),
            str(tmp_path / "etc" / "*.missing"),
        ]
    )
    assert set(files) == {passwd, sshd, group}


def test_expand_paths_can_record_missing_literals(tmp_path: Path) -> None:
    missing = tmp_path / "managed.conf"
    files = expand_paths([str(missing), str(tmp_path / "*.glob")], include_missing=True)
    assert files == (missing,)


def test_create_list_load_verify_and_compress(tmp_path: Path) -> None:
    passwd, sshd, _ = _make_files(tmp_path)
    store = SnapshotStore(tmp_path / "backups")

    snapshot = store.create([passwd, sshd], label="backup", compress=True)
    assert (snapshot.directory / "archive.tar.gz").is_file()

    infos = store.list()
    assert len(infos) == 1
    assert infos[0].snapshot_id == snapshot.snapshot_id
    assert infos[0].files == 2
    assert infos[0].compressed is True
    assert infos[0].created_at

    loaded = store.load(snapshot.snapshot_id)
    assert store.verify(loaded)

    stored = snapshot.directory / "files" / str(loaded.entries[0].stored)
    stored.write_text("corrupted", encoding="utf-8")
    assert store.verify(loaded) is False


def test_snapshot_ids_are_unique(tmp_path: Path) -> None:
    passwd, _, _ = _make_files(tmp_path)
    store = SnapshotStore(tmp_path / "backups")
    first = store.create([passwd], label="backup")
    second = store.create([passwd], label="backup")
    assert first.snapshot_id != second.snapshot_id


def test_diff_restore_and_drill(tmp_path: Path) -> None:
    passwd, sshd, _ = _make_files(tmp_path)
    absent = tmp_path / "new.conf"
    store = SnapshotStore(tmp_path / "backups")
    snapshot = store.create([passwd, sshd, absent], label="backup")

    passwd.write_text("changed\n", encoding="utf-8")
    sshd.unlink()
    absent.write_text("added later\n", encoding="utf-8")

    statuses = {item.path: item.status for item in store.diff(snapshot)}
    assert statuses[str(passwd)] == "changed"
    assert statuses[str(sshd)] == "missing"
    assert statuses[str(absent)] == "added"

    drill_dir = tmp_path / "drill"
    restored = store.drill(snapshot, drill_dir)
    assert restored == 2
    drill_passwd = drill_dir / snapshot.entries[0].stored
    assert drill_passwd.read_text(encoding="utf-8") == "root:x:0:0\n"

    store.restore(snapshot)
    assert passwd.read_text(encoding="utf-8") == "root:x:0:0\n"
    assert sshd.is_file()
    assert not absent.exists()
    assert all(item.status == "unchanged" for item in store.diff(snapshot))


def test_drill_detects_hash_mismatch(tmp_path: Path) -> None:
    passwd, _, _ = _make_files(tmp_path)
    store = SnapshotStore(tmp_path / "backups")
    snapshot = store.create([passwd], label="backup")

    stored = snapshot.directory / "files" / str(snapshot.entries[0].stored)
    stored.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(OSError):
        store.drill(snapshot, tmp_path / "drill")


def test_prune_retention_policy(tmp_path: Path) -> None:
    passwd, _, _ = _make_files(tmp_path)
    store = SnapshotStore(tmp_path / "backups")
    oldest = store.create([passwd], label="backup")
    middle = store.create([passwd], label="backup")
    newest = store.create([passwd], label="backup")

    old_time = time.time() - 100 * 86400
    os.utime(oldest.directory, (old_time, old_time))

    removed = store.prune(days=30, count=1)
    assert removed == (oldest.snapshot_id,)
    remaining = {info.snapshot_id for info in store.list()}
    assert remaining == {middle.snapshot_id, newest.snapshot_id}


def test_cli_backup_list_verify_drill(
    tmp_path: Path, capsys
) -> None:
    passwd, sshd, _ = _make_files(tmp_path)
    backup_dir = tmp_path / "backups"
    store = SnapshotStore(backup_dir)
    snapshot = store.create([passwd, sshd], label="backup")

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "version: 1\n"
        "backup:\n"
        f'  dir: "{backup_dir.as_posix()}"\n'
        "  compress: false\n",
        encoding="utf-8",
    )

    assert main(["--config", str(config_path), "backup", "list"]) == ExitCode.OK
    assert snapshot.snapshot_id in capsys.readouterr().out

    assert (
        main(
            ["--config", str(config_path), "backup", "verify", snapshot.snapshot_id]
        )
        == ExitCode.OK
    )
    assert "valid" in capsys.readouterr().out

    assert (
        main(
            ["--config", str(config_path), "backup", "drill", snapshot.snapshot_id]
        )
        == ExitCode.OK
    )
    assert "drill ok" in capsys.readouterr().out


def test_cli_backup_missing_action_and_unknown_snapshot(
    tmp_path: Path, capsys
) -> None:
    assert main(["backup"]) == ExitCode.USAGE

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "version: 1\n"
        f'backup:\n  dir: "{(tmp_path / "backups").as_posix()}"\n',
        encoding="utf-8",
    )
    assert (
        main(["--config", str(config_path), "backup", "verify", "missing"])
        == ExitCode.INTERNAL
    )
    assert "snapshot not found" in capsys.readouterr().err
