"""Platform and dependency check tests."""

from __future__ import annotations

from pathlib import Path

from ubuntuguard.core.permissions import (
    EnvironmentStatus,
    check_environment,
    missing_dependencies,
    read_os_release,
)


def test_read_os_release_parses_quotes(tmp_path: Path) -> None:
    path = tmp_path / "os-release"
    path.write_text(
        'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n# comment\n',
        encoding="utf-8",
    )
    values = read_os_release(path)
    assert values["ID"] == "ubuntu"
    assert values["VERSION_ID"] == "24.04"
    assert values["NAME"] == "Ubuntu"


def test_read_os_release_missing_file(tmp_path: Path) -> None:
    assert read_os_release(tmp_path / "absent") == {}


def test_missing_dependencies_detects_unknown_binary() -> None:
    assert missing_dependencies(["ubuntuguard-definitely-missing"]) == (
        "ubuntuguard-definitely-missing",
    )


def test_check_environment_returns_status() -> None:
    status = check_environment()
    assert isinstance(status, EnvironmentStatus)
    assert status.python_version
    payload = status.as_dict()
    assert "supported" in payload
    assert "is_root" in payload
