"""Configuration loading and validation tests."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from ubuntuguard.core.config import load_config, validate_config
from ubuntuguard.core.config.defaults import DEFAULTS
from ubuntuguard.errors import ConfigError


def test_missing_file_falls_back_to_defaults(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.yaml")
    assert config.source == "defaults"
    assert config.path is None
    assert config.get("general.timeout_seconds") == 30
    assert config.warnings


def test_file_overrides_are_merged(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "version: 1\n"
        "general:\n"
        "  timeout_seconds: 5\n"
        "firewall:\n"
        "  allow_ports: ['22/tcp', '443/tcp']\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.source == "file"
    assert config.path == path
    assert config.get("general.timeout_seconds") == 5
    assert config.get("general.log_level") == "info"
    assert config.get("firewall.allow_ports") == ["22/tcp", "443/tcp"]


def test_unknown_section_warns(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("version: 1\nfuture_section:\n  enabled: true\n", encoding="utf-8")
    config = load_config(path)
    assert any("unknown config section" in warning for warning in config.warnings)


@pytest.mark.parametrize(
    "body",
    [
        "version: 2\n",
        "version: 1\ngeneral:\n  timeout_seconds: 0\n",
        "version: 1\ngeneral:\n  log_level: loud\n",
        "version: 1\naudit:\n  engine: nessus\n",
        "version: 1\nharden:\n  require_confirmation: false\n",
        "version: 1\nharden:\n  backup_before_change: false\n",
        "version: 1\nfirewall:\n  allow_ports: ['22']\n",
        "version: 1\nssh:\n  port: 70000\n",
        "version: 1\nmonitoring:\n  thresholds:\n    cpu_percent: 120\n",
    ],
)
def test_invalid_config_raises_config_error(tmp_path: Path, body: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_invalid_yaml_raises_config_error(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("version: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_non_mapping_root_raises_config_error(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- 1\n- 2\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_defaults_are_valid() -> None:
    validate_config(copy.deepcopy(DEFAULTS))
