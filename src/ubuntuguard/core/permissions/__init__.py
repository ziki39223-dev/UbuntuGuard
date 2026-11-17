"""Platform and privilege checks."""

from .checks import (
    EnvironmentStatus,
    check_environment,
    is_root,
    missing_dependencies,
    read_os_release,
    require_root,
    require_supported_platform,
)

__all__ = [
    "EnvironmentStatus",
    "check_environment",
    "is_root",
    "missing_dependencies",
    "read_os_release",
    "require_root",
    "require_supported_platform",
]
