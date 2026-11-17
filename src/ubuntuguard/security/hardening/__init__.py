"""Hardening orchestration package.

Engine exports are loaded lazily to avoid a circular import between the
hardening package initializer and the individual action modules.
"""

from __future__ import annotations

from typing import Any

from .base import HardeningAction

__all__ = [
    "ACTION_MAP",
    "ACTION_NAMES",
    "ACTIONS",
    "HardeningAction",
    "HardeningPlanSet",
    "HardeningResult",
    "apply_plans",
    "build_plans",
]

_ENGINE_EXPORTS = frozenset(
    {
        "ACTION_MAP",
        "ACTION_NAMES",
        "ACTIONS",
        "HardeningPlanSet",
        "HardeningResult",
        "apply_plans",
        "build_plans",
    }
)


def __getattr__(name: str) -> Any:
    if name in _ENGINE_EXPORTS:
        from . import engine

        return getattr(engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
