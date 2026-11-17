"""External engine adapters (Lynis, node_exporter, ...).

Adapters only parse external data. They must never carry audit decisions.
GPL projects are integrated through subprocess + report files only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Finding


@runtime_checkable
class AuditEngine(Protocol):
    name: str

    def available(self) -> bool:
        """Whether the external engine can be used on this host."""

    def collect_findings(self) -> list[Finding]:
        """Return findings parsed from the external engine."""


class NullEngine:
    """Placeholder engine used until a real adapter is wired in Phase 3."""

    name = "null"

    def available(self) -> bool:
        return False

    def collect_findings(self) -> list[Finding]:
        return []
