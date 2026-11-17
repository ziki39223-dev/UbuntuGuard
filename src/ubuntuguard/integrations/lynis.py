"""Lynis adapter: subprocess execution plus report parsing.

Only the report file is parsed. No Lynis code is copied or imported, which keeps
the GPL boundary intact.
"""

from __future__ import annotations

import contextlib
import hashlib
import shutil
from pathlib import Path

from ..core.executor import CommandExecutor
from ..errors import UbuntuGuardError
from ..models import Finding, Severity

DEFAULT_REPORT_PATH = Path("/var/log/lynis-report.dat")


class LynisEngine:
    name = "lynis"

    def __init__(
        self,
        executor: CommandExecutor,
        report_path: Path = DEFAULT_REPORT_PATH,
    ) -> None:
        self._executor = executor
        self._report_path = report_path

    def available(self) -> bool:
        return shutil.which("lynis") is not None

    def collect_findings(self) -> list[Finding]:
        if self.available():
            with contextlib.suppress(UbuntuGuardError):
                self._executor.run(
                    [
                        "lynis",
                        "audit",
                        "system",
                        "--quick",
                        "--quiet",
                        "--report-file",
                        str(self._report_path),
                    ],
                    timeout=300.0,
                )
        try:
            text = self._report_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return parse_lynis_report(text)


def parse_lynis_report(text: str) -> list[Finding]:
    findings: list[Finding] = []
    prefixes = (
        ("warning[]=", Severity.MEDIUM),
        ("suggestion[]=", Severity.LOW),
    )
    for line in text.splitlines():
        for prefix, severity in prefixes:
            if not line.startswith(prefix):
                continue
            detail = line[len(prefix) :].strip()
            if not detail:
                continue
            parts = [part.strip() for part in detail.split("|")]
            test_id = parts[0] if len(parts) > 1 else ""
            message = parts[1] if len(parts) > 1 and parts[1] else detail
            digest = hashlib.sha256(detail.encode("utf-8")).hexdigest()[:8]
            findings.append(
                Finding(
                    id=f"LYNIS-{digest}",
                    title=message,
                    severity=severity,
                    category="lynis",
                    evidence={"test": test_id, "text": detail},
                    remediation="Review the Lynis finding and apply the recommended hardening",
                    references=("Lynis",),
                )
            )
    return findings
