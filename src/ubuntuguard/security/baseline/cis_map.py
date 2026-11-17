"""CIS Ubuntu control references per baseline rule.

Numbers follow the public ComplianceAsCode control files:
- CIS Ubuntu 24.04 LTS benchmark v1.0.0 (controls/cis_ubuntu2404.yml)
- CIS Ubuntu 22.04 LTS benchmark v2.0.0 (controls/cis_ubuntu2204.yml)

Where a benchmark has no dedicated control, the closest section is used and
noted in docs/CIS_MAPPING.md.
"""

from __future__ import annotations

_MAP: dict[str, tuple[str, str]] = {
    # SSH server (5.1.x in both benchmark versions)
    "SSH-001": ("5.1.20", "5.1.20"),
    "SSH-002": ("5.1.4", "5.1.4"),
    "SSH-003": ("5.1.19", "5.1.19"),
    "SSH-004": ("5.1.8", "5.1.8"),
    "SSH-005": ("5.1.16", "5.1.16"),
    "SSH-006": ("5.1.11", "5.1.11"),
    "SSH-007": ("5.1.10", "5.1.10"),
    "SSH-008": ("5.1.21", "5.1.21"),
    "SSH-009": ("5.1", "5.1"),
    "SSH-010": ("5.1.13", "5.1.13"),
    "SSH-011": ("5.1.7", "5.1.7"),
    "SSH-012": ("5.1.4", "5.1.4"),
    "SSH-013": ("5.1.5", "5.1.5"),
    "SSH-014": ("5.1.6", "5.1.6"),
    "SSH-015": ("5.1.15", "5.1.15"),
    "SSH-016": ("5.1.12", "5.1.12"),
    # Accounts, sudo, password policy
    "ACC-001": ("5.4.2.1", "5.4.2.1"),
    "ACC-002": ("5.4.2.1", "5.4.2.1"),
    "ACC-003": ("5.4.2.7", "5.4.2.7"),
    "ACC-004": ("5.4.2.3", "5.4.2.3"),
    "ACC-005": ("5.3.3.4.1, 5.4.2.8", "5.3.3.4.1, 5.4.2.8"),
    "PERM-001": ("7.1.1", "7.1.1"),
    "PERM-002": ("7.1.3", "7.1.3"),
    "PERM-003": ("7.1.5", "7.1.5"),
    "SUDO-001": ("5.2.4", "5.2.4"),
    "SUDO-002": ("5.2", "5.2"),
    "LOGIN-001": ("5.4.1.1", "5.4.1.1"),
    "LOGIN-002": ("5.4.1.2", "5.4.1.2"),
    "LOGIN-003": ("5.4.1.3", "5.4.1.3"),
    "LOGIN-004": ("5.4.3.3", "5.4.3.3"),
    # Firewall (section numbering differs between benchmark versions)
    "FW-001": ("4.2.3", "4.1.3"),
    "FW-002": ("4.2.7", "4.1.7"),
    # Exposed services
    "PORT-001": (
        "2.1.6, 2.1.12, 2.1.14, 2.1.16",
        "2.1.6, 2.1.12, 2.1.14, 2.1.16",
    ),
    # Kernel parameters
    "SYS-001": ("1.5.1", "1.5.1"),
    "SYS-002": ("3.3.10", "3.3.10"),
    "SYS-003": ("3.3.7", "3.3.7"),
    "SYS-004": ("3.3.2, 3.3.5", "3.3.2, 3.3.5"),
    "SYS-005": ("3.3.4, 3.3.8, 3.3.9", "3.3.4, 3.3.8, 3.3.9"),
    "SYS-006": ("1.5", "1.5"),
    "SYS-007": ("1.5", "1.5"),
    # Detection rules
    "LOG-001": ("6.2", "6.3"),
    "LOG-002": ("5.1.20", "5.1.20"),
    "LOG-003": ("5.1.4", "5.1.4"),
    "PROC-001": ("6.2", "6.3"),
    "AUD-001": ("6.2.1.1", "6.3.1.1"),
    "AUD-002": ("6.2.1.2", "6.3.1.2"),
    "AUD-003": ("6.2.3.1", "6.3.3.1"),
    "AID-001": ("6.3.1", "6.1.1"),
    "AID-002": ("6.3.2", "6.1.2"),
    "FILE-001": ("6.3.2", "6.1.2"),
    "FILE-002": ("6.3.2", "6.1.2"),
}


def references_for(rule_id: str) -> tuple[str, ...]:
    entry = _MAP.get(rule_id)
    if entry is None:
        return ()
    modern, legacy = entry
    if modern and modern == legacy:
        return (f"CIS Ubuntu 24.04/22.04 §{modern}",)
    parts: list[str] = []
    if modern:
        parts.append(f"CIS Ubuntu 24.04 §{modern}")
    if legacy:
        parts.append(f"CIS Ubuntu 22.04 §{legacy}")
    return tuple(parts)
