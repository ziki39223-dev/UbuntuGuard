"""Process exit codes.

The values are part of the public CLI contract (see docs/TECHNICAL_DESIGN.md).
Never renumber or reuse an existing code.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    INTERNAL = 1
    USAGE = 2
    PERMISSION = 3
    AUDIT_FINDINGS = 4
    PARTIAL = 5
    ROLLED_BACK = 6
    ROLLBACK_FAILED = 7
    MISSING_DEPENDENCY = 8
    UNSUPPORTED = 9
