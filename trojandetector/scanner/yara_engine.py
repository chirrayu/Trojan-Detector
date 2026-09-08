"""
YARA rule engine — placeholder for Phase 2.

Phase 1 does not include YARA integration; this module exists so imports
don't break and the project structure stays consistent with the README.
"""

from __future__ import annotations

from trojandetector.logger import log


def scan_with_yara(file_path: str) -> list[str]:
    """Scan *file_path* against loaded YARA rules.

    Returns a list of matched rule names.  Currently returns an empty list
    because YARA integration is planned for Phase 2.
    """
    log.debug("YARA scanning not yet implemented (Phase 2) — skipping %s", file_path)
    return []
