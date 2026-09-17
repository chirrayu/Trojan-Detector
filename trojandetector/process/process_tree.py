"""
Process tree builder — Phase 2 placeholder.

Full parent/child tree visualisation is planned for Phase 2.  The basic
child-process enumeration in ``process_monitor`` covers Phase 1 needs.
"""

from __future__ import annotations

from trojandetector.logger import log


def build_process_tree(root_pid: int) -> dict:
    """Build a nested dict representing the process tree rooted at *root_pid*.

    Not yet implemented — returns an empty dict.
    """
    log.debug("Process tree building not yet implemented (Phase 2)")
    return {}
