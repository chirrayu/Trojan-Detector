"""Build process ancestry snapshots and process trees."""

from __future__ import annotations

import psutil

from trojandetector.logger import log
from trojandetector.models import ProcessInfo
from trojandetector.process.process_monitor import get_process_info


def build_process_tree(root_pid: int) -> dict:
    """Return a nested process tree rooted at ``root_pid``.

    Each node contains the process snapshot fields and a ``children`` list.
    Returns an empty dict when the root is unavailable.
    """
    root = get_process_info(root_pid)
    if root is None:
        return {}

    def node(info: ProcessInfo, ancestors: frozenset[int]) -> dict:
        children = []
        for child_pid in info.children_pids:
            if child_pid in ancestors:
                continue
            child = get_process_info(child_pid)
            if child is not None:
                children.append(node(child, ancestors | {child_pid}))
        return {**info.model_dump(mode="json"), "children": children}

    return node(root, frozenset({root_pid}))


def build_process_snapshot() -> dict[int, ProcessInfo]:
    """Capture one process table and enrich each process with direct children."""
    snapshots: dict[int, ProcessInfo] = {}
    for proc in psutil.process_iter(["pid", "ppid", "name"]):
        try:
            info = get_process_info(proc.info["pid"])
            if info is not None:
                snapshots[info.pid] = info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    children: dict[int, list[int]] = {}
    for info in snapshots.values():
        if info.ppid in snapshots:
            children.setdefault(info.ppid, []).append(info.pid)
    for pid, info in snapshots.items():
        info.children_pids = sorted(children.get(pid, []))
    log.info("Captured process tree snapshot with %d processes", len(snapshots))
    return snapshots
