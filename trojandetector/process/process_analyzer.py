"""Behavioral analysis of process ancestry, resources, files, and sockets."""

from __future__ import annotations

from trojandetector.models import ProcessInfo
from trojandetector.process.process_monitor import get_process_info
from trojandetector.process.process_tree import build_process_tree
from trojandetector.risk.risk_engine import SUSPICIOUS_PROCESS_NAMES


def analyze_process(pid: int) -> dict:
    """Return a process snapshot, ancestry tree, and explainable indicators."""
    info = get_process_info(pid)
    if info is None:
        return {}
    tree = build_process_tree(pid)
    indicators = []
    if info.parent_name and info.parent_name.casefold() in SUSPICIOUS_PROCESS_NAMES:
        indicators.append("suspicious_parent")
    if info.cpu_percent > 80:
        indicators.append("high_cpu_usage")
    if info.memory_mb > 500:
        indicators.append("high_memory_usage")
    if any(c.remote_addr for c in info.connections):
        indicators.append("has_network_connections")
    return {
        "process": info.model_dump(mode="json"),
        "tree": tree,
        "indicators": indicators,
    }
