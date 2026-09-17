"""
Process monitor — enumerate and snapshot running processes.

Uses ``psutil`` to gather PID, name, exe path, parent, children, CPU,
memory, and network connections for each process.
"""

from __future__ import annotations

import psutil

from trojandetector.logger import log
from trojandetector.models import ConnectionInfo, ProcessInfo


def get_process_info(pid: int) -> ProcessInfo | None:
    """Return a :class:`ProcessInfo` snapshot for *pid*, or ``None`` if
    the process no longer exists / is inaccessible.
    """
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            info = ProcessInfo(
                pid=proc.pid,
                name=proc.name(),
                exe=_safe(proc.exe),
                cmdline=_safe(proc.cmdline) or [],
                ppid=proc.ppid(),
                parent_name=_safe_parent_name(proc),
                username=_safe(proc.username),
                cpu_percent=proc.cpu_percent(interval=0.1),
                memory_mb=round(proc.memory_info().rss / (1024 * 1024), 2),
                children_pids=[c.pid for c in proc.children(recursive=False)],
                connections=_get_connections(proc),
                create_time=proc.create_time(),
            )
        return info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
        log.debug("Cannot read PID %d: %s", pid, exc)
        return None


def list_all_processes() -> list[ProcessInfo]:
    """Snapshot every running process.

    Processes that are inaccessible (e.g. system-level) are silently
    skipped.
    """
    results: list[ProcessInfo] = []
    for pid in psutil.pids():
        info = get_process_info(pid)
        if info is not None:
            results.append(info)
    log.info("Enumerated %d processes", len(results))
    return results


def find_process_by_name(name: str) -> list[ProcessInfo]:
    """Return snapshots of all processes whose name matches *name*
    (case-insensitive).
    """
    matches: list[ProcessInfo] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() == name.lower():
                info = get_process_info(proc.info["pid"])
                if info:
                    matches.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matches


def get_children(pid: int, recursive: bool = True) -> list[ProcessInfo]:
    """Return snapshots of all child processes of *pid*."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=recursive)
        results: list[ProcessInfo] = []
        for child in children:
            info = get_process_info(child.pid)
            if info:
                results.append(info)
        return results
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


# ── helpers ──────────────────────────────────────────────────────────────


def _safe(fn, default=None):
    """Call *fn* and swallow AccessDenied / NoSuchProcess."""
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return default


def _safe_parent_name(proc: psutil.Process) -> str | None:
    try:
        parent = proc.parent()
        return parent.name() if parent else None
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _get_connections(proc: psutil.Process) -> list[ConnectionInfo]:
    """Extract network connections from a process."""
    try:
        conns = proc.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return []

    results: list[ConnectionInfo] = []
    for c in conns:
        results.append(
            ConnectionInfo(
                local_addr=c.laddr.ip if c.laddr else "",
                local_port=c.laddr.port if c.laddr else 0,
                remote_addr=c.raddr.ip if c.raddr else None,
                remote_port=c.raddr.port if c.raddr else None,
                status=c.status,
                protocol="tcp" if c.type == 1 else "udp",
            )
        )
    return results
