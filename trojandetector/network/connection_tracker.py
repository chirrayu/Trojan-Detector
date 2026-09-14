"""
Connection tracker — monitor active network connections system-wide.

Uses ``psutil`` to enumerate TCP/UDP connections and correlate them
with owning processes.
"""

from __future__ import annotations

import psutil

from trojandetector.logger import log
from trojandetector.models import ConnectionInfo


def get_all_connections(kind: str = "inet") -> list[dict]:
    """Return all system-wide network connections.

    Each entry is a dict with keys: ``pid``, ``local_addr``, ``local_port``,
    ``remote_addr``, ``remote_port``, ``status``, ``protocol``.

    Parameters
    ----------
    kind : str
        Connection kind filter passed to ``psutil.net_connections``.
        Defaults to ``"inet"`` (IPv4 + IPv6).
    """
    results: list[dict] = []
    try:
        connections = psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        log.warning("Insufficient permissions to list network connections (try running as admin)")
        return results

    for conn in connections:
        entry = {
            "pid": conn.pid,
            "local_addr": conn.laddr.ip if conn.laddr else "",
            "local_port": conn.laddr.port if conn.laddr else 0,
            "remote_addr": conn.raddr.ip if conn.raddr else None,
            "remote_port": conn.raddr.port if conn.raddr else None,
            "status": conn.status,
            "protocol": "tcp" if conn.type == 1 else "udp",
        }
        results.append(entry)

    log.info("Tracked %d active connections", len(results))
    return results


def get_connections_for_pid(pid: int) -> list[ConnectionInfo]:
    """Return network connections belonging to process *pid*."""
    try:
        proc = psutil.Process(pid)
        conns = proc.net_connections(kind="inet")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
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


def get_external_connections() -> list[dict]:
    """Return only connections with a non-private remote address.

    Useful for quickly spotting traffic leaving the local network.
    """
    import ipaddress

    all_conns = get_all_connections()
    external: list[dict] = []
    for conn in all_conns:
        remote = conn.get("remote_addr")
        if not remote:
            continue
        try:
            addr = ipaddress.ip_address(remote)
            if not addr.is_private and not addr.is_loopback:
                external.append(conn)
        except ValueError:
            continue

    log.info("Found %d external connections", len(external))
    return external
