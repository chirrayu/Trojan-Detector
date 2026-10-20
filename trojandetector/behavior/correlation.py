"""Correlate DNS answers, process-owned connections, and filesystem events."""

from __future__ import annotations

from trojandetector.models import ProcessInfo


def correlate_network_to_process(connections: list[dict]) -> dict[int, list[dict]]:
    """Group system connection records by owning PID, skipping unknown PIDs."""
    grouped: dict[int, list[dict]] = {}
    for connection in connections:
        pid = connection.get("pid")
        if isinstance(pid, int):
            grouped.setdefault(pid, []).append(connection)
    return grouped


def correlate_dns_to_connections(connections: list[dict], records) -> list[dict]:
    """Annotate connections whose remote IP appeared in a DNS answer."""
    ip_domains: dict[str, list[str]] = {}
    for record in records:
        for ip in record.resolved_ips:
            ip_domains.setdefault(ip, []).append(record.domain)
    result = []
    for connection in connections:
        remote = connection.get("remote_addr")
        result.append({
            **connection,
            "domains": sorted(set(ip_domains.get(remote, []))),
            "dns_correlated": bool(remote and remote in ip_domains),
        })
    return result


def correlate_file_event_to_process(event: dict, processes: dict[int, ProcessInfo]) -> dict:
    """Attach process identity to a watchdog event when its PID is known."""
    pid = event.get("pid")
    process = processes.get(pid) if isinstance(pid, int) else None
    return {
        **event,
        "process_name": process.name if process else None,
        "process_exe": process.exe if process else None,
    }
