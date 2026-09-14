"""
Packet monitor — placeholder for Scapy-based packet capture.

Full packet sniffing requires elevated privileges and is best used in
controlled environments.  This module provides a lightweight wrapper
that will be expanded in later phases.
"""

from __future__ import annotations

from trojandetector.logger import log


def start_packet_capture(interface: str | None = None, count: int = 100) -> list[dict]:
    """Capture *count* packets on *interface* using Scapy.

    Returns a simplified list of dicts with packet metadata.

    .. note::
        Requires elevated privileges.  On Windows, also requires Npcap.
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS  # type: ignore[import-untyped]
    except ImportError:
        log.warning("Scapy not available — packet capture disabled")
        return []

    log.info("Starting packet capture (count=%d, iface=%s)", count, interface or "default")

    packets: list[dict] = []

    try:
        captured = sniff(iface=interface, count=count, timeout=30, store=True)
    except PermissionError:
        log.error("Packet capture requires elevated privileges")
        return []
    except Exception as exc:
        log.error("Packet capture failed: %s", exc)
        return []

    for pkt in captured:
        entry: dict = {"summary": pkt.summary()}
        if pkt.haslayer(IP):
            entry["src_ip"] = pkt[IP].src
            entry["dst_ip"] = pkt[IP].dst
            entry["protocol"] = pkt[IP].proto
        if pkt.haslayer(TCP):
            entry["src_port"] = pkt[TCP].sport
            entry["dst_port"] = pkt[TCP].dport
            entry["tcp_flags"] = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            entry["src_port"] = pkt[UDP].sport
            entry["dst_port"] = pkt[UDP].dport
        if pkt.haslayer(DNS):
            entry["dns"] = True
        packets.append(entry)

    log.info("Captured %d packets", len(packets))
    return packets
