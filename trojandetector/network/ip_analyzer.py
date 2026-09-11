"""
IP address and subnet analyser.

Determines whether a given IP is private, loopback, or falls inside the
configured expected subnets.  Uses Python's built-in ``ipaddress`` module.
"""

from __future__ import annotations

import ipaddress

from trojandetector.config import settings
from trojandetector.logger import log
from trojandetector.models import IPAnalysisResult
from trojandetector.network.dns_monitor import reverse_lookup


def analyze_ip(ip: str) -> IPAnalysisResult:
    """Analyse *ip* against expected subnets and classify it.

    Returns an :class:`IPAnalysisResult` with ``is_in_expected_subnet``
    set to ``True`` when the address belongs to any configured expected
    network.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        log.warning("Invalid IP address: %s", ip)
        return IPAnalysisResult(ip=ip)

    result = IPAnalysisResult(
        ip=ip,
        is_private=addr.is_private,
        is_loopback=addr.is_loopback,
    )

    # Check against expected subnets
    for subnet_str in settings.expected_subnets:
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            if addr in network:
                result.is_in_expected_subnet = True
                result.matched_subnet = subnet_str
                break
        except ValueError:
            log.warning("Invalid subnet in config: %s", subnet_str)

    # Reverse DNS (best-effort)
    if not result.is_loopback:
        result.reverse_dns = reverse_lookup(ip)

    log.info(
        "IP analysis [bold]%s[/bold]: private=%s, expected_subnet=%s",
        ip,
        result.is_private,
        result.is_in_expected_subnet,
    )
    return result
