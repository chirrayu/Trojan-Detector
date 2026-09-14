"""
DNS monitor — resolve domains and capture DNS query results.

Uses ``dnspython`` for reliable DNS resolution and caches results so
repeated queries for the same domain are fast.
"""

from __future__ import annotations

from datetime import datetime, timezone

import dns.resolver
import dns.reversename
import dns.exception

from trojandetector.logger import log
from trojandetector.models import DNSRecord


# In-memory cache: domain → DNSRecord
_dns_cache: dict[str, DNSRecord] = {}


def resolve_domain(domain: str, query_type: str = "A") -> DNSRecord:
    """Resolve *domain* and return a :class:`DNSRecord`.

    Results are cached in-memory for the lifetime of the process.
    """
    cache_key = f"{domain}:{query_type}"
    if cache_key in _dns_cache:
        log.debug("DNS cache hit for %s (%s)", domain, query_type)
        return _dns_cache[cache_key]

    record = DNSRecord(
        domain=domain,
        query_type=query_type,
        timestamp=datetime.now(timezone.utc),
    )

    try:
        answers = dns.resolver.resolve(domain, query_type)
        record.resolved_ips = [rdata.to_text() for rdata in answers]
        log.info(
            "DNS resolved [bold]%s[/bold] (%s) → %s",
            domain,
            query_type,
            ", ".join(record.resolved_ips),
        )
    except dns.exception.DNSException as exc:
        log.warning("DNS resolution failed for %s: %s", domain, exc)

    _dns_cache[cache_key] = record
    return record


def reverse_lookup(ip: str) -> str | None:
    """Attempt a reverse DNS lookup for *ip*.

    Returns the PTR hostname or ``None`` on failure.
    """
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        hostname = str(answers[0]).rstrip(".")
        log.debug("Reverse DNS: %s → %s", ip, hostname)
        return hostname
    except dns.exception.DNSException:
        log.debug("Reverse DNS failed for %s", ip)
        return None


def clear_cache() -> None:
    """Clear the in-memory DNS cache."""
    _dns_cache.clear()
    log.debug("DNS cache cleared")
