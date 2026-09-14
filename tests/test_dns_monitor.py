"""Tests for the DNS monitor module."""

import pytest

from trojandetector.network.dns_monitor import resolve_domain, clear_cache


class TestDNSMonitor:
    """DNS monitor tests."""

    def test_resolve_known_domain(self) -> None:
        """Resolving a well-known domain should return at least one IP."""
        clear_cache()
        record = resolve_domain("dns.google")
        # dns.google resolves to 8.8.8.8 and 8.8.4.4
        assert len(record.resolved_ips) > 0
        assert record.domain == "dns.google"

    def test_resolve_nonexistent_domain(self) -> None:
        """A non-existent domain should return an empty IP list, not crash."""
        clear_cache()
        record = resolve_domain("this.domain.does.not.exist.example.invalid")
        assert record.resolved_ips == []

    def test_cache_hit(self) -> None:
        """Subsequent lookups for the same domain should hit the cache."""
        clear_cache()
        r1 = resolve_domain("dns.google")
        r2 = resolve_domain("dns.google")
        # Same object from cache
        assert r1 is r2
