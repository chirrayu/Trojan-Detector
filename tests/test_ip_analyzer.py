"""Tests for the IP analyser module."""

import pytest

from trojandetector.network.ip_analyzer import analyze_ip


class TestAnalyzeIP:
    """analyze_ip() tests."""

    def test_private_ip(self) -> None:
        """RFC-1918 addresses should be flagged as private and expected."""
        result = analyze_ip("192.168.1.100")
        assert result.is_private is True
        assert result.is_in_expected_subnet is True

    def test_loopback(self) -> None:
        """127.0.0.1 should be loopback and expected."""
        result = analyze_ip("127.0.0.1")
        assert result.is_loopback is True
        assert result.is_in_expected_subnet is True

    def test_external_ip(self) -> None:
        """A public IP should NOT be in expected subnets."""
        result = analyze_ip("8.8.8.8")
        assert result.is_private is False
        assert result.is_loopback is False
        assert result.is_in_expected_subnet is False

    def test_ten_network(self) -> None:
        """10.x.x.x should be private and expected."""
        result = analyze_ip("10.0.5.42")
        assert result.is_private is True
        assert result.is_in_expected_subnet is True
        assert result.matched_subnet == "10.0.0.0/8"

    def test_invalid_ip(self) -> None:
        """Invalid IP strings should return a bare result without crashing."""
        result = analyze_ip("not-an-ip")
        assert result.ip == "not-an-ip"
        assert result.is_private is False
