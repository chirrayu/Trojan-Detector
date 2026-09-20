"""Tests for the risk engine module."""

import pytest

from trojandetector.models import (
    FileScanResult,
    FileType,
    IPAnalysisResult,
    PEAnalysisResult,
    PESection,
    ProcessInfo,
    RiskLevel,
)
from trojandetector.risk.risk_engine import (
    merge_reports,
    score_file_scan,
    score_ip,
    score_process,
)


class TestScoreFileScan:
    """Tests for score_file_scan()."""

    def test_clean_file(self) -> None:
        """A file with no PE or suspicious signals should score LOW."""
        scan = FileScanResult(file_path="test.txt", file_type=FileType.UNKNOWN)
        report = score_file_scan(scan)
        assert report.total_score == 0
        assert report.level == RiskLevel.LOW

    def test_suspicious_imports(self) -> None:
        """Files with suspicious PE imports should increase score."""
        pe = PEAnalysisResult(
            file_path="test.exe",
            is_valid_pe=True,
            is_exe=True,
            suspicious_imports=["kernel32.dll:VirtualAllocEx", "kernel32.dll:WriteProcessMemory"],
        )
        scan = FileScanResult(file_path="test.exe", file_type=FileType.PE_EXE, pe_analysis=pe)
        report = score_file_scan(scan)
        assert report.total_score > 0
        assert "suspicious_pe_imports" in report.signals

    def test_high_entropy(self) -> None:
        """High-entropy sections should contribute to the score."""
        pe = PEAnalysisResult(
            file_path="packed.exe",
            is_valid_pe=True,
            is_exe=True,
            sections=[
                PESection(
                    name=".text",
                    virtual_size=1000,
                    raw_size=1000,
                    entropy=7.9,
                    characteristics=0,
                ),
            ],
        )
        scan = FileScanResult(file_path="packed.exe", file_type=FileType.PE_EXE, pe_analysis=pe)
        report = score_file_scan(scan)
        assert "high_entropy_sections" in report.signals


class TestScoreIP:
    """Tests for score_ip()."""

    def test_private_ip_no_risk(self) -> None:
        """A private IP inside expected subnets should score 0."""
        analysis = IPAnalysisResult(
            ip="192.168.1.1", is_private=True, is_in_expected_subnet=True
        )
        report = score_ip(analysis)
        assert report.total_score == 0

    def test_external_ip_risk(self) -> None:
        """An unexpected external IP should add risk points."""
        analysis = IPAnalysisResult(
            ip="185.0.0.1", is_private=False, is_in_expected_subnet=False
        )
        report = score_ip(analysis)
        assert report.total_score > 0
        assert "unexpected_external_ip" in report.signals


class TestMergeReports:
    """Tests for merge_reports()."""

    def test_merge_combines_scores(self) -> None:
        """Merging two reports should sum their signals."""
        r1 = score_ip(
            IPAnalysisResult(ip="185.0.0.1", is_private=False, is_in_expected_subnet=False)
        )
        r2 = score_ip(
            IPAnalysisResult(ip="203.0.113.5", is_private=False, is_in_expected_subnet=False)
        )
        merged = merge_reports(r1, r2)
        # Since both have the same signal key it won't double — but reasons do accumulate
        assert merged.total_score >= r1.total_score

    def test_merge_empty(self) -> None:
        """Merging zero reports should return a clean report."""
        merged = merge_reports()
        assert merged.total_score == 0
        assert merged.level == RiskLevel.LOW
