"""
Data models used throughout Trojan Detector.

All models are plain Pydantic v2 ``BaseModel`` instances, making them easy to
serialise to JSON / BSON and validate at the boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    """Risk classification buckets."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FileType(str, Enum):
    """High-level file type after initial identification."""

    PE_EXE = "PE_EXE"
    PE_DLL = "PE_DLL"
    SCRIPT = "SCRIPT"
    DOCUMENT = "DOCUMENT"
    ARCHIVE = "ARCHIVE"
    UNKNOWN = "UNKNOWN"


# ── Hash result ──────────────────────────────────────────────────────────


class HashResult(BaseModel):
    """Cryptographic hashes for a single file."""

    sha256: str
    md5: str
    sha1: str
    file_path: str
    file_size: int


# ── PE analysis ──────────────────────────────────────────────────────────


class PEImport(BaseModel):
    """A single imported function from a DLL."""

    dll: str
    function: str


class PESection(BaseModel):
    """Metadata about one PE section."""

    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int


class PEAnalysisResult(BaseModel):
    """Full result of static PE analysis."""

    file_path: str
    is_valid_pe: bool = False
    is_dll: bool = False
    is_exe: bool = False
    entry_point: int | None = None
    image_base: int | None = None
    sections: list[PESection] = Field(default_factory=list)
    imports: list[PEImport] = Field(default_factory=list)
    suspicious_imports: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    overall_entropy: float = 0.0
    compile_time: str | None = None


# ── Scan result ──────────────────────────────────────────────────────────


class FileScanResult(BaseModel):
    """Aggregate result of scanning a single file."""

    file_path: str
    file_type: FileType = FileType.UNKNOWN
    hashes: HashResult | None = None
    pe_analysis: PEAnalysisResult | None = None
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    risk_reasons: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Process snapshot ─────────────────────────────────────────────────────


class ProcessInfo(BaseModel):
    """Snapshot of a running process."""

    pid: int
    name: str
    exe: str | None = None
    cmdline: list[str] = Field(default_factory=list)
    ppid: int | None = None
    parent_name: str | None = None
    username: str | None = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    children_pids: list[int] = Field(default_factory=list)
    connections: list[ConnectionInfo] = Field(default_factory=list)
    create_time: float | None = None


# ── Network models ───────────────────────────────────────────────────────


class ConnectionInfo(BaseModel):
    """A single network connection belonging to a process."""

    local_addr: str
    local_port: int
    remote_addr: str | None = None
    remote_port: int | None = None
    status: str = ""
    protocol: str = "tcp"


class DNSRecord(BaseModel):
    """A captured DNS query/response pair."""

    domain: str
    resolved_ips: list[str] = Field(default_factory=list)
    query_type: str = "A"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IPAnalysisResult(BaseModel):
    """Result of analysing a single IP address."""

    ip: str
    is_private: bool = False
    is_loopback: bool = False
    is_in_expected_subnet: bool = False
    matched_subnet: str | None = None
    reverse_dns: str | None = None


# ── Risk report ──────────────────────────────────────────────────────────


class RiskReport(BaseModel):
    """Final risk assessment aggregated from all signals."""

    total_score: int = 0
    level: RiskLevel = RiskLevel.LOW
    reasons: list[str] = Field(default_factory=list)
    signals: dict[str, int] = Field(default_factory=dict)
    recommendation: str = ""


# Rebuild models that have forward references
ProcessInfo.model_rebuild()
