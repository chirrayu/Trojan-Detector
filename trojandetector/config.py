"""
Application configuration using Pydantic Settings.

Configuration is loaded from environment variables and .env files.
Sensitive values (like MongoDB URI) should be set as env vars rather than
hard-coded.
"""

from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Global application settings."""

    # ── Monitoring toggles ───────────────────────────────────────────
    monitor_network: bool = Field(default=True, description="Enable network monitoring")
    monitor_processes: bool = Field(default=True, description="Enable process monitoring")
    monitor_files: bool = Field(default=True, description="Enable file-system monitoring")

    # ── Risk engine ──────────────────────────────────────────────────
    risk_threshold: int = Field(
        default=75,
        ge=0,
        le=100,
        description="Risk score (0-100) above which a file is flagged suspicious",
    )

    # ── MongoDB (optional for Phase 1) ───────────────────────────────
    mongodb_enabled: bool = Field(default=False, description="Enable MongoDB intelligence layer")
    mongodb_uri: str = Field(
        default="mongodb://localhost:27017",
        description="MongoDB connection string",
    )
    mongodb_database: str = Field(default="trojan_detector", description="MongoDB database name")

    # ── Logging ──────────────────────────────────────────────────────
    log_level: str = Field(default="INFO", description="Logging level")
    log_dir: Path = Field(default=Path("logs"), description="Directory for log files")

    # ── Quarantine ───────────────────────────────────────────────────
    quarantine_dir: Path = Field(
        default=Path("quarantine"),
        description="Directory where quarantined files are stored",
    )

    # ── Network ──────────────────────────────────────────────────────
    expected_subnets: list[str] = Field(
        default_factory=lambda: [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
        ],
        description="Subnets considered 'expected' (RFC-1918 + loopback by default)",
    )

    model_config = {
        "env_prefix": "",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


# Singleton – import this wherever config is needed
settings = Settings()
