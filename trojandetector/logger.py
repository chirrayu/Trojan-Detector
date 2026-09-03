"""
Structured logging for Trojan Detector.

Uses Rich for colourful console output and a standard file handler for
persistent log storage.
"""

import logging
import sys
from pathlib import Path

from rich.logging import RichHandler

from trojandetector.config import settings


def setup_logger(name: str = "trojandetector") -> logging.Logger:
    """Create and configure the application logger.

    Returns a logger that writes to both the console (via Rich) and a
    rotating log file under the configured ``log_dir``.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # already configured

    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logger.setLevel(level)

    # ── Console handler (Rich) ───────────────────────────────────────
    console = RichHandler(
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    console.setLevel(level)
    console.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    logger.addHandler(console)

    # ── File handler ─────────────────────────────────────────────────
    log_dir = Path(settings.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "trojandetector.log"

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)  # always capture DEBUG to file
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(file_handler)

    return logger


# Module-level convenience logger
log = setup_logger()
