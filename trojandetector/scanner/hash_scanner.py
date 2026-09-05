"""
Cryptographic file hashing.

Computes SHA-256, SHA-1, and MD5 digests for a given file.  SHA-256 is the
primary identifier used throughout the project (file names can be spoofed).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from trojandetector.logger import log
from trojandetector.models import HashResult


_BUFFER_SIZE = 64 * 1024  # 64 KiB read chunks


def hash_file(file_path: str | Path) -> HashResult:
    """Compute SHA-256, SHA-1, and MD5 for *file_path*.

    Raises
    ------
    FileNotFoundError
        If the path does not exist.
    IsADirectoryError
        If the path points to a directory.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if path.is_dir():
        raise IsADirectoryError(f"Path is a directory, not a file: {path}")

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    file_size = path.stat().st_size

    with path.open("rb") as fh:
        while chunk := fh.read(_BUFFER_SIZE):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    result = HashResult(
        sha256=sha256.hexdigest(),
        sha1=sha1.hexdigest(),
        md5=md5.hexdigest(),
        file_path=str(path.resolve()),
        file_size=file_size,
    )

    log.info(
        "Hashed [bold]%s[/bold]  SHA-256=%s",
        path.name,
        result.sha256[:16] + "…",
    )
    return result
