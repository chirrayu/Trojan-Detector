"""
High-level file scanner.

Orchestrates hashing + PE analysis into a single :class:`FileScanResult`.
"""

from __future__ import annotations

from pathlib import Path

from trojandetector.logger import log
from trojandetector.models import FileScanResult, FileType
from trojandetector.scanner.hash_scanner import hash_file
from trojandetector.scanner.pe_analyzer import analyze_pe


# Extensions that hint at a PE executable/DLL
_PE_EXTENSIONS: set[str] = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv"}
_SCRIPT_EXTENSIONS: set[str] = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta"}
_DOC_EXTENSIONS: set[str] = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf"}
_ARCHIVE_EXTENSIONS: set[str] = {".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso"}


def _classify(path: Path) -> FileType:
    """Determine a high-level file type from the extension."""
    ext = path.suffix.lower()
    if ext in _PE_EXTENSIONS:
        return FileType.PE_EXE  # will refine to PE_DLL after PE analysis
    if ext in _SCRIPT_EXTENSIONS:
        return FileType.SCRIPT
    if ext in _DOC_EXTENSIONS:
        return FileType.DOCUMENT
    if ext in _ARCHIVE_EXTENSIONS:
        return FileType.ARCHIVE
    return FileType.UNKNOWN


def scan_file(file_path: str | Path) -> FileScanResult:
    """Scan a file: hash it and, if it looks like a PE, run static analysis.

    Returns a :class:`FileScanResult` with all gathered information.  Risk
    scoring is *not* performed here — call the risk engine separately.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    log.info("Scanning [bold cyan]%s[/bold cyan]", path.name)

    file_type = _classify(path)
    hashes = hash_file(path)

    pe_result = None
    if file_type in (FileType.PE_EXE, FileType.PE_DLL) or path.suffix.lower() in _PE_EXTENSIONS:
        pe_result = analyze_pe(path)
        if pe_result.is_valid_pe and pe_result.is_dll:
            file_type = FileType.PE_DLL

    result = FileScanResult(
        file_path=str(path),
        file_type=file_type,
        hashes=hashes,
        pe_analysis=pe_result,
    )

    log.info(
        "Scan complete for [bold]%s[/bold] — type=%s, SHA-256=%s",
        path.name,
        file_type.value,
        hashes.sha256[:16] + "…",
    )
    return result
