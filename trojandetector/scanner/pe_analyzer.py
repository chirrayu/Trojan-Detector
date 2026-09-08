"""
Windows PE (Portable Executable) static analyser.

Inspects PE headers, sections, imports, entropy, and compile timestamps.
Flags suspicious imports commonly abused by malware.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path

from trojandetector.logger import log
from trojandetector.models import PEAnalysisResult, PEImport, PESection

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore[assignment]


# ── Suspicious API functions ─────────────────────────────────────────────

SUSPICIOUS_IMPORTS: set[str] = {
    # Process injection / manipulation
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "OpenProcess",
    # Code execution
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteExA",
    "ShellExecuteExW",
    "WinExec",
    "CreateProcessA",
    "CreateProcessW",
    # DLL injection
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    # Privilege escalation
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "LookupPrivilegeValueA",
    "LookupPrivilegeValueW",
    # Persistence / registry
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    # Anti-debugging
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    # Networking
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    # Crypto
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContextA",
    "CryptAcquireContextW",
}


def _section_entropy(data: bytes) -> float:
    """Shannon entropy of *data* (0.0–8.0 for byte-level)."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def analyze_pe(file_path: str | Path) -> PEAnalysisResult:
    """Perform static analysis on a PE file.

    Returns a populated :class:`PEAnalysisResult`.  If ``pefile`` is not
    installed the result will have ``is_valid_pe = False``.
    """
    path = Path(file_path)
    result = PEAnalysisResult(file_path=str(path.resolve()))

    if pefile is None:
        result.warnings.append("pefile library not installed — PE analysis skipped")
        log.warning("pefile not installed; cannot analyse %s", path.name)
        return result

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        result.warnings.append(f"Not a valid PE file: {exc}")
        log.debug("PE parse failed for %s: %s", path.name, exc)
        return result

    result.is_valid_pe = True
    result.is_dll = pe.is_dll()
    result.is_exe = pe.is_exe()
    result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    result.image_base = pe.OPTIONAL_HEADER.ImageBase

    # ── Compile timestamp ────────────────────────────────────────────
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        compile_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        result.compile_time = compile_dt.isoformat()
    except (OSError, ValueError, OverflowError):
        result.compile_time = None

    # ── Sections ─────────────────────────────────────────────────────
    overall_data = b""
    for section in pe.sections:
        sec_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        sec_data = section.get_data()
        overall_data += sec_data
        ent = _section_entropy(sec_data)
        result.sections.append(
            PESection(
                name=sec_name,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=round(ent, 4),
                characteristics=section.Characteristics,
            )
        )
        if ent > 7.2:
            result.warnings.append(
                f"High entropy in section '{sec_name}': {ent:.2f} (possible packing/encryption)"
            )

    result.overall_entropy = round(_section_entropy(overall_data), 4) if overall_data else 0.0

    # ── Imports ──────────────────────────────────────────────────────
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            for imp in entry.imports:
                func_name = (
                    imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                )
                result.imports.append(PEImport(dll=dll_name, function=func_name))
                if func_name in SUSPICIOUS_IMPORTS:
                    result.suspicious_imports.append(f"{dll_name}:{func_name}")

    # ── pefile built-in warnings ─────────────────────────────────────
    pe_warnings = pe.get_warnings()
    if pe_warnings:
        result.warnings.extend(pe_warnings)

    pe.close()

    log.info(
        "PE analysis for [bold]%s[/bold]: %d imports, %d suspicious, entropy=%.2f",
        path.name,
        len(result.imports),
        len(result.suspicious_imports),
        result.overall_entropy,
    )
    return result
