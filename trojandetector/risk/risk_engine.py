"""
Risk engine — combine multiple signals into a single risk score.

Each signal contributes a weighted point value.  The total is clamped to
0–100 and mapped to a :class:`RiskLevel`.

Weights are intentionally conservative for the MVP and will be tuned
during Phase 2 testing.
"""

from __future__ import annotations

from trojandetector.config import settings
from trojandetector.logger import log
from trojandetector.models import (
    FileScanResult,
    IPAnalysisResult,
    ProcessInfo,
    RiskLevel,
    RiskReport,
)


# ── Signal weights ───────────────────────────────────────────────────────

WEIGHTS: dict[str, int] = {
    "suspicious_pe_imports": 15,
    "high_entropy_section": 10,
    "many_suspicious_imports": 25,  # ≥ 5 suspicious imports
    "pe_warnings": 5,
    "unexpected_external_ip": 10,
    "suspicious_child_process": 20,
    "high_cpu_usage": 5,
    "high_memory_usage": 5,
    "multiple_connections": 10,
    "suspicious_parent": 15,
}

# Process names commonly abused in attack chains
SUSPICIOUS_PROCESS_NAMES: set[str] = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}


def _level_from_score(score: int) -> RiskLevel:
    """Map a numeric score to a risk level."""
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _recommendation(level: RiskLevel) -> str:
    """Return a human-readable recommendation based on risk level."""
    match level:
        case RiskLevel.CRITICAL:
            return "CRITICAL RISK — strongly recommend quarantine or termination."
        case RiskLevel.HIGH:
            return "HIGH RISK — manual investigation recommended before allowing execution."
        case RiskLevel.MEDIUM:
            return "MEDIUM RISK — some suspicious indicators found; proceed with caution."
        case RiskLevel.LOW:
            return "LOW RISK — no strong indicators of malicious behaviour detected."


# ── Public API ───────────────────────────────────────────────────────────


def score_file_scan(scan: FileScanResult) -> RiskReport:
    """Score a :class:`FileScanResult` and return a :class:`RiskReport`.

    This evaluates only static/file-level signals.  Process and network
    signals should be scored with :func:`score_process` /
    :func:`score_ip` and merged via :func:`merge_reports`.
    """
    report = RiskReport()

    pe = scan.pe_analysis
    if pe and pe.is_valid_pe:
        # Suspicious imports
        if pe.suspicious_imports:
            pts = WEIGHTS["suspicious_pe_imports"]
            report.signals["suspicious_pe_imports"] = pts
            report.reasons.append(
                f"Suspicious PE imports detected: {', '.join(pe.suspicious_imports[:5])}"
            )
            if len(pe.suspicious_imports) >= 5:
                bonus = WEIGHTS["many_suspicious_imports"]
                report.signals["many_suspicious_imports"] = bonus
                report.reasons.append(
                    f"{len(pe.suspicious_imports)} suspicious imports — possible "
                    "process injection or evasion toolkit"
                )

        # High entropy sections
        high_ent = [s for s in pe.sections if s.entropy > 7.2]
        if high_ent:
            pts = WEIGHTS["high_entropy_section"] * len(high_ent)
            report.signals["high_entropy_sections"] = pts
            report.reasons.append(
                f"High-entropy sections ({', '.join(s.name for s in high_ent)}) — "
                "possible packing/encryption"
            )

        # PE structural warnings
        if pe.warnings:
            pts = WEIGHTS["pe_warnings"]
            report.signals["pe_warnings"] = pts
            report.reasons.append(f"PE structural warnings: {len(pe.warnings)}")

    report.total_score = min(sum(report.signals.values()), 100)
    report.level = _level_from_score(report.total_score)
    report.recommendation = _recommendation(report.level)
    return report


def score_process(proc: ProcessInfo) -> RiskReport:
    """Score a :class:`ProcessInfo` snapshot."""
    report = RiskReport()

    # Suspicious child processes
    if proc.children_pids:
        import psutil

        for cpid in proc.children_pids:
            try:
                child = psutil.Process(cpid)
                if child.name().lower() in SUSPICIOUS_PROCESS_NAMES:
                    pts = WEIGHTS["suspicious_child_process"]
                    report.signals["suspicious_child_process"] = pts
                    report.reasons.append(
                        f"Spawned suspicious child process: {child.name()} (PID {cpid})"
                    )
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # Resource usage anomalies
    if proc.cpu_percent > 80:
        report.signals["high_cpu_usage"] = WEIGHTS["high_cpu_usage"]
        report.reasons.append(f"High CPU usage: {proc.cpu_percent:.1f}%")

    if proc.memory_mb > 500:
        report.signals["high_memory_usage"] = WEIGHTS["high_memory_usage"]
        report.reasons.append(f"High memory usage: {proc.memory_mb:.1f} MB")

    # Multiple external connections
    external_conns = [c for c in proc.connections if c.remote_addr and c.remote_port]
    if len(external_conns) >= 3:
        report.signals["multiple_connections"] = WEIGHTS["multiple_connections"]
        report.reasons.append(f"Multiple active connections: {len(external_conns)}")

    # Suspicious parent
    if proc.parent_name and proc.parent_name.lower() in SUSPICIOUS_PROCESS_NAMES:
        report.signals["suspicious_parent"] = WEIGHTS["suspicious_parent"]
        report.reasons.append(f"Suspicious parent process: {proc.parent_name}")

    report.total_score = min(sum(report.signals.values()), 100)
    report.level = _level_from_score(report.total_score)
    report.recommendation = _recommendation(report.level)
    return report


def score_ip(analysis: IPAnalysisResult) -> RiskReport:
    """Score an :class:`IPAnalysisResult`."""
    report = RiskReport()

    if not analysis.is_in_expected_subnet and not analysis.is_private and not analysis.is_loopback:
        pts = WEIGHTS["unexpected_external_ip"]
        report.signals["unexpected_external_ip"] = pts
        report.reasons.append(
            f"Connection to unexpected external IP: {analysis.ip}"
        )

    report.total_score = min(sum(report.signals.values()), 100)
    report.level = _level_from_score(report.total_score)
    report.recommendation = _recommendation(report.level)
    return report


def merge_reports(*reports: RiskReport) -> RiskReport:
    """Merge multiple :class:`RiskReport` instances into one aggregate.

    Signals and reasons are combined; the total score is capped at 100.
    """
    merged = RiskReport()

    for r in reports:
        merged.signals.update(r.signals)
        merged.reasons.extend(r.reasons)

    merged.total_score = min(sum(merged.signals.values()), 100)
    merged.level = _level_from_score(merged.total_score)
    merged.recommendation = _recommendation(merged.level)

    log.info(
        "Risk assessment: score=%d, level=%s",
        merged.total_score,
        merged.level.value,
    )
    return merged
