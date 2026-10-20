"""
Trojan Detector CLI — Typer-based command-line interface.

Commands
--------
scan       Scan a file (hash + PE analysis + risk score).
hash       Compute SHA-256 / SHA-1 / MD5 for a file.
monitor    Enumerate running processes and flag suspicious ones.
investigate  Investigate an IP address or domain.
connections  List active network connections, highlighting external ones.

Run ``trojan-detector --help`` to see all commands.
"""

from __future__ import annotations

from pathlib import Path

import typer
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from trojandetector import __version__
from trojandetector.logger import log

# ── Typer app ────────────────────────────────────────────────────────────

app = typer.Typer(
    name="trojan-detector",
    help="🔍 Behavioral Trojan detection & investigation tool.",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
intel_app = typer.Typer(help="Query and submit confirmed threat intelligence.")
app.add_typer(intel_app, name="intel")


# ── Helpers ──────────────────────────────────────────────────────────────


def _risk_colour(level: str) -> str:
    """Map a risk level string to a Rich colour."""
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }.get(level, "white")


def _print_risk_report(report) -> None:
    """Pretty-print a :class:`RiskReport` to the console."""
    colour = _risk_colour(report.level.value)

    console.print()
    console.print(
        Panel(
            f"[{colour}]Risk Score: {report.total_score}/100  —  {report.level.value}[/{colour}]",
            title="⚠️  Risk Assessment",
            border_style=colour,
            box=box.HEAVY,
        )
    )

    if report.reasons:
        table = Table(title="Signals", box=box.SIMPLE_HEAVY, show_lines=True)
        table.add_column("Signal", style="cyan")
        table.add_column("Points", justify="right", style="magenta")
        for signal, points in report.signals.items():
            table.add_row(signal, str(points))
        console.print(table)

        console.print("\n[bold]Reasons:[/bold]")
        for reason in report.reasons:
            console.print(f"  • {reason}")

    console.print(f"\n[dim]{report.recommendation}[/dim]\n")


# ═══════════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════════


@app.command()
def scan(
    file: Path = typer.Argument(..., help="Path to the file to scan.", exists=True),
) -> None:
    """Scan a file — hash, PE analysis, and risk assessment."""
    from trojandetector.scanner.file_scanner import scan_file
    from trojandetector.risk.risk_engine import (
        merge_reports,
        score_file_scan,
        score_hash_intelligence,
    )
    from trojandetector.config import settings

    console.print(f"\n🔍 Scanning [bold cyan]{file.name}[/bold cyan]…\n")

    result = scan_file(file)

    # ── Hashes ───────────────────────────────────────────────────────
    if result.hashes:
        hash_table = Table(title="File Hashes", box=box.ROUNDED)
        hash_table.add_column("Algorithm", style="cyan")
        hash_table.add_column("Digest", style="green")
        hash_table.add_row("SHA-256", result.hashes.sha256)
        hash_table.add_row("SHA-1", result.hashes.sha1)
        hash_table.add_row("MD5", result.hashes.md5)
        hash_table.add_row("Size", f"{result.hashes.file_size:,} bytes")
        console.print(hash_table)

    # ── PE details ───────────────────────────────────────────────────
    pe = result.pe_analysis
    if pe and pe.is_valid_pe:
        pe_table = Table(title="PE Analysis", box=box.ROUNDED)
        pe_table.add_column("Property", style="cyan")
        pe_table.add_column("Value", style="white")
        pe_table.add_row("Type", "DLL" if pe.is_dll else "EXE")
        pe_table.add_row("Entry Point", hex(pe.entry_point) if pe.entry_point else "N/A")
        pe_table.add_row("Image Base", hex(pe.image_base) if pe.image_base else "N/A")
        pe_table.add_row("Compile Time", pe.compile_time or "N/A")
        pe_table.add_row("Sections", str(len(pe.sections)))
        pe_table.add_row("Total Imports", str(len(pe.imports)))
        pe_table.add_row("Suspicious Imports", str(len(pe.suspicious_imports)))
        pe_table.add_row("Overall Entropy", f"{pe.overall_entropy:.4f}")
        console.print(pe_table)

        if pe.sections:
            sec_table = Table(title="Sections", box=box.SIMPLE)
            sec_table.add_column("Name")
            sec_table.add_column("VSize", justify="right")
            sec_table.add_column("RawSize", justify="right")
            sec_table.add_column("Entropy", justify="right")
            for s in pe.sections:
                ent_style = "red" if s.entropy > 7.2 else "green"
                sec_table.add_row(
                    s.name,
                    f"{s.virtual_size:,}",
                    f"{s.raw_size:,}",
                    f"[{ent_style}]{s.entropy:.4f}[/{ent_style}]",
                )
            console.print(sec_table)

        if pe.suspicious_imports:
            console.print("\n[bold red]Suspicious Imports:[/bold red]")
            for imp in pe.suspicious_imports:
                console.print(f"  ⚠️  {imp}")

        if pe.warnings:
            console.print("\n[yellow]PE Warnings:[/yellow]")
            for w in pe.warnings:
                console.print(f"  ⚡ {w}")

    # ── Risk ─────────────────────────────────────────────────────────
    report = score_file_scan(result)
    if settings.mongodb_enabled and result.hashes:
        try:
            from trojandetector.intelligence.hash_intelligence import lookup_hash

            intelligence = lookup_hash(result.hashes.sha256)
            report = merge_reports(report, score_hash_intelligence(intelligence))
            if intelligence:
                console.print("[yellow]This hash has a prior intelligence report.[/yellow]")
        except Exception as exc:
            log.warning("Hash intelligence lookup unavailable: %s", exc)
            console.print("[dim]Hash intelligence lookup is currently unavailable.[/dim]")
    _print_risk_report(report)


@app.command()
def hash(
    file: Path = typer.Argument(..., help="Path to the file to hash.", exists=True),
) -> None:
    """Compute SHA-256, SHA-1, and MD5 hashes for a file."""
    from trojandetector.scanner.hash_scanner import hash_file

    result = hash_file(file)

    table = Table(title=f"Hashes — {file.name}", box=box.ROUNDED)
    table.add_column("Algorithm", style="cyan")
    table.add_column("Digest", style="green")
    table.add_row("SHA-256", result.sha256)
    table.add_row("SHA-1", result.sha1)
    table.add_row("MD5", result.md5)
    table.add_row("Size", f"{result.file_size:,} bytes")
    console.print(table)


@app.command()
def monitor(
    top: int = typer.Option(20, "--top", "-n", help="Number of processes to display."),
) -> None:
    """Enumerate running processes and flag suspicious activity."""
    from trojandetector.process.process_monitor import list_all_processes
    from trojandetector.risk.risk_engine import score_process, SUSPICIOUS_PROCESS_NAMES

    console.print("\n🔎 Monitoring running processes…\n")
    processes = list_all_processes()

    # Sort by CPU descending
    processes.sort(key=lambda p: p.cpu_percent, reverse=True)

    table = Table(title=f"Top {top} Processes (by CPU)", box=box.ROUNDED, show_lines=False)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Parent", style="dim")
    table.add_column("CPU%", justify="right")
    table.add_column("Mem MB", justify="right")
    table.add_column("Conns", justify="right")
    table.add_column("Risk", justify="center")

    for proc in processes[:top]:
        report = score_process(proc)
        risk_str = f"[{_risk_colour(report.level.value)}]{report.level.value}[/{_risk_colour(report.level.value)}]"

        table.add_row(
            str(proc.pid),
            proc.name,
            proc.parent_name or "—",
            f"{proc.cpu_percent:.1f}",
            f"{proc.memory_mb:.1f}",
            str(len(proc.connections)),
            risk_str,
        )

    console.print(table)

    # Alert on suspicious processes
    suspicious = [
        p for p in processes if p.name.lower() in SUSPICIOUS_PROCESS_NAMES
    ]
    if suspicious:
        console.print(
            f"\n[yellow]⚠️  {len(suspicious)} process(es) with names commonly "
            "abused in attack chains:[/yellow]"
        )
        for p in suspicious:
            console.print(f"  • PID {p.pid}: {p.name} (parent: {p.parent_name or '?'})")
    console.print()


@app.command()
def investigate(
    target: str = typer.Argument(..., help="IP address or domain name to investigate."),
) -> None:
    """Investigate an IP address or domain."""
    import ipaddress as _ipaddress

    is_ip = False
    try:
        _ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        from trojandetector.network.ip_analyzer import analyze_ip
        from trojandetector.risk.risk_engine import score_ip

        console.print(f"\n🌐 Investigating IP [bold]{target}[/bold]…\n")
        analysis = analyze_ip(target)

        table = Table(title=f"IP Analysis — {target}", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Private", "✅" if analysis.is_private else "❌")
        table.add_row("Loopback", "✅" if analysis.is_loopback else "❌")
        table.add_row("In Expected Subnet", "✅" if analysis.is_in_expected_subnet else "❌")
        table.add_row("Matched Subnet", analysis.matched_subnet or "—")
        table.add_row("Reverse DNS", analysis.reverse_dns or "—")
        console.print(table)

        report = score_ip(analysis)
        _print_risk_report(report)
    else:
        from trojandetector.network.dns_monitor import resolve_domain

        console.print(f"\n🌐 Resolving domain [bold]{target}[/bold]…\n")
        record = resolve_domain(target)

        table = Table(title=f"DNS — {target}", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Domain", record.domain)
        table.add_row("Query Type", record.query_type)
        table.add_row("Resolved IPs", ", ".join(record.resolved_ips) or "—")
        table.add_row("Timestamp", str(record.timestamp))
        console.print(table)

        # Analyse each resolved IP
        if record.resolved_ips:
            from trojandetector.network.ip_analyzer import analyze_ip
            from trojandetector.risk.risk_engine import score_ip, merge_reports

            ip_reports = []
            for ip in record.resolved_ips:
                analysis = analyze_ip(ip)
                ip_table = Table(title=f"  IP: {ip}", box=box.SIMPLE)
                ip_table.add_column("Property", style="cyan")
                ip_table.add_column("Value", style="white")
                ip_table.add_row("Private", "✅" if analysis.is_private else "❌")
                ip_table.add_row("Expected Subnet", "✅" if analysis.is_in_expected_subnet else "❌")
                ip_table.add_row("Reverse DNS", analysis.reverse_dns or "—")
                console.print(ip_table)
                ip_reports.append(score_ip(analysis))

            if ip_reports:
                merged = merge_reports(*ip_reports)
                _print_risk_report(merged)

    console.print()


@app.command()
def connections(
    external_only: bool = typer.Option(
        False, "--external", "-e", help="Show only external (non-private) connections."
    ),
) -> None:
    """List active network connections, optionally filtering to external ones."""
    from trojandetector.network.connection_tracker import (
        get_all_connections,
        get_external_connections,
    )

    if external_only:
        console.print("\n🌍 External connections only:\n")
        conns = get_external_connections()
    else:
        console.print("\n🔗 All active connections:\n")
        conns = get_all_connections()

    if not conns:
        console.print("[dim]No connections found (may require admin privileges).[/dim]\n")
        return

    table = Table(box=box.ROUNDED, show_lines=False)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Protocol")
    table.add_column("Local Address")
    table.add_column("Remote Address")
    table.add_column("Status")

    for c in conns[:100]:  # cap display
        local = f"{c['local_addr']}:{c['local_port']}"
        remote = f"{c['remote_addr']}:{c['remote_port']}" if c["remote_addr"] else "—"
        table.add_row(
            str(c["pid"] or "?"),
            c["protocol"].upper(),
            local,
            remote,
            c["status"],
        )

    console.print(table)
    console.print(f"\n[dim]Showing {min(len(conns), 100)} of {len(conns)} connections.[/dim]\n")


@app.command("process-tree")
def process_tree(pid: int = typer.Argument(..., help="PID to use as the tree root.")) -> None:
    """Display a process and its descendants as a tree."""
    from trojandetector.process.process_tree import build_process_tree

    tree = build_process_tree(pid)
    if not tree:
        console.print(f"[yellow]Process {pid} is unavailable.[/yellow]")
        raise typer.Exit(1)

    def render(node: dict, prefix: str = "") -> None:
        console.print(f"{prefix}[cyan]{node['pid']}[/cyan] {node['name']}")
        children = node.get("children", [])
        for index, child in enumerate(children):
            render(child, prefix + ("└─ " if index == len(children) - 1 else "├─ "))

    render(tree)


@app.command("watch-files")
def watch_files(
    directory: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive"),
) -> None:
    """Watch a directory and report file create, modify, move, and delete events."""
    from trojandetector.behavior.file_monitor import watch_directory

    def report(event: dict) -> None:
        console.print(
            f"[yellow]{event['event_type']}[/yellow] {event['path']} "
            f"[dim]({event['timestamp']})[/dim]"
        )

    console.print(f"Watching [cyan]{directory.resolve()}[/cyan]. Press Ctrl+C to stop.")
    watch_directory(directory, callback=report, recursive=recursive)


@intel_app.command("status")
def intelligence_status() -> None:
    """Show whether MongoDB intelligence is configured and reachable."""
    from trojandetector.intelligence.database import check_connection

    available, message = check_connection()
    console.print(f"[green]●[/green] {message}" if available else f"[yellow]●[/yellow] {message}")


@intel_app.command("lookup")
def intelligence_lookup(target: str = typer.Argument(..., help="SHA-256, IP address, or domain.")) -> None:
    """Look up an observable in local MongoDB intelligence."""
    import ipaddress

    try:
        ipaddress.ip_address(target)
    except ValueError:
        if len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target):
            from trojandetector.intelligence.hash_intelligence import lookup_hash

            record = lookup_hash(target)
        else:
            from trojandetector.intelligence.domain_intelligence import lookup_domain

            record = lookup_domain(target)
    else:
        from trojandetector.intelligence.ip_intelligence import lookup_ip

        record = lookup_ip(target)
    console.print_json(json.dumps(record, default=str) if record else "{}")
    if not record:
        console.print("[dim]No intelligence record found.[/dim]")


@intel_app.command("history")
def intelligence_history(
    limit: int = typer.Option(50, min=1, max=500, help="Maximum reports to show."),
) -> None:
    """Show recent confirmed community detection reports."""
    from trojandetector.intelligence.database import get_detection_history

    reports = get_detection_history(limit=limit)
    if not reports:
        console.print("[dim]No detection reports found.[/dim]")
        return
    console.print_json(json.dumps(reports, default=str))


@intel_app.command("report")
def intelligence_report(
    classification: str = typer.Argument(..., help="Confirmed classification: suspicious or malicious."),
    sha256: str | None = typer.Option(None, help="SHA-256 file indicator."),
    ip: list[str] = typer.Option([], "--ip", help="Related IP address; repeat as needed."),
    domain: list[str] = typer.Option([], "--domain", help="Related domain; repeat as needed."),
    risk_score: int = typer.Option(0, min=0, max=100, help="Assessed risk score."),
    reason: str = typer.Option("", help="Short explanation supporting the report."),
    confirmed: bool = typer.Option(False, "--confirmed", help="Confirm this detection is suitable for community reporting."),
) -> None:
    """Submit an explicitly confirmed detection to shared intelligence."""
    from trojandetector.intelligence.database import record_detection

    try:
        detection_id = record_detection({
            "classification": classification.lower(),
            "sha256": sha256,
            "ips": ip,
            "domains": domain,
            "risk_score": risk_score,
            "reason": reason.strip(),
            "confirmed": confirmed,
        })
    except (ValueError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]Detection report stored.[/green] ID: {detection_id}")


@app.command()
def version() -> None:
    """Show the Trojan Detector version."""
    console.print(f"[bold]Trojan Detector[/bold] v{__version__}")


# ── Entry point ──────────────────────────────────────────────────────────

def main() -> None:
    """Entry point for ``python -m trojandetector``."""
    app()


if __name__ == "__main__":
    main()
