"""
MASVS CLI — Full command-line interface for MASVS/MASTG Audit Copilot.

Commands:
    masvs auth login --token <key>        Save API token
    masvs auth profile set --url <url>    Set server URL
    masvs scan run <app.apk>              Upload and scan
    masvs scan status <job_id>            Check progress
    masvs report get <scan_id> --format   Download report
    masvs report diff <id1> <id2>         Compare two scans
    masvs finding accept <id> --reason    Accept risk
    masvs finding suppress <id>           Mark false positive
"""

import sys
import time
import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import print as rprint

app = typer.Typer(
    name="masvs",
    help="MASVS/MASTG Audit Copilot CLI — Scan mobile apps for security vulnerabilities",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

# ─── Sub-command groups ───
scan_app = typer.Typer(name="scan", help="Scan mobile apps", no_args_is_help=True)
report_app = typer.Typer(name="report", help="Audit reports", no_args_is_help=True)
finding_app = typer.Typer(name="finding", help="Manage findings", no_args_is_help=True)
auth_app = typer.Typer(name="auth", help="Authentication", no_args_is_help=True)

app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(finding_app, name="finding")
app.add_typer(auth_app, name="auth")


# ═══════════════════════════════════════════
# AUTH COMMANDS
# ═══════════════════════════════════════════

@auth_app.command("login")
def auth_login(
    token: str = typer.Option(..., prompt="API Token", help="API access token"),
):
    """Save API token for authentication."""
    from masvs_cli.client import save_token
    save_token(token)
    console.print("[green]✓[/green] Token saved to ~/.masvs/config.toml")


@auth_app.command("profile")
def auth_profile(
    url: str = typer.Option("http://localhost:8000", help="API server URL"),
):
    """Set the API server URL."""
    from masvs_cli.client import save_server_url
    save_server_url(url)
    console.print(f"[green]✓[/green] Server URL set to: {url}")


@auth_app.command("register")
def auth_register(
    email: str = typer.Option(..., prompt=True, help="Email address"),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Password"),
    name: str = typer.Option(None, help="Full name"),
):
    """Register a new account and save the token."""
    from masvs_cli.client import APIClient, save_token
    api = APIClient()

    data = {"email": email, "password": password}
    if name:
        data["full_name"] = name

    resp = api.post("/api/auth/register", json=data)
    if resp.status_code == 201:
        token = resp.json()["access_token"]
        save_token(token)
        console.print("[green]✓[/green] Account created. Token saved.")
    else:
        console.print(f"[red]✗[/red] Registration failed: {resp.json().get('detail', resp.text)}")
        raise typer.Exit(1)


# ═══════════════════════════════════════════
# SCAN COMMANDS
# ═══════════════════════════════════════════

@scan_app.command("run")
def scan_run(
    app_path: str = typer.Argument(..., help="Path to APK or IPA file"),
    project: str = typer.Option("default", help="Project name"),
    version: Optional[str] = typer.Option(None, help="App version"),
    mode: str = typer.Option("static", help="Scan mode: static|dynamic"),
    output: str = typer.Option("table", help="Output: table|json|pdf|sarif|markdown"),
    fail_on: Optional[str] = typer.Option(None, help="Exit 1 if severity >= critical|high|medium"),
    wait: bool = typer.Option(True, help="Wait for scan to complete"),
):
    """Upload and scan a mobile application."""
    import os
    if not os.path.isfile(app_path):
        console.print(f"[red]✗[/red] File not found: {app_path}")
        raise typer.Exit(1)

    from masvs_cli.client import APIClient
    api = APIClient()

    # Upload
    console.print(f"[yellow]*[/yellow] Uploading [bold]{os.path.basename(app_path)}[/bold]...")
    data = {"project_name": project, "scan_mode": mode}
    if version:
        data["app_version"] = version

    resp = api.upload_file("/api/scans/upload", app_path, data)
    if resp.status_code != 202:
        console.print(f"[red]✗[/red] Upload failed: {resp.text}")
        raise typer.Exit(1)

    result = resp.json()
    scan_id = result["scan_id"]
    console.print(f"[green]✓[/green] Uploaded. Scan ID: [bold]{scan_id}[/bold]")

    if not wait:
        console.print(f"[dim]Track with: masvs scan status {scan_id}[/dim]")
        return

    # Poll for completion
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=100)

        while True:
            resp = api.get(f"/api/scans/{scan_id}")
            if resp.status_code != 200:
                break
            scan_data = resp.json()
            status = scan_data.get("status", "")
            pct = scan_data.get("progress", 0)
            progress.update(task, completed=pct, description=f"[{status}]")

            if status in ("done", "failed"):
                break
            time.sleep(2)

    # Show results
    resp = api.get(f"/api/scans/{scan_id}")
    scan_data = resp.json()

    if scan_data.get("status") == "failed":
        console.print(f"[red]✗[/red] Scan failed: {scan_data.get('error_message', 'Unknown error')}")
        raise typer.Exit(1)

    # Display summary
    score = scan_data.get("score", 0)
    grade = scan_data.get("grade", "?")
    findings_count = scan_data.get("findings_count", 0)

    console.print()
    console.print(Panel.fit(
        f"[bold]Score: {score:.1f}/100 ({grade})[/bold]\n"
        f"Findings: {findings_count}",
        title="Scan Complete",
        border_style="green" if score >= 75 else "yellow" if score >= 50 else "red",
    ))

    # Show findings table
    if output in ("table", "json"):
        resp = api.get(f"/api/scans/{scan_id}/findings")
        if resp.status_code == 200:
            findings = resp.json()
            if output == "json":
                console.print_json(json.dumps(findings, indent=2))
            else:
                _print_findings_table(findings)

    # Auto-download report
    if output in ("pdf", "markdown", "sarif"):
        console.print(f"[yellow]⏳[/yellow] Generating {output} report...")
        resp = api.post(f"/api/reports/{scan_id}/{output}")
        if resp.status_code == 201:
            report_data = resp.json()
            download_url = report_data["download_url"]
            filename = f"audit_report_{scan_id}.{output if output != 'markdown' else 'md'}"
            api.download_file(download_url, filename)
            console.print(f"[green]✓[/green] Report saved: {filename}")

    # CI/CD gate
    if fail_on:
        resp = api.get(f"/api/scans/{scan_id}/findings")
        if resp.status_code == 200:
            findings = resp.json()
            severity_order = ["critical", "high", "medium", "low", "info"]
            threshold_idx = severity_order.index(fail_on)
            blocking = [f for f in findings if
                        f.get("severity") in severity_order[:threshold_idx + 1]]
            if blocking:
                console.print(
                    f"[red]✗[/red] CI gate failed: {len(blocking)} finding(s) >= {fail_on}"
                )
                raise typer.Exit(1)


@scan_app.command("status")
def scan_status(job_id: int = typer.Argument(..., help="Scan ID")):
    """Check the status of a running scan."""
    from masvs_cli.client import APIClient
    api = APIClient()

    resp = api.get(f"/api/scans/{job_id}")
    if resp.status_code != 200:
        console.print(f"[red]✗[/red] Scan {job_id} not found")
        raise typer.Exit(1)

    data = resp.json()
    console.print(Panel.fit(
        f"Status: [bold]{data['status']}[/bold]\n"
        f"Progress: {data.get('progress', 0)}%\n"
        f"Score: {data.get('score', 'N/A')}\n"
        f"Grade: {data.get('grade', 'N/A')}",
        title=f"Scan #{job_id}",
    ))


@scan_app.command("list")
def scan_list(
    limit: int = typer.Option(10, help="Number of scans to show"),
    project: Optional[str] = typer.Option(None, help="Filter by project name"),
):
    """List recent security scans."""
    from masvs_cli.client import APIClient
    api = APIClient()

    params = {"page_size": limit}
    resp = api.get("/api/scans/", params=params)
    if resp.status_code != 200:
        console.print(f"[red]✗[/red] Failed to fetch scans: {resp.text}")
        raise typer.Exit(1)

    scans = resp.json().get("scans", [])
    if not scans:
        console.print("[yellow]![/yellow] No scans found.")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=6)
    table.add_column("Project", width=20)
    table.add_column("App/File", width=25)
    table.add_column("Score", width=8, justify="center")
    table.add_column("Grade", width=6, justify="center")
    table.add_column("Status", width=12)
    table.add_column("Date", width=12)

    for s in scans:
        score = s.get("score")
        score_str = f"{score:.1f}" if score is not None else "—"
        grade = s.get("grade", "—")
        status = s.get("status", "unknown")
        
        # Color score
        s_color = "green" if score and score >= 75 else "yellow" if score and score >= 50 else "red"
        
        table.add_row(
            str(s.get("id")),
            s.get("project_name", "N/A"),
            s.get("file_name", "N/A")[:25],
            f"[{s_color}]{score_str}[/]",
            f"[bold]{grade}[/]",
            status,
            s.get("created_at", "")[:10],
        )

    console.print(table)


# ═══════════════════════════════════════════
# REPORT COMMANDS
# ═══════════════════════════════════════════

@report_app.command("get")
def report_get(
    scan_id: int = typer.Argument(..., help="Scan ID"),
    format: str = typer.Option("pdf", help="Format: pdf|markdown|sarif"),
    output: Optional[str] = typer.Option(None, help="Output filename"),
):
    """Generate and download a report."""
    from masvs_cli.client import APIClient
    api = APIClient()

    console.print(f"[yellow]*[/yellow] Generating {format} report...")
    resp = api.post(f"/api/reports/{scan_id}/{format}")
    if resp.status_code != 201:
        console.print(f"[red]✗[/red] Failed: {resp.text}")
        raise typer.Exit(1)

    report_data = resp.json()
    ext = {"pdf": ".pdf", "markdown": ".md", "sarif": ".sarif"}.get(format, ".bin")
    filename = output or f"audit_report_{scan_id}{ext}"

    api.download_file(report_data["download_url"], filename)
    console.print(f"[green]✓[/green] Report saved: {filename}")


@report_app.command("diff")
def report_diff(
    scan_id_1: int = typer.Argument(..., help="First scan ID (older)"),
    scan_id_2: int = typer.Argument(..., help="Second scan ID (newer)"),
):
    """Compare two scan versions."""
    from masvs_cli.client import APIClient
    api = APIClient()

    resp = api.get(f"/api/scans/{scan_id_1}/diff", params={"compare": scan_id_2})
    if resp.status_code != 200:
        console.print(f"[red]✗[/red] Diff failed: {resp.text}")
        raise typer.Exit(1)

    data = resp.json()
    score_change = data.get("score_change")

    console.print(Panel.fit(
        f"[red]🆕 New findings: {len(data['new_findings'])}[/red]\n"
        f"[green]✅ Fixed: {len(data['fixed_findings'])}[/green]\n"
        f"[dim]⏺  Persistent: {len(data['persistent_findings'])}[/dim]\n"
        f"Score change: {f'{score_change:+.1f}' if score_change is not None else 'N/A'}",
        title=f"Diff: #{scan_id_1} → #{scan_id_2}",
    ))

    if data["new_findings"]:
        console.print("\n[bold red]New Findings:[/bold red]")
        _print_findings_table(data["new_findings"])

    if data["fixed_findings"]:
        console.print("\n[bold green]Fixed Findings:[/bold green]")
        _print_findings_table(data["fixed_findings"])


# ═══════════════════════════════════════════
# FINDING COMMANDS
# ═══════════════════════════════════════════

@finding_app.command("accept")
def finding_accept(
    finding_id: int = typer.Argument(..., help="Finding ID"),
    reason: str = typer.Option(..., prompt="Reason", help="Justification"),
):
    """Mark a finding as accepted risk."""
    from masvs_cli.client import APIClient
    api = APIClient()

    resp = api.patch(
        f"/api/findings/{finding_id}/status",
        json={"status": "accepted_risk", "reason": reason},
    )
    if resp.status_code == 200:
        console.print(f"[green]✓[/green] Finding #{finding_id} → accepted risk")
    else:
        console.print(f"[red]✗[/red] Failed: {resp.text}")
        raise typer.Exit(1)


@finding_app.command("suppress")
def finding_suppress(finding_id: int = typer.Argument(..., help="Finding ID")):
    """Mark a finding as false positive."""
    from masvs_cli.client import APIClient
    api = APIClient()

    resp = api.patch(
        f"/api/findings/{finding_id}/status",
        json={"status": "false_positive", "reason": "Suppressed via CLI"},
    )
    if resp.status_code == 200:
        console.print(f"[green]✓[/green] Finding #{finding_id} → suppressed")
    else:
        console.print(f"[red]✗[/red] Failed: {resp.text}")
        raise typer.Exit(1)


# ═══════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════

def _print_findings_table(findings: list):
    """Print a rich table of findings."""
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=5)
    table.add_column("Severity", width=10)
    table.add_column("Title", max_width=40)
    table.add_column("MASVS", width=18)
    table.add_column("CVSS", width=6)
    table.add_column("Triage", width=12)

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for f in findings:
        sev = f.get("severity", "info")
        table.add_row(
            str(f.get("id", "")),
            f"[{severity_colors.get(sev, 'white')}]{sev.upper()}[/]",
            f.get("title", "")[:40],
            f.get("masvs_control", "N/A"),
            str(f.get("cvss_score", "N/A")),
            f.get("triage_result", "—"),
        )

    console.print(table)


if __name__ == "__main__":
    app()
