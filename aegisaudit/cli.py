import typer
import asyncio
import logging
import sys
from functools import wraps
from pathlib import Path
from typing import Callable, List, Optional, Set, TypeVar, cast
from datetime import datetime

from rich.console import Console
from rich.table import Table

from aegisaudit.models import _tool_version
from aegisaudit.config import load_config, AegisConfig
from aegisaudit.fetcher import Fetcher
from aegisaudit.gating import gate_failure_reason, parse_formats, parse_severity
from aegisaudit.models import ScanResult, Severity
from aegisaudit.runner import Runner
from aegisaudit.reporters import generate_json_report, generate_sarif_report, generate_html_report
from aegisaudit.history import ScanHistory
from aegisaudit.notifications import send_webhook, send_telegram
from aegisaudit.integrations.notion import push_to_notion
from aegisaudit.sast.scanner import SASTScanner

app = typer.Typer(help="AegisAudit - Security posture reports for modern web apps.")
console = Console()

# Exit codes. See aegisaudit/gating.py for the rationale.
EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_USAGE_ERROR = 2
EXIT_TOOL_ERROR = 2  # an unhandled crash; distinct from a tripped gate (1)

F = TypeVar("F", bound=Callable[..., None])


def _guarded(fn: F) -> F:
    """Map any unhandled exception in a command to exit code >=2.

    Without this, a crash anywhere in the pipeline (a malformed input file, a
    report-writer error) falls through to the framework default of exit 1 --
    indistinguishable from "--fail-on tripped". gating.py sells that
    distinction as the tool's edge over gitleaks; this backstop preserves it.
    typer.Exit (deliberate 0/1/2) is re-raised untouched.
    """

    @wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> None:
        try:
            fn(*args, **kwargs)
        except typer.Exit:
            raise
        except Exception as exc:  # noqa: BLE001 - deliberate top-level backstop
            console.print(f"[bold red]Tool error:[/bold red] {exc}")
            raise typer.Exit(code=EXIT_TOOL_ERROR) from exc

    return cast(F, wrapper)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"AegisAudit {_tool_version()}")
        raise typer.Exit(code=EXIT_OK)


def _resolve_formats(format_values: List[str]) -> Set[str]:
    """Parse --format, converting a bad value into a usage error (exit 2)."""
    try:
        return parse_formats(format_values)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_USAGE_ERROR) from None


def _resolve_fail_on(fail_on: Optional[str]) -> Optional[Severity]:
    if fail_on is None:
        return None
    try:
        return parse_severity(fail_on)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_USAGE_ERROR) from None


def _write_reports(result: ScanResult, out: Path, formats: Set[str]) -> None:
    """Write every requested report format."""
    out.mkdir(parents=True, exist_ok=True)

    if "json" in formats:
        path = out / "report.json"
        generate_json_report(result, path)
        console.print(f"JSON Report: [link=file://{path}]{path}[/link]")

    if "sarif" in formats:
        path = out / "report.sarif"
        generate_sarif_report(result, path)
        console.print(f"SARIF Report: [link=file://{path}]{path}[/link]")

    if "html" in formats:
        path = out / "report.html"
        generate_html_report(result, path)
        console.print(f"HTML Report: [link=file://{path}]{path}[/link]")


def _apply_gate(
    result: ScanResult, fail_on: Optional[Severity], fail_under: Optional[float]
) -> None:
    """Fail the build if the result trips the configured gate."""
    reason = gate_failure_reason(result, fail_on=fail_on, fail_under=fail_under)
    if reason:
        console.print(f"\n[bold red]FAILED:[/bold red] {reason}")
        raise typer.Exit(code=EXIT_GATE_FAILED)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the AegisAudit version and exit.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Emit diagnostic logs (to stderr)."
    ),
) -> None:
    """
    AegisAudit security auditor.
    """
    # Diagnostics go through logging to stderr so stdout stays clean for piping;
    # -v raises the level from WARNING to DEBUG.
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


async def run_scan(
    urls: List[str],
    config: AegisConfig,
    output_dir: Path,
    formats: Set[str],
    save_history: bool = True,
    webhook: Optional[str] = None,
) -> Optional[ScanResult]:
    console.print(f"[bold green]Starting scan against {len(urls)} targets...[/bold green]")
    fetcher = Fetcher(config)

    try:
        artifacts = await fetcher.fetch_many(urls)
    finally:
        await fetcher.close()

    for artifact in artifacts:
        console.print(f"  [green]✓[/green] {artifact.status_code} {artifact.final_url}")
    fetched_urls = {a.url for a in artifacts}
    failed_targets = [u for u in urls if u not in fetched_urls]
    if failed_targets:
        console.print(
            f"  [red]✗[/red] {len(failed_targets)} of {len(urls)} target(s) failed to fetch"
        )

    if artifacts:
        console.print(f"\n[bold]Running checks on {len(artifacts)} artifacts...[/bold]")
        runner = Runner(config)
        result = runner.run_checks(artifacts)
        # Record what never got assessed so an incomplete scan can't read as a
        # clean one in the report or the gate.
        result.failed_targets = failed_targets
        result.finished_at = datetime.now()

        # Display Summary
        console.print("\n[bold]Scan Summary:[/bold]")
        console.print(
            f"Overall Score: [bold cyan]{result.summary.overall_score:.1f}[/bold cyan] / 100"
        )

        # Display Findings
        if result.findings:
            table = Table(title="Security Findings")
            table.add_column("Severity", style="bold")
            table.add_column("Finding", style="white")
            table.add_column("URL", style="cyan")

            for finding in result.findings:
                color = "green"
                if finding.severity == "high":
                    color = "red"
                elif finding.severity == "medium":
                    color = "yellow"
                elif finding.severity == "low":
                    color = "blue"

                table.add_row(
                    f"[{color}]{finding.severity.upper()}[/{color}]", finding.title, finding.url
                )
            console.print(table)
        else:
            console.print("[green]No issues found![/green]")

        _write_reports(result, output_dir, formats)

        # History is a property of having run a scan, not of having asked for
        # an HTML report. This call used to sit inside the `if "html"` branch,
        # so `--format json` silently recorded no trend data at all.
        if save_history:
            ScanHistory().add_scan(result)
            console.print("[dim]Scan saved to history.[/dim]")

        if webhook:
            send_webhook(webhook, result)
            console.print("[dim]Sent webhook notification.[/dim]")

        return result

    return None


@app.command()
@_guarded
def audit(
    directory: Path = typer.Argument(
        ...,
        metavar="DIRECTORY",
        help="Directory to audit",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    out: Path = typer.Option(Path("./aegis-audit"), "--out", help="Output directory"),
    format: List[str] = typer.Option(
        ["all"], "--format", help="Output formats: json, html, sarif, all"
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 if any finding is at or above this severity (info|low|medium|high|critical).",
    ),
    fail_under: Optional[float] = typer.Option(
        None, "--fail-under", help="Exit 1 if the overall score is below this value (0-100)."
    ),
    telegram_token: Optional[str] = typer.Option(
        None, "--telegram-token", envvar="AEGIS_TELEGRAM_TOKEN", help="Telegram bot token"
    ),
    telegram_chat_id: Optional[str] = typer.Option(
        None, "--telegram-chat-id", envvar="AEGIS_TELEGRAM_CHAT_ID", help="Telegram chat ID"
    ),
    notion_db: Optional[str] = typer.Option(
        None, "--notion-db", envvar="AEGIS_NOTION_DB_ID", help="Notion database ID"
    ),
    notion_token: Optional[str] = typer.Option(
        None, "--notion-token", envvar="NOTION_TOKEN", help="Notion integration token"
    ),
) -> None:
    """
    Run a static analysis (SAST) audit on a local directory.
    Checks for secrets, dependency vulnerabilities, and insecure code patterns.
    """
    formats = _resolve_formats(format)
    fail_on_severity = _resolve_fail_on(fail_on)

    console.print(f"[bold green]Starting audit of {directory}...[/bold green]")

    scanner = SASTScanner()
    result = scanner.scan(directory)
    findings = result.findings

    # Display Summary
    console.print(f"\n[bold]Audit Complete found {len(findings)} issues.[/bold]")
    console.print(f"Overall Score: [bold cyan]{result.summary.overall_score:.1f}[/bold cyan] / 100")
    if findings:
        table = Table(title="Audit Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="white")
        table.add_column("Location", style="cyan")

        for f in findings:
            color = "green"
            if f.severity == Severity.HIGH:
                color = "red"
            elif f.severity == Severity.MEDIUM:
                color = "yellow"
            elif f.severity == Severity.LOW:
                color = "blue"

            # Truncate evidence/location for CLI
            loc = f.evidence if f.evidence else f.url
            if len(loc) > 60:
                loc = loc[:57] + "..."

            table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.title, loc)
        console.print(table)
    else:
        console.print("[green]No issues found![/green]")

    _write_reports(result, out, formats)

    if telegram_token and telegram_chat_id:
        send_telegram(telegram_token, telegram_chat_id, result)
    if notion_db and notion_token:
        push_to_notion(result, notion_db, notion_token)

    _apply_gate(result, fail_on_severity, fail_under)


@app.command()
@_guarded
def scan(
    urls: Optional[List[str]] = typer.Option(
        None, "--url", help="Single URL to scan (can be repeated)"
    ),
    file: Optional[Path] = typer.Option(None, "--file", help="File containing URLs to scan"),
    config_file: Optional[Path] = typer.Option(
        None, "--config", help="Path to aegis.yml config file"
    ),
    out: Path = typer.Option(Path("./aegis-report"), "--out", help="Output directory"),
    format: List[str] = typer.Option(
        ["all"], "--format", help="Output formats: json, html, sarif, all"
    ),
    probe: bool = typer.Option(
        False, "--probe", help="Actively probe for sensitive files (.env, .git)"
    ),
    webhook: Optional[str] = typer.Option(
        None, "--webhook", help="Slack/Discord webhook URL for alerts"
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 if any finding is at or above this severity (info|low|medium|high|critical).",
    ),
    fail_under: Optional[float] = typer.Option(
        None, "--fail-under", help="Exit 1 if the overall score is below this value (0-100)."
    ),
    telegram_token: Optional[str] = typer.Option(
        None, "--telegram-token", envvar="AEGIS_TELEGRAM_TOKEN", help="Telegram bot token"
    ),
    telegram_chat_id: Optional[str] = typer.Option(
        None, "--telegram-chat-id", envvar="AEGIS_TELEGRAM_CHAT_ID", help="Telegram chat ID"
    ),
    notion_db: Optional[str] = typer.Option(
        None, "--notion-db", envvar="AEGIS_NOTION_DB_ID", help="Notion database ID"
    ),
    notion_token: Optional[str] = typer.Option(
        None, "--notion-token", envvar="NOTION_TOKEN", help="Notion integration token"
    ),
) -> None:
    """
    Run a security posture scan against target URLs.
    """
    formats = _resolve_formats(format)
    fail_on_severity = _resolve_fail_on(fail_on)

    config = load_config(config_file)
    target_urls = []

    if urls:
        target_urls.extend(urls)

    if file is not None:
        # An explicit --file that doesn't exist is a mistake worth naming, not a
        # silent no-op that later surfaces as the generic "no targets" message.
        if not file.exists():
            console.print(f"[red]File not found:[/red] {file}")
            raise typer.Exit(code=EXIT_USAGE_ERROR)
        with open(file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
            target_urls.extend(lines)

    if not target_urls:
        console.print("[red]No targets specified.[/red] Provide --url or --file.")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    # Probing Logic: Expand targets
    if probe:
        expanded_urls = []
        for url in target_urls:
            expanded_urls.append(url)  # Keep original
            # Remove trailing slash for appending
            base = url.rstrip("/")
            expanded_urls.append(f"{base}/.env")
            expanded_urls.append(f"{base}/.git/HEAD")
            # Fetch the RFC 9116 disclosure file so check_security_txt can
            # actually validate it -- without this it only fires when the user
            # names a security.txt URL by hand.
            expanded_urls.append(f"{base}/.well-known/security.txt")
            # We could add more here (wp-config, etc.)
        target_urls = expanded_urls
        console.print(
            f"[yellow]Probing enabled. Target list expanded to {len(target_urls)} URLs.[/yellow]"
        )

    result = asyncio.run(
        run_scan(
            target_urls,
            config,
            output_dir=out,
            formats=formats,
            save_history=True,
            webhook=webhook,
        )
    )

    if result is None:
        # Every target failed to fetch. That is a scan failure, not a clean
        # bill of health -- exiting 0 here would let a DNS outage read as
        # "no issues found".
        console.print("[red]No targets could be fetched.[/red]")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    if telegram_token and telegram_chat_id:
        send_telegram(telegram_token, telegram_chat_id, result)
    if notion_db and notion_token:
        push_to_notion(result, notion_db, notion_token)

    _apply_gate(result, fail_on_severity, fail_under)


if __name__ == "__main__":
    app()
