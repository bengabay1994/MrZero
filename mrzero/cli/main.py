"""MrZero CLI - Main entry point."""

import asyncio
import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.markdown import Markdown

from mrzero import __version__
from mrzero.core.config import MrZeroConfig, get_config, set_config
from mrzero.core.schemas import ExecutionMode
from mrzero.cli.commands.docker_cmd import docker_app

app = typer.Typer(
    name="mrzero",
    help="MrZero - Autonomous AI Bug Bounty CLI",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

# Marker file for first run detection
FIRST_RUN_MARKER = ".mrzero_initialized"


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold blue]MrZero[/bold blue] version {__version__}")
        raise typer.Exit()


def print_banner() -> None:
    """Print the MrZero banner."""
    banner = r"""
[bold red]  __  __     _____                
 |  \/  |   |__  /__ _ _ __ ___   
 | |\/| |r    / // _ \ '__/ _ \  
 | |  | |   / /|  __/ | | (_) | 
 |_|  |_|  /____\___|_|  \___/  
[/bold red]
[dim]Autonomous AI Bug Bounty CLI[/dim]
    """
    console.print(banner)


def is_first_run() -> bool:
    """Check if this is the first time MrZero is being run."""
    config = get_config()
    marker_path = config.data_dir / FIRST_RUN_MARKER
    return not marker_path.exists()


def mark_initialized() -> None:
    """Mark MrZero as initialized after first run."""
    config = get_config()
    config.ensure_directories()
    marker_path = config.data_dir / FIRST_RUN_MARKER
    marker_path.touch()


def run_onboarding() -> None:
    """Run first-time onboarding process."""
    console.print("\n[bold cyan]Welcome to MrZero![/bold cyan]")
    console.print("Let's get you set up.\n")

    # Step 1: Check tool availability
    console.print("[bold]Step 1: Checking installed security tools...[/bold]\n")

    tool_status = _check_all_tools()
    _display_tool_summary(tool_status)

    # Step 2: LLM Provider setup
    console.print("\n[bold]Step 2: LLM Provider Configuration[/bold]\n")
    console.print("MrZero requires an LLM provider. Choose one:")
    console.print("  1. [cyan]AWS Bedrock[/cyan] - Use AWS credentials (Claude, Nova, Llama)")
    console.print("  2. [cyan]Google Gemini[/cyan] - Use Google OAuth\n")

    config = get_config()

    choice = Prompt.ask("Select provider", choices=["1", "2"], default="1")
    if choice == "1":
        config.llm.provider = "aws_bedrock"
        console.print("\n[dim]Run 'aws configure' if you haven't set up AWS credentials.[/dim]")
    else:
        config.llm.provider = "google_gemini"
        console.print("\n[dim]Run 'mrzero auth login' to authenticate with Google.[/dim]")

    # Step 3: Save configuration
    config.ensure_directories()
    config.save()
    set_config(config)

    # Mark as initialized
    mark_initialized()

    console.print("\n[green]Setup complete![/green]")
    console.print("\nQuick start:")
    console.print("  [cyan]mrzero scan ./target_repo --mode hitl[/cyan]  # Start a scan")
    console.print("  [cyan]mrzero tools[/cyan]                          # Check tool status")
    console.print("  [cyan]mrzero config show[/cyan]                    # View configuration")
    console.print()


def _check_all_tools() -> dict[str, dict]:
    """Check all tools using ToolCompatibility."""
    from mrzero.core.sast_runner import ToolCompatibility, get_platform_info

    compat = ToolCompatibility()
    platform_info = get_platform_info()

    # Get all tools from compatibility matrix
    results = {
        "platform": platform_info.to_dict(),
        "categories": {},
    }

    # Categorize tools
    categories = {
        "SAST": ["opengrep", "gitleaks", "trivy", "codeql", "infer", "bearer", "appinspector"],
        "Code Analysis": ["joern"],
        "Smart Contract": ["slither", "mythril"],
        "Binary": ["binwalk", "strings", "ropgadget"],
        "Dynamic/Exploit": ["pwntools", "frida", "gdb", "afl", "metasploit", "msfvenom"],
        "Windows": ["windbg", "winafl"],
    }

    for category, tools in categories.items():
        category_results = {}
        for tool in tools:
            is_compatible = compat.is_compatible(tool)
            is_available = compat.is_available(tool) if is_compatible else False
            tool_info = compat.TOOL_COMPATIBILITY.get(tool, {})

            category_results[tool] = {
                "compatible": is_compatible,
                "available": is_available,
                "binary": tool_info.get("binary", tool),
                "notes": tool_info.get("notes", ""),
                "platforms": tool_info.get("platforms", []),
            }
        results["categories"][category] = category_results

    return results


def _display_tool_summary(tool_status: dict) -> None:
    """Display a summary of tool availability."""
    platform_info = tool_status["platform"]

    console.print(f"[dim]Platform: {platform_info['system']} ({platform_info['machine']})[/dim]\n")

    total_available = 0
    total_tools = 0

    for category, tools in tool_status["categories"].items():
        # Skip Windows tools on non-Windows
        if category == "Windows" and platform_info["system"] != "windows":
            continue

        available_in_category = sum(1 for t in tools.values() if t["available"])
        total_in_category = sum(1 for t in tools.values() if t["compatible"])

        total_available += available_in_category
        total_tools += total_in_category

        status_color = (
            "green"
            if available_in_category == total_in_category
            else ("yellow" if available_in_category > 0 else "red")
        )

        console.print(
            f"  [{status_color}]{category}:[/{status_color}] "
            f"{available_in_category}/{total_in_category} tools available"
        )

    console.print(f"\n[bold]Total: {total_available}/{total_tools} tools available[/bold]")

    if total_available < total_tools:
        console.print("\n[dim]Run 'mrzero tools' for detailed status and installation hints.[/dim]")


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """MrZero - Autonomous AI Bug Bounty CLI Tool.

    Analyze codebases for security vulnerabilities, setup reproduction
    environments, and generate weaponized exploits.
    """
    pass


@app.command()
def scan(
    target: Path = typer.Argument(
        ...,
        help="Path to the target codebase to scan.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    mode: str = typer.Option(
        "hitl",
        "--mode",
        "-m",
        help="Execution mode: 'yolo' (autonomous) or 'hitl' (human-in-the-loop).",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for results.",
    ),
    resume: Optional[str] = typer.Option(
        None,
        "--resume",
        "-r",
        help="Resume a previous session by ID.",
    ),
    checkpoint_interval: int = typer.Option(
        1,
        "--checkpoint-interval",
        "-c",
        help="Save checkpoint every N agent completions (0 to disable).",
    ),
    skip_onboarding: bool = typer.Option(
        False,
        "--skip-onboarding",
        help="Skip first-run onboarding check.",
    ),
) -> None:
    """Start a vulnerability scan on a target codebase.

    The scan will analyze the codebase, identify vulnerabilities, and
    optionally generate exploits.
    """
    print_banner()

    # Check for first run and run onboarding
    if not skip_onboarding and is_first_run():
        run_onboarding()
        console.print()  # Extra spacing

    # Validate mode
    try:
        exec_mode = ExecutionMode(mode.lower())
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid mode '{mode}'. Use 'yolo' or 'hitl'.")
        raise typer.Exit(1)

    # Display scan configuration
    config = get_config()
    config.ensure_directories()

    if output:
        config.output_dir = output
        config.output_dir.mkdir(parents=True, exist_ok=True)

    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Mode:[/bold] {exec_mode.value.upper()}\n"
            f"[bold]Output:[/bold] {config.output_dir}",
            title="[bold blue]Scan Configuration[/bold blue]",
            border_style="blue",
        )
    )

    if exec_mode == ExecutionMode.HITL:
        console.print(
            "\n[yellow]HITL Mode:[/yellow] You will be prompted for confirmation at "
            "critical decision points.\n"
        )
    else:
        console.print(
            "\n[red]YOLO Mode:[/red] The AI will make all decisions autonomously. "
            "[bold]Use with caution![/bold]\n"
        )
        if not Confirm.ask("Are you sure you want to proceed in YOLO mode?"):
            console.print("[dim]Scan cancelled.[/dim]")
            raise typer.Exit(0)

    # Start the scan
    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Initializing scan...", total=None)

        # Import and run the orchestrator
        try:
            from mrzero.core.orchestration.graph import run_scan

            asyncio.run(
                run_scan(
                    str(target),
                    exec_mode,
                    resume_session_id=resume,
                    checkpoint_interval=checkpoint_interval,
                )
            )
        except ImportError as e:
            progress.update(task, description=f"[red]Error: {e}")
            console.print(f"\n[red]Failed to initialize:[/red] {e}")
            console.print("[dim]Ensure all dependencies are installed: pip install -e .[/dim]")
            raise typer.Exit(1)
        except KeyboardInterrupt:
            progress.update(task, description="[yellow]Scan interrupted")
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
            raise typer.Exit(0)
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}")
            console.print(f"\n[red]Scan failed:[/red] {e}")
            raise typer.Exit(1)


# Config subcommand group
config_app = typer.Typer(help="Configuration management")
app.add_typer(config_app, name="config")

# Docker toolbox commands
app.add_typer(docker_app, name="docker")


@config_app.command("show")
def config_show() -> None:
    """Show current configuration."""
    print_banner()
    current_config = get_config()
    _display_config(current_config)


@config_app.command("reset")
def config_reset() -> None:
    """Reset all settings to defaults."""
    print_banner()

    if Confirm.ask("Reset all settings to defaults?"):
        new_config = MrZeroConfig()
        new_config.ensure_directories()
        new_config.save()
        set_config(new_config)
        console.print("[green]Configuration reset to defaults.[/green]")


@config_app.command("tools")
def config_tools() -> None:
    """Configure tool preferences and priorities."""
    print_banner()

    current_config = get_config()

    console.print("\n[bold]Tool Preference Configuration[/bold]\n")
    console.print(
        "[dim]Set tool priorities. Tools are tried in order - first available tool is used.[/dim]\n"
    )

    # Disassembly tools
    console.print("[bold cyan]Disassembly Tools[/bold cyan]")
    console.print("Available: ghidra, ida, binaryninja, radare2")
    console.print(f"Current priority: {', '.join(current_config.tools.disassembly)}")
    disasm_input = Prompt.ask(
        "New priority (comma-separated)",
        default=",".join(current_config.tools.disassembly),
    )
    current_config.tools.disassembly = [t.strip() for t in disasm_input.split(",") if t.strip()]

    # SAST tools
    console.print("\n[bold cyan]SAST Tools[/bold cyan]")
    console.print("Available: opengrep, codeql, joern, bearer, gitleaks, trivy, infer, slither")
    console.print(f"Current enabled: {', '.join(current_config.tools.sast_tools)}")
    sast_input = Prompt.ask(
        "Enabled SAST tools (comma-separated)",
        default=",".join(current_config.tools.sast_tools),
    )
    current_config.tools.sast_tools = [t.strip() for t in sast_input.split(",") if t.strip()]

    # Debugger preference
    console.print("\n[bold cyan]Debugger Preferences[/bold cyan]")
    console.print(f"Linux debugger: {current_config.tools.debugger_linux}")
    linux_debugger = Prompt.ask(
        "Linux debugger (gdb, lldb)",
        default=current_config.tools.debugger_linux,
    )
    current_config.tools.debugger_linux = linux_debugger

    console.print(f"Windows debugger: {current_config.tools.debugger_windows}")
    windows_debugger = Prompt.ask(
        "Windows debugger (windbg, x64dbg)",
        default=current_config.tools.debugger_windows,
    )
    current_config.tools.debugger_windows = windows_debugger

    # Fuzzer preference
    console.print("\n[bold cyan]Fuzzer Preferences[/bold cyan]")
    linux_fuzzer = Prompt.ask(
        "Linux fuzzer (afl++, libfuzzer, honggfuzz)",
        default=current_config.tools.fuzzer_linux,
    )
    current_config.tools.fuzzer_linux = linux_fuzzer

    windows_fuzzer = Prompt.ask(
        "Windows fuzzer (winafl, libfuzzer)",
        default=current_config.tools.fuzzer_windows,
    )
    current_config.tools.fuzzer_windows = windows_fuzzer

    # Save
    current_config.save()
    set_config(current_config)

    console.print("\n[green]Tool preferences saved![/green]")

    # Show current tool availability
    console.print("\n[bold]Checking tool availability...[/bold]")
    tool_status = _check_all_tools()
    _display_tool_summary(tool_status)


@config_app.command("llm")
def config_llm() -> None:
    """Configure LLM provider settings."""
    print_banner()

    current_config = get_config()

    console.print("\n[bold]LLM Provider Configuration[/bold]\n")

    # LLM Provider
    providers = ["aws_bedrock", "google_gemini"]
    console.print("[dim]Available LLM providers:[/dim]")
    for i, p in enumerate(providers, 1):
        desc = (
            "AWS Bedrock (Claude, Nova, Llama)" if p == "aws_bedrock" else "Google Gemini (OAuth)"
        )
        marker = " [current]" if p == current_config.llm.provider else ""
        console.print(f"  {i}. {p} - {desc}{marker}")

    provider_choice = Prompt.ask(
        "\nSelect LLM provider",
        default=current_config.llm.provider,
    )
    if provider_choice in providers:
        current_config.llm.provider = provider_choice

    # Model (optional, provider has default)
    model_input = Prompt.ask(
        "LLM model (leave empty for provider default)",
        default=current_config.llm.model or "",
    )
    current_config.llm.model = model_input if model_input else None

    # Temperature
    temp_input = Prompt.ask(
        "Temperature (0.0-1.0)",
        default=str(current_config.llm.temperature),
    )
    try:
        current_config.llm.temperature = float(temp_input)
    except ValueError:
        console.print("[yellow]Invalid temperature, keeping current value.[/yellow]")

    # Provider-specific configuration
    if current_config.llm.provider == "aws_bedrock":
        console.print("\n[bold]AWS Bedrock Settings[/bold]")
        current_config.llm.aws_region = Prompt.ask(
            "AWS Region",
            default=current_config.llm.aws_region,
        )
        profile_input = Prompt.ask(
            "AWS Profile (leave empty for default)",
            default=current_config.llm.aws_profile or "",
        )
        current_config.llm.aws_profile = profile_input if profile_input else None

    elif current_config.llm.provider == "google_gemini":
        console.print("\n[bold]Google Gemini Settings[/bold]")
        console.print("[dim]Run 'mrzero auth login' to authenticate with OAuth[/dim]")
        project_input = Prompt.ask(
            "Google Cloud Project ID (optional)",
            default=current_config.llm.google_project_id or "",
        )
        current_config.llm.google_project_id = project_input if project_input else None

    # Save
    current_config.save()
    set_config(current_config)

    console.print("\n[green]LLM configuration saved![/green]")
    _display_config(current_config)


# Legacy config command for backward compatibility
@app.command("configure", hidden=True)
def config_legacy(
    show: bool = typer.Option(False, "--show", "-s", help="Show current configuration."),
    reset: bool = typer.Option(False, "--reset", help="Reset to default configuration."),
) -> None:
    """[Deprecated] Use 'mrzero config' subcommands instead."""
    console.print(
        "[yellow]Note: 'mrzero configure' is deprecated. Use 'mrzero config' subcommands.[/yellow]"
    )
    console.print("  mrzero config show   - Show configuration")
    console.print("  mrzero config tools  - Configure tools")
    console.print("  mrzero config llm    - Configure LLM")
    console.print("  mrzero config reset  - Reset configuration")
    console.print()

    if show:
        config_show()
    elif reset:
        config_reset()


@app.command()
def tools() -> None:
    """Check installed security tools and their status."""
    print_banner()

    console.print("\n[bold]Security Tool Status[/bold]\n")

    tools_to_check = {
        "SAST Tools": [
            ("opengrep", "opengrep --version"),
            ("codeql", "codeql --version"),
            ("joern", "joern --version"),
            ("gitleaks", "gitleaks version"),
            ("bearer", "bearer version"),
            ("trivy", "trivy --version"),
        ],
        "Language Analysis": [
            ("tree-sitter", "tree-sitter --version"),
            ("linguist", "github-linguist --version"),
        ],
        "Binary Analysis": [
            ("ghidra", "ghidraRun --help"),
            ("radare2", "r2 -v"),
            ("binwalk", "binwalk --help"),
        ],
        "Exploitation": [
            ("pwntools", "python3 -c 'import pwn; print(pwn.version)'"),
            ("ropgadget", "ROPgadget --version"),
            ("metasploit", "msfconsole --version"),
        ],
        "Debugging": [
            ("gdb", "gdb --version"),
            ("pwndbg", "python3 -c 'import pwndbg'"),
        ],
        "Fuzzing": [
            ("afl++", "afl-fuzz --help"),
        ],
    }

    import subprocess

    for category, tool_list in tools_to_check.items():
        table = Table(title=category, show_header=True, header_style="bold")
        table.add_column("Tool", style="cyan")
        table.add_column("Status")
        table.add_column("Version/Info", style="dim")

        for tool_name, check_cmd in tool_list:
            try:
                result = subprocess.run(
                    check_cmd.split(),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    version = result.stdout.strip().split("\n")[0][:50]
                    table.add_row(tool_name, "[green]Installed[/green]", version)
                else:
                    table.add_row(tool_name, "[red]Not Found[/red]", "-")
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                table.add_row(tool_name, "[red]Not Found[/red]", "-")

        console.print(table)
        console.print()


@app.command()
def sessions(
    list_all: bool = typer.Option(True, "--list", "-l", help="List all saved sessions."),
    delete: Optional[str] = typer.Option(None, "--delete", "-d", help="Delete a session by ID."),
) -> None:
    """Manage scan sessions."""
    print_banner()

    from mrzero.core.memory.sqlite import SessionManager

    config = get_config()
    manager = SessionManager(config.db_path)

    if delete:
        if manager.delete_session(delete):
            console.print(f"[green]Session {delete} deleted.[/green]")
        else:
            console.print(f"[red]Session {delete} not found.[/red]")
        return

    sessions = manager.list_sessions()

    if not sessions:
        console.print("[dim]No saved sessions found.[/dim]")
        return

    table = Table(title="Saved Sessions", show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Started")
    table.add_column("Agent")

    for session in sessions:
        table.add_row(
            session.id[:8],
            str(session.target_path)[:40],
            session.mode.value,
            session.status,
            session.started_at.strftime("%Y-%m-%d %H:%M"),
            session.current_agent or "-",
        )

    console.print(table)


# Auth subcommand group
auth_app = typer.Typer(help="Authentication management")
app.add_typer(auth_app, name="auth")


@auth_app.command("login")
def auth_login(
    provider: str = typer.Option(
        None,
        "--provider",
        "-p",
        help="Provider to authenticate with (aws_bedrock, google_gemini)",
    ),
) -> None:
    """Authenticate with an LLM provider."""
    print_banner()

    providers = ["aws_bedrock", "google_gemini"]

    if not provider:
        console.print("\n[bold]Select LLM Provider:[/bold]\n")
        for i, p in enumerate(providers, 1):
            desc = (
                "AWS Bedrock (Claude, Nova, Llama)"
                if p == "aws_bedrock"
                else "Google Gemini (OAuth)"
            )
            console.print(f"  {i}. {p} - {desc}")

        choice = Prompt.ask("\nSelect provider", choices=["1", "2"], default="2")
        provider = providers[int(choice) - 1]

    if provider == "google_gemini":
        console.print("\n[cyan]Authenticating with Google Gemini...[/cyan]\n")

        try:
            from mrzero.core.llm.providers import GoogleGeminiProvider

            gemini = GoogleGeminiProvider()

            if gemini.is_configured():
                if not Confirm.ask("Already authenticated. Re-authenticate?"):
                    console.print("[dim]Cancelled.[/dim]")
                    return

            success = asyncio.run(gemini.authenticate_oauth())

            if success:
                console.print("\n[green]Successfully authenticated with Google![/green]")
                console.print("[dim]Token saved to ~/.mrzero/[/dim]")
            else:
                console.print("\n[red]Authentication failed.[/red]")
                raise typer.Exit(1)

        except ImportError as e:
            console.print(f"\n[red]Missing dependencies:[/red] {e}")
            console.print("Install with: [cyan]uv pip install -e '.[google]'[/cyan]")
            raise typer.Exit(1)

    elif provider == "aws_bedrock":
        console.print("\n[cyan]Checking AWS Bedrock credentials...[/cyan]\n")

        try:
            from mrzero.core.llm.providers import AWSBedrockProvider

            bedrock = AWSBedrockProvider()

            if bedrock.is_configured():
                console.print("[green]AWS credentials are configured![/green]")

                # Show identity
                try:
                    import boto3

                    sts = boto3.client("sts")
                    identity = sts.get_caller_identity()
                    console.print(f"[dim]Account: {identity['Account']}[/dim]")
                    console.print(f"[dim]ARN: {identity['Arn']}[/dim]")
                except Exception:
                    pass
            else:
                console.print("[red]AWS credentials not found.[/red]")
                console.print("\nConfigure with one of:")
                console.print("  1. [cyan]aws configure[/cyan]")
                console.print("  2. [cyan]aws configure sso[/cyan]")
                console.print("  3. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
                raise typer.Exit(1)

        except ImportError as e:
            console.print(f"\n[red]Missing dependencies:[/red] {e}")
            console.print("Install with: [cyan]uv pip install -e '.[aws]'[/cyan]")
            raise typer.Exit(1)

    else:
        console.print(f"[red]Unknown provider: {provider}[/red]")
        raise typer.Exit(1)


@auth_app.command("status")
def auth_status() -> None:
    """Check authentication status for all providers."""
    print_banner()

    console.print("\n[bold]Authentication Status[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Details")

    # Check AWS Bedrock
    try:
        from mrzero.core.llm.providers import AWSBedrockProvider

        bedrock = AWSBedrockProvider()
        if bedrock.is_configured():
            try:
                import boto3

                sts = boto3.client("sts")
                identity = sts.get_caller_identity()
                table.add_row(
                    "AWS Bedrock",
                    "[green]Configured[/green]",
                    f"Account: {identity['Account']}",
                )
            except Exception:
                table.add_row("AWS Bedrock", "[green]Configured[/green]", "-")
        else:
            table.add_row("AWS Bedrock", "[red]Not Configured[/red]", "Run: aws configure")
    except ImportError:
        table.add_row("AWS Bedrock", "[yellow]Not Installed[/yellow]", "pip install boto3")

    # Check Google Gemini
    try:
        from mrzero.core.llm.providers import GoogleGeminiProvider

        gemini = GoogleGeminiProvider()
        if gemini.is_configured():
            table.add_row(
                "Google Gemini",
                "[green]Authenticated[/green]",
                "OAuth token valid",
            )
        else:
            table.add_row(
                "Google Gemini",
                "[red]Not Authenticated[/red]",
                "Run: mrzero auth login",
            )
    except ImportError:
        table.add_row("Google Gemini", "[yellow]Not Installed[/yellow]", "pip install google-auth")

    console.print(table)


@auth_app.command("logout")
def auth_logout(
    provider: str = typer.Option(
        None,
        "--provider",
        "-p",
        help="Provider to logout from (google_gemini)",
    ),
) -> None:
    """Logout from an LLM provider."""
    print_banner()

    if provider == "google_gemini" or provider is None:
        import os

        token_path = os.path.expanduser("~/.mrzero/.mrzero_google_token.json")
        if os.path.exists(token_path):
            if Confirm.ask("Remove Google OAuth token?"):
                os.remove(token_path)
                console.print("[green]Logged out from Google Gemini.[/green]")
        else:
            console.print("[dim]No Google token found.[/dim]")

    if provider == "aws_bedrock":
        console.print("[yellow]AWS credentials are managed by AWS CLI.[/yellow]")
        console.print("Use [cyan]aws configure[/cyan] to manage credentials.")


def _display_config(config: MrZeroConfig) -> None:
    """Display configuration in a formatted table."""
    table = Table(title="Current Configuration", show_header=True, header_style="bold")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row("Data Directory", str(config.data_dir))
    table.add_row("Database Path", str(config.db_path))
    table.add_row("Vector DB Path", str(config.vector_db_path))
    table.add_row("Output Directory", str(config.output_dir))
    table.add_row("", "")
    table.add_row("[bold]LLM Settings[/bold]", "")
    table.add_row("Provider", config.llm.provider)
    table.add_row("Model", config.llm.model or "[dim]Provider Default[/dim]")
    table.add_row("Temperature", str(config.llm.temperature))

    # Provider-specific settings
    if config.llm.provider == "aws_bedrock":
        table.add_row("AWS Region", config.llm.aws_region)
        table.add_row("AWS Profile", config.llm.aws_profile or "[dim]Default[/dim]")
    elif config.llm.provider == "google_gemini":
        table.add_row("Google Project", config.llm.google_project_id or "[dim]Not Set[/dim]")

    table.add_row("", "")
    table.add_row("[bold]Tool Preferences[/bold]", "")
    table.add_row("Disassembly", ", ".join(config.tools.disassembly))
    table.add_row("SAST Tools", ", ".join(config.tools.sast_tools))
    table.add_row("Debugger (Linux)", config.tools.debugger_linux)
    table.add_row("Debugger (Windows)", config.tools.debugger_windows)
    table.add_row("", "")
    table.add_row("[bold]Execution Settings[/bold]", "")
    table.add_row("Max Build Attempts", str(config.max_build_attempts))
    table.add_row("Max Hunter-Verifier Iterations", str(config.hunter_verifier_max_iterations))
    table.add_row("Min True Positives", str(config.min_true_positives))

    console.print(table)


if __name__ == "__main__":
    app()
