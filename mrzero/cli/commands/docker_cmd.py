"""Docker toolbox CLI commands."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

docker_app = typer.Typer(
    name="docker",
    help="Manage MrZero Docker toolbox",
)
console = Console()


def _get_toolbox_manager():
    """Get the ToolboxManager instance."""
    from mrzero.core.docker.toolbox import ToolboxManager

    return ToolboxManager()


@docker_app.command("pull")
def docker_pull(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force pull even if image exists.",
    ),
) -> None:
    """Pull or update the MrZero toolbox Docker image.

    The toolbox contains SAST and code analysis tools:
    - Opengrep (SAST scanner)
    - Linguist (language detection)
    """
    manager = _get_toolbox_manager()

    # Check Docker availability
    if not manager.is_docker_available():
        console.print(
            "[red]Error:[/red] Docker is not installed or not running.\n"
            "Install Docker: https://docs.docker.com/get-docker/"
        )
        raise typer.Exit(1)

    # Check if already exists
    if manager.is_toolbox_available() and not force:
        console.print(f"[green]Toolbox image already exists:[/green] {manager.image}")
        console.print("[dim]Use --force to pull latest version.[/dim]")
        return

    # Pull the image
    console.print(f"[cyan]Pulling toolbox image:[/cyan] {manager.image}\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Downloading...", total=None)

        def progress_callback(line: str) -> None:
            # Update progress with Docker pull output
            if line.strip():
                progress.update(task, description=f"[cyan]{line[:60]}...")

        success = manager.pull_toolbox(progress_callback)

        if success:
            progress.update(task, description="[green]Download complete!")
        else:
            progress.update(task, description="[red]Download failed!")

    if success:
        console.print("\n[green]Toolbox pulled successfully![/green]")
        console.print("\n[dim]Available tools:[/dim]")
        for tool_name, tool_info in manager.get_available_tools().items():
            console.print(f"  - [cyan]{tool_name}[/cyan]: {tool_info['description']}")
    else:
        console.print("\n[red]Failed to pull toolbox image.[/red]")
        console.print("[dim]Check your internet connection and Docker configuration.[/dim]")
        raise typer.Exit(1)


@docker_app.command("status")
def docker_status() -> None:
    """Show Docker toolbox status and available tools."""
    manager = _get_toolbox_manager()
    status = manager.get_status()

    # Docker status panel
    if status["docker_available"]:
        docker_status_text = "[green]Running[/green]"
    else:
        docker_status_text = "[red]Not Available[/red]"

    if status["toolbox_available"]:
        toolbox_status_text = "[green]Installed[/green]"
    else:
        toolbox_status_text = "[yellow]Not Installed[/yellow]"

    console.print(
        Panel(
            f"[bold]Docker:[/bold] {docker_status_text}\n"
            f"[bold]Toolbox:[/bold] {toolbox_status_text}\n"
            f"[bold]Image:[/bold] {status['image']}",
            title="[bold blue]MrZero Docker Toolbox[/bold blue]",
            border_style="blue",
        )
    )

    # Show error if any
    if "error" in status:
        console.print(f"\n[yellow]Note:[/yellow] {status['error']}")

    # Tools table
    if status["toolbox_available"]:
        console.print("\n[bold]Available Tools:[/bold]")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Tool", style="cyan")
        table.add_column("Description")

        for tool_name in status["tools"]:
            tool_info = manager.get_available_tools().get(tool_name, {})
            table.add_row(tool_name, tool_info.get("description", "-"))

        console.print(table)

        # Image info
        if status.get("image_info"):
            image_info = status["image_info"]
            created = image_info.get("Created", "Unknown")[:19]  # Trim timezone
            size_bytes = image_info.get("Size", 0)
            size_mb = size_bytes / (1024 * 1024)

            console.print(f"\n[dim]Image created: {created}[/dim]")
            console.print(f"[dim]Image size: {size_mb:.1f} MB[/dim]")
    else:
        console.print("\n[dim]Run 'mrzero docker pull' to download the toolbox.[/dim]")


@docker_app.command("test")
def docker_test(
    tool: str = typer.Argument(
        None,
        help="Specific tool to test (opengrep, linguist). Tests all if not specified.",
    ),
) -> None:
    """Test Docker toolbox tools are working correctly."""
    manager = _get_toolbox_manager()

    # Check toolbox availability
    if not manager.is_docker_available():
        console.print(
            "[red]Error:[/red] Docker is not installed or not running.\n"
            "Install Docker: https://docs.docker.com/get-docker/"
        )
        raise typer.Exit(1)

    if not manager.is_toolbox_available():
        console.print("[red]Error:[/red] Toolbox not installed.\nRun 'mrzero docker pull' first.")
        raise typer.Exit(1)

    # Get tools to test
    if tool:
        if tool not in manager.get_available_tools():
            console.print(f"[red]Unknown tool:[/red] {tool}")
            console.print(
                f"[dim]Available: {', '.join(manager.get_available_tools().keys())}[/dim]"
            )
            raise typer.Exit(1)
        tools_to_test = [tool]
    else:
        tools_to_test = list(manager.get_available_tools().keys())

    console.print("[bold]Testing Docker toolbox tools...[/bold]\n")

    all_passed = True

    for tool_name in tools_to_test:
        with console.status(f"[cyan]Testing {tool_name}...[/cyan]"):
            # Run version command for each tool
            tool_info = manager.get_available_tools()[tool_name]
            version_cmd = tool_info.get("version_cmd", [tool_name, "--version"])

            result = manager.client.run_container(
                image=manager.image,
                command=version_cmd,
                timeout=30,
            )

            if result.success:
                version_output = result.stdout.strip().split("\n")[0][:60]
                console.print(f"  [green]PASS[/green] {tool_name}: {version_output}")
            else:
                console.print(f"  [red]FAIL[/red] {tool_name}: {result.stderr[:60]}")
                all_passed = False

    console.print()
    if all_passed:
        console.print("[green]All tools passed![/green]")
    else:
        console.print("[red]Some tools failed. Check Docker logs for details.[/red]")
        raise typer.Exit(1)


@docker_app.command("remove")
def docker_remove(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force remove without confirmation.",
    ),
) -> None:
    """Remove the MrZero toolbox Docker image."""
    from rich.prompt import Confirm

    manager = _get_toolbox_manager()

    if not manager.is_toolbox_available():
        console.print("[dim]Toolbox image not found. Nothing to remove.[/dim]")
        return

    if not force:
        if not Confirm.ask(f"Remove toolbox image '{manager.image}'?"):
            console.print("[dim]Cancelled.[/dim]")
            return

    if manager.client.remove_image(manager.image, force=True):
        console.print("[green]Toolbox image removed.[/green]")
    else:
        console.print("[red]Failed to remove toolbox image.[/red]")
        raise typer.Exit(1)
