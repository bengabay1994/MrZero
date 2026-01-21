"""MCP (Model Context Protocol) CLI commands."""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

mcp_app = typer.Typer(
    name="mcp",
    help="Manage MCP (Model Context Protocol) servers",
)
console = Console()


def _get_registry():
    """Get the MCP registry."""
    from mrzero.core.mcp.registry import get_mcp_registry

    return get_mcp_registry()


def _get_installer():
    """Get the MCP installer."""
    from mrzero.core.mcp.installer import get_mcp_installer

    return get_mcp_installer()


@mcp_app.command("list")
def mcp_list(
    category: str = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (reverse_engineering, debugging, exploitation, dynamic_analysis)",
    ),
    installed_only: bool = typer.Option(
        False,
        "--installed",
        "-i",
        help="Only show installed servers",
    ),
) -> None:
    """List available MCP servers."""
    registry = _get_registry()
    installer = _get_installer()

    if category:
        servers = registry.get_servers_by_category(category)
        if not servers:
            console.print(f"[yellow]No servers in category: {category}[/yellow]")
            console.print(
                "[dim]Available categories: reverse_engineering, debugging, exploitation, dynamic_analysis[/dim]"
            )
            return
    else:
        servers = registry.get_compatible_servers()

    if installed_only:
        servers = [s for s in servers if installer.is_installed(s.name)]

    if not servers:
        console.print("[dim]No MCP servers found.[/dim]")
        return

    table = Table(title="MCP Servers", show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Status")
    table.add_column("Description")
    table.add_column("Requirements")

    for server in servers:
        # Check installation status
        if installer.is_installed(server.name):
            status = "[green]Installed[/green]"
        else:
            status = "[dim]Not Installed[/dim]"

        # Format requirements
        reqs = ", ".join(server.requires) if server.requires else "-"

        table.add_row(
            server.name,
            status,
            server.description[:50] + "..." if len(server.description) > 50 else server.description,
            reqs,
        )

    console.print(table)
    console.print()
    console.print("[dim]Use 'mrzero mcp install <name>' to install a server.[/dim]")


@mcp_app.command("info")
def mcp_info(
    server_name: str = typer.Argument(..., help="Name of the MCP server"),
) -> None:
    """Show detailed information about an MCP server."""
    registry = _get_registry()
    installer = _get_installer()

    server = registry.get_server(server_name)
    if server is None:
        console.print(f"[red]Unknown server:[/red] {server_name}")
        console.print(f"[dim]Available servers: {', '.join(registry.list_server_names())}[/dim]")
        raise typer.Exit(1)

    # Installation status
    if installer.is_installed(server_name):
        status = "[green]Installed[/green]"
        install_path = installer.get_install_path(server_name)
    else:
        status = "[yellow]Not Installed[/yellow]"
        install_path = None

    # Requirements check
    requirements = installer.check_requirements(server_name)

    console.print(
        Panel(
            f"[bold]Name:[/bold] {server.name}\n"
            f"[bold]Status:[/bold] {status}\n"
            f"[bold]Description:[/bold] {server.description}\n"
            f"[bold]Repository:[/bold] {server.repo_url}\n"
            f"[bold]Type:[/bold] {server.server_type.value}\n"
            f"[bold]Platforms:[/bold] {', '.join(server.platforms)}",
            title=f"[bold blue]MCP Server: {server.name}[/bold blue]",
            border_style="blue",
        )
    )

    if install_path:
        console.print(f"\n[bold]Install Path:[/bold] {install_path}")

    if server.docs_url:
        console.print(f"[bold]Documentation:[/bold] {server.docs_url}")

    # Requirements table
    if requirements:
        console.print("\n[bold]Requirements:[/bold]")
        for req, available in requirements.items():
            status_icon = "[green]OK[/green]" if available else "[red]Missing[/red]"
            console.print(f"  {req}: {status_icon}")

    # Environment variables
    if server.env:
        console.print("\n[bold]Environment Variables:[/bold]")
        for key, default in server.env.items():
            console.print(f"  {key}={default or '[not set]'}")


@mcp_app.command("install")
def mcp_install(
    server_name: str = typer.Argument(..., help="Name of the MCP server to install"),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force reinstall even if already installed",
    ),
) -> None:
    """Install an MCP server."""
    registry = _get_registry()
    installer = _get_installer()

    server = registry.get_server(server_name)
    if server is None:
        console.print(f"[red]Unknown server:[/red] {server_name}")
        console.print(f"[dim]Available servers: {', '.join(registry.list_server_names())}[/dim]")
        raise typer.Exit(1)

    # Check if already installed
    if installer.is_installed(server_name) and not force:
        console.print(f"[green]{server_name} is already installed.[/green]")
        console.print("[dim]Use --force to reinstall.[/dim]")
        return

    # Check platform compatibility
    if sys.platform not in server.platforms:
        console.print(f"[red]Error:[/red] {server_name} is not compatible with {sys.platform}")
        console.print(f"[dim]Supported platforms: {', '.join(server.platforms)}[/dim]")
        raise typer.Exit(1)

    # Check requirements
    requirements = installer.check_requirements(server_name)
    missing = [req for req, available in requirements.items() if not available]
    if missing:
        console.print(f"[yellow]Warning:[/yellow] Missing requirements: {', '.join(missing)}")
        console.print("[dim]The server may not function without these dependencies.[/dim]")

    # Install
    console.print(f"[cyan]Installing {server_name}...[/cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Installing...", total=None)

        def progress_callback(msg: str) -> None:
            progress.update(task, description=f"[cyan]{msg[:60]}")

        result = installer.install(server_name, progress_callback)

        if result.success:
            progress.update(task, description="[green]Installation complete!")
        else:
            progress.update(task, description="[red]Installation failed!")

    console.print()

    if result.success:
        console.print(f"[green]Successfully installed {server_name}![/green]")
        console.print(f"[dim]Location: {result.install_path}[/dim]")
    else:
        console.print(f"[red]Failed to install {server_name}[/red]")
        if result.error:
            console.print(f"[dim]Error: {result.error}[/dim]")
        raise typer.Exit(1)


@mcp_app.command("uninstall")
def mcp_uninstall(
    server_name: str = typer.Argument(..., help="Name of the MCP server to uninstall"),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force uninstall without confirmation",
    ),
) -> None:
    """Uninstall an MCP server."""
    from rich.prompt import Confirm

    installer = _get_installer()

    if not installer.is_installed(server_name):
        console.print(f"[dim]{server_name} is not installed.[/dim]")
        return

    if not force:
        if not Confirm.ask(f"Uninstall {server_name}?"):
            console.print("[dim]Cancelled.[/dim]")
            return

    if installer.uninstall(server_name):
        console.print(f"[green]Successfully uninstalled {server_name}.[/green]")
    else:
        console.print(f"[red]Failed to uninstall {server_name}.[/red]")
        raise typer.Exit(1)


@mcp_app.command("status")
def mcp_status() -> None:
    """Show status of all MCP servers and their dependencies."""
    registry = _get_registry()
    installer = _get_installer()

    servers = registry.get_compatible_servers()

    console.print(
        Panel(
            f"[bold]Platform:[/bold] {sys.platform}\n"
            f"[bold]Compatible Servers:[/bold] {len(servers)}\n"
            f"[bold]Install Directory:[/bold] {installer.base_dir}",
            title="[bold blue]MCP Status[/bold blue]",
            border_style="blue",
        )
    )

    # Servers table
    table = Table(title="Server Status", show_header=True, header_style="bold")
    table.add_column("Server", style="cyan")
    table.add_column("Installed")
    table.add_column("Requirements")

    for server in servers:
        installed = installer.is_installed(server.name)
        installed_text = "[green]Yes[/green]" if installed else "[dim]No[/dim]"

        # Check requirements
        requirements = installer.check_requirements(server.name)
        if not requirements:
            req_text = "[dim]-[/dim]"
        elif all(requirements.values()):
            req_text = "[green]All met[/green]"
        else:
            missing = [r for r, ok in requirements.items() if not ok]
            req_text = f"[yellow]Missing: {', '.join(missing)}[/yellow]"

        table.add_row(server.name, installed_text, req_text)

    console.print(table)


@mcp_app.command("test")
def mcp_test(
    server_name: str = typer.Argument(..., help="Name of the MCP server to test"),
) -> None:
    """Test an installed MCP server connection."""
    import asyncio

    registry = _get_registry()
    installer = _get_installer()

    server = registry.get_server(server_name)
    if server is None:
        console.print(f"[red]Unknown server:[/red] {server_name}")
        raise typer.Exit(1)

    if not installer.is_installed(server_name):
        console.print(f"[red]Error:[/red] {server_name} is not installed.")
        console.print("[dim]Run 'mrzero mcp install {server_name}' first.[/dim]")
        raise typer.Exit(1)

    console.print(f"[cyan]Testing {server_name}...[/cyan]\n")

    async def _test_server() -> bool:
        from mrzero.core.mcp.client import MCPServerConnection

        install_path = installer.get_install_path(server_name)
        cmd = installer.get_server_command(server_name)

        if cmd is None:
            console.print("[red]Could not determine server command.[/red]")
            return False

        console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")
        console.print(f"[dim]Working directory: {install_path}[/dim]")

        connection = MCPServerConnection(
            name=server_name,
            command=cmd,
            env=server.get_env(),
            cwd=install_path,
        )

        try:
            # Try to connect
            console.print("\n[cyan]Connecting...[/cyan]")
            success = await connection.connect()

            if not success:
                console.print("[red]Failed to start server process.[/red]")
                return False

            console.print("[green]Process started.[/green]")

            # List tools
            console.print("\n[cyan]Listing available tools...[/cyan]")
            tools = await connection.list_tools()

            console.print(f"[green]Found {len(tools)} tools:[/green]")
            for tool in tools[:10]:  # Show first 10
                tool_name = tool.get("name", "unknown")
                console.print(f"  - {tool_name}")
            if len(tools) > 10:
                console.print(f"  ... and {len(tools) - 10} more")

            return True

        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            return False

        finally:
            await connection.disconnect()

    success = asyncio.run(_test_server())

    if success:
        console.print("\n[green]Server test passed![/green]")
    else:
        console.print("\n[red]Server test failed.[/red]")
        raise typer.Exit(1)


@mcp_app.command("check")
def mcp_check() -> None:
    """Check for all MCP server requirements."""
    registry = _get_registry()
    installer = _get_installer()

    console.print("[bold]Checking MCP server requirements...[/bold]\n")

    # Collect all unique requirements
    all_requirements: dict[str, list[str]] = {}  # requirement -> list of servers

    for server in registry.list_servers():
        for req in server.requires:
            if req not in all_requirements:
                all_requirements[req] = []
            all_requirements[req].append(server.name)

    # Check each requirement
    table = Table(title="External Dependencies", show_header=True, header_style="bold")
    table.add_column("Dependency", style="cyan")
    table.add_column("Status")
    table.add_column("Required By")

    for req, servers in sorted(all_requirements.items()):
        # Check if available
        available = installer._check_requirement(req)
        status = "[green]Available[/green]" if available else "[red]Not Found[/red]"
        servers_text = ", ".join(servers[:3])
        if len(servers) > 3:
            servers_text += f" (+{len(servers) - 3})"

        table.add_row(req, status, servers_text)

    console.print(table)

    # Summary
    available_count = sum(1 for req in all_requirements if installer._check_requirement(req))
    total_count = len(all_requirements)

    console.print(f"\n[bold]Summary:[/bold] {available_count}/{total_count} dependencies available")

    if available_count < total_count:
        console.print("\n[dim]Some MCP servers may not work without their dependencies.[/dim]")
