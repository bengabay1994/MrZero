"""Unified tools CLI commands.

This module provides CLI commands for viewing status of all tool backends:
- Docker toolbox tools
- MCP server tools
- Local system tools
"""

import asyncio
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

tools_app = typer.Typer(
    name="tools",
    help="View and manage all security tools",
)
console = Console()


def _run_async(coro):
    """Run an async coroutine synchronously."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


async def _get_tools_service():
    """Get initialized ToolsService."""
    from mrzero.core.tools_service import get_initialized_tools_service

    return await get_initialized_tools_service()


@tools_app.command("list")
def tools_list(
    category: str = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (sast, secret_detection, binary_analysis, etc.)",
    ),
    available_only: bool = typer.Option(
        False,
        "--available",
        "-a",
        help="Show only available tools.",
    ),
) -> None:
    """List all known security tools and their status.

    Shows tools across all backends (Docker, MCP, Local) with their
    availability status.
    """
    try:
        service = _run_async(_get_tools_service())
    except Exception as e:
        console.print(f"[red]Error initializing tools service:[/red] {e}")
        raise typer.Exit(1)

    # Get all tools
    all_tools = list(service._tools.values())

    # Filter by category if specified
    if category:
        from mrzero.core.tools_service import ToolCategory

        try:
            cat_enum = ToolCategory(category.lower())
            all_tools = [t for t in all_tools if t.category == cat_enum]
        except ValueError:
            valid_categories = [c.value for c in ToolCategory]
            console.print(f"[red]Invalid category:[/red] {category}")
            console.print(f"[dim]Valid categories: {', '.join(valid_categories)}[/dim]")
            raise typer.Exit(1)

    # Filter available only
    if available_only:
        all_tools = [t for t in all_tools if t.available]

    if not all_tools:
        console.print("[yellow]No tools found matching criteria.[/yellow]")
        return

    # Create table
    table = Table(title="Security Tools", show_header=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Category", style="blue")
    table.add_column("Backend", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Description")

    # Sort by category then name
    all_tools.sort(key=lambda t: (t.category.value, t.name))

    for tool in all_tools:
        status = "[green]Available[/green]" if tool.available else "[red]Not Available[/red]"
        table.add_row(
            tool.name,
            tool.category.value,
            tool.backend.value,
            status,
            tool.description[:50] + "..." if len(tool.description) > 50 else tool.description,
        )

    console.print(table)

    # Summary
    available_count = sum(1 for t in all_tools if t.available)
    console.print(f"\n[dim]Showing {len(all_tools)} tools ({available_count} available)[/dim]")


@tools_app.command("status")
def tools_status() -> None:
    """Show unified status of all tool backends.

    Displays status for:
    - Docker toolbox (Opengrep, Linguist)
    - MCP servers (Ghidra, pwndbg, Metasploit, etc.)
    - Local tools (gitleaks, trivy, slither, etc.)
    """
    try:
        service = _run_async(_get_tools_service())
    except Exception as e:
        console.print(f"[red]Error initializing tools service:[/red] {e}")
        raise typer.Exit(1)

    status = service.get_status()

    # === Docker Backend ===
    docker_info = status["backends"]["docker"]
    if docker_info["available"]:
        docker_status = "[green]Running[/green]"
        if docker_info["toolbox_ready"]:
            toolbox_status = "[green]Ready[/green]"
        else:
            toolbox_status = "[yellow]Not Pulled[/yellow] (run 'mrzero docker pull')"
    else:
        docker_status = "[red]Not Available[/red]"
        toolbox_status = "[dim]N/A[/dim]"

    docker_panel = Panel(
        f"Docker: {docker_status}\nToolbox: {toolbox_status}",
        title="[cyan]Docker Backend[/cyan]",
        border_style="cyan",
    )
    console.print(docker_panel)

    # === MCP Backend ===
    mcp_info = status["backends"]["mcp"]
    if mcp_info["available"]:
        mcp_status = "[green]Available[/green]"
        connected = mcp_info["connected_servers"]
        if connected:
            servers_text = f"Connected: [green]{', '.join(connected)}[/green]"
        else:
            servers_text = "[dim]No servers connected[/dim]"
    else:
        mcp_status = "[red]Not Available[/red]"
        servers_text = "[dim]N/A[/dim]"

    mcp_panel = Panel(
        f"Status: {mcp_status}\n{servers_text}\n\n[dim]Use 'mrzero mcp list' for available servers[/dim]",
        title="[magenta]MCP Backend[/magenta]",
        border_style="magenta",
    )
    console.print(mcp_panel)

    # === Local Backend ===
    local_panel = Panel(
        f"Status: [green]Available[/green]\n[dim]Local tools run directly via subprocess[/dim]",
        title="[blue]Local Backend[/blue]",
        border_style="blue",
    )
    console.print(local_panel)

    # === Tools Summary ===
    tools_info = status["tools"]
    total = tools_info["total"]
    available = tools_info["available"]
    by_category = tools_info.get("by_category", {})

    summary_lines = [
        f"Total: {total} | Available: [green]{available}[/green] | Unavailable: [red]{total - available}[/red]",
        "",
        "[dim]By Category:[/dim]",
    ]

    for cat, count in sorted(by_category.items()):
        summary_lines.append(f"  {cat}: {count}")

    tools_panel = Panel(
        "\n".join(summary_lines),
        title="[yellow]Tools Summary[/yellow]",
        border_style="yellow",
    )
    console.print(tools_panel)


@tools_app.command("check")
def tools_check(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed information for each tool.",
    ),
) -> None:
    """Check availability of all tools.

    Performs a comprehensive check of all tools and shows which are
    ready to use.
    """
    try:
        service = _run_async(_get_tools_service())
    except Exception as e:
        console.print(f"[red]Error initializing tools service:[/red] {e}")
        raise typer.Exit(1)

    console.print("[cyan]Checking tool availability...[/cyan]\n")

    # Group tools by category
    from mrzero.core.tools_service import ToolCategory

    categories: dict[ToolCategory, list] = {}
    for tool in service._tools.values():
        if tool.category not in categories:
            categories[tool.category] = []
        categories[tool.category].append(tool)

    total_available = 0
    total_tools = 0

    for category in sorted(categories.keys(), key=lambda c: c.value):
        tools = categories[category]
        tools.sort(key=lambda t: t.name)

        console.print(f"[bold]{category.value.upper()}[/bold]")

        for tool in tools:
            total_tools += 1
            if tool.available:
                total_available += 1
                status_icon = "[green]✓[/green]"
                status_text = ""
            else:
                status_icon = "[red]✗[/red]"
                # Provide helpful hints
                if tool.backend.value == "mcp":
                    status_text = f" [dim](MCP server not connected)[/dim]"
                elif tool.backend.value == "docker":
                    status_text = f" [dim](run 'mrzero docker pull')[/dim]"
                else:
                    status_text = f" [dim](not installed)[/dim]"

            line = f"  {status_icon} {tool.name}{status_text}"
            if verbose and tool.available:
                line += f" [dim]({tool.backend.value})[/dim]"
            console.print(line)

        console.print()

    # Summary
    if total_available == total_tools:
        summary_style = "green"
        summary_text = "All tools available!"
    elif total_available == 0:
        summary_style = "red"
        summary_text = "No tools available!"
    else:
        summary_style = "yellow"
        summary_text = f"{total_available}/{total_tools} tools available"

    console.print(f"[bold {summary_style}]{summary_text}[/bold {summary_style}]")

    # Suggestions
    if total_available < total_tools:
        console.print("\n[dim]To get more tools:[/dim]")
        if not service._docker_toolbox or not service._docker_toolbox.is_toolbox_available():
            console.print("  - Run 'mrzero docker pull' for Opengrep/Linguist")
        console.print("  - Run 'mrzero mcp install <server>' for MCP tools")
        console.print("  - Install local tools: gitleaks, trivy, slither, etc.")


@tools_app.command("info")
def tools_info(
    tool_name: str = typer.Argument(..., help="Name of the tool to show info for."),
) -> None:
    """Show detailed information about a specific tool.

    Examples:
        mrzero tools info opengrep
        mrzero tools info ghidra
    """
    try:
        service = _run_async(_get_tools_service())
    except Exception as e:
        console.print(f"[red]Error initializing tools service:[/red] {e}")
        raise typer.Exit(1)

    tool = service.get_tool(tool_name)

    if tool is None:
        console.print(f"[red]Tool not found:[/red] {tool_name}")
        console.print("\n[dim]Use 'mrzero tools list' to see available tools.[/dim]")
        raise typer.Exit(1)

    # Create info panel
    status = "[green]Available[/green]" if tool.available else "[red]Not Available[/red]"

    info_lines = [
        f"[bold]Name:[/bold] {tool.name}",
        f"[bold]Description:[/bold] {tool.description}",
        f"[bold]Category:[/bold] {tool.category.value}",
        f"[bold]Backend:[/bold] {tool.backend.value}",
        f"[bold]Status:[/bold] {status}",
    ]

    # Add backend-specific info
    if tool.mcp_server:
        info_lines.append(f"[bold]MCP Server:[/bold] {tool.mcp_server}")
    if tool.docker_image:
        info_lines.append(f"[bold]Docker Image:[/bold] {tool.docker_image}")
    if tool.binary_name:
        info_lines.append(f"[bold]Binary:[/bold] {tool.binary_name}")

    panel = Panel(
        "\n".join(info_lines),
        title=f"[cyan]{tool.name}[/cyan]",
        border_style="cyan",
    )
    console.print(panel)

    # Usage hints
    if not tool.available:
        console.print("\n[yellow]How to enable this tool:[/yellow]")
        if tool.backend.value == "docker":
            console.print("  Run: mrzero docker pull")
        elif tool.backend.value == "mcp":
            console.print(f"  Run: mrzero mcp install {tool.mcp_server}")
        elif tool.backend.value == "local":
            console.print(f"  Install '{tool.binary_name}' on your system")
        elif tool.backend.value == "hybrid":
            console.print("  Either:")
            console.print("    - Run: mrzero docker pull")
            console.print(f"    - Or install '{tool.binary_name}' locally")
