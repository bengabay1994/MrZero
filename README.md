# MrZero - AI-Powered Security Research Agents

MrZero is a collection of specialized AI agents for vulnerability research, attack surface mapping, and exploit development on open-source projects. It integrates with Claude Code and OpenCode to provide AI-assisted security analysis.

## Features

- **4 Specialized Security Agents** - Purpose-built AI personas for different security tasks
- **Docker-Wrapped Security Tools** - Consistent, isolated tooling via transparent CLI wrappers
- **MCP Server Integration** - Connect AI to debugging and reverse engineering tools
- **One-Command Installation** - Automated setup for Claude Code and OpenCode

## Available Agents

| Agent | Description |
|-------|-------------|
| **MrZeroMapperOS** | Attack surface mapping and analysis - identifies entry points and attack vectors |
| **MrZeroVulnHunterOS** | Vulnerability hunting - finds critical security bugs using multiple analysis tools |
| **MrZeroExploitDeveloper** | Exploit development - builds and tests working exploits with debugging support |
| **MrZeroEnvBuilder** | Environment setup - creates reproducible test environments for vulnerabilities |

## Prerequisites

### Required

- **Linux or macOS** (Ubuntu 20.04+ / macOS 12+ recommended)
- **Docker** - for containerized security tools
- **Node.js 18+** - for the installer (`npx`)
- **Python 3.10+** - for Python-based tools
- **uv** - fast Python package manager

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Optional (for MrZeroExploitDeveloper)

- **GDB + pwndbg** - for binary exploitation and debugging
- **Ghidra** - for reverse engineering
- **Metasploit Framework** - for exploitation modules
- **IDA Pro** - commercial disassembler (auto-detected if installed)
- **Burp Suite** - web security testing proxy (Community or Professional edition)

## Quick Install

```bash
npx @bengabay94/mrzero install
```

The installer will:
1. Detect your system configuration and existing tools
2. Let you select which agents to install
3. Let you choose target platforms (Claude Code / OpenCode)
4. Install required tools (Docker image, Python packages, MCP servers)
5. Configure your AI platforms automatically

### Non-Interactive Installation

```bash
# Install all agents for both platforms
npx @bengabay94/mrzero install --yes

# Install specific agents
npx @bengabay94/mrzero install --agent MrZeroMapperOS --agent MrZeroVulnHunterOS

# Install for a specific platform
npx @bengabay94/mrzero install --platform claude-code
```

## Post-Installation Setup

Some tools require manual setup steps.

### GhidraMCP (for Ghidra integration)

The installer downloads GhidraMCP but Ghidra extensions must be installed manually:

1. Open Ghidra
2. Go to **File** → **Install Extensions**
3. Click the **+** button
4. Select `~/.mrzero/mcp-servers/GhidraMCP/GhidraMCP-extension.zip`
5. Restart Ghidra
6. Enable the plugin: **File** → **Configure** → **Developer** → Enable **GhidraMCPPlugin**

### MetasploitMCP (for Metasploit integration)

Before using Metasploit features, start the RPC daemon:

```bash
# Start with default MrZero password
msfrpcd -P mrzero -S -a 127.0.0.1 -p 55553
```

To use a different password, update the `MSF_PASSWORD` environment variable in your platform configuration.

### Burp Suite MCP (for web application testing)

The Burp Suite MCP server is **not installed by MrZero** - you must install it manually in Burp Suite:

1. Open **Burp Suite** (Community or Professional edition)
2. Go to the **Extensions** tab
3. Click **BApp Store**
4. Search for **"MCP Server"** and click **Install**
5. Go to the **MCP** tab and ensure the server is enabled (default: `http://127.0.0.1:9876`)

Once installed, MrZero will automatically configure your AI platform (OpenCode/Claude Code) to connect to the Burp Suite MCP server when you select it during `mrzero install`.

> **Important:** Burp Suite must be running with the MCP Server extension loaded whenever you use MrZeroExploitDeveloper for web application targets.

For more details, see the [official BApp Store page](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc) and the [source code](https://github.com/PortSwigger/mcp-server).

## Usage

### With Claude Code

Launch Claude Code through MrZero to enable the security tools:

```bash
mrzero claude
```

The agents are available globally and can use all MrZero tools.

**Switch agents:** Press `Tab` to cycle through available agents

**Invoke by name:**
```
@MrZeroMapperOS analyze the attack surface of this repository
```

### With OpenCode

Launch OpenCode through MrZero to enable the security tools:

```bash
mrzero opencode
```

The agents are configured automatically and can use all MrZero tools.

**Switch agents:** Press `Tab` to cycle through agents

**Invoke by name:**
```
@MrZeroVulnHunterOS find vulnerabilities in this codebase
```

> **Note:** When using OpenCode's interactive bash mode (the `!` prefix), the MrZero tools
> may not be visible in your PATH. However, the AI agents have full access to all tools
> when they execute bash commands. If you need to run a tool manually in bash mode,
> use the full path: `~/.local/bin/mrzero-tools/<tool-name>`

## Verify Installation

Check what's installed:

```bash
npx @bengabay94/mrzero check
```

## Uninstall

Remove MrZero and all installed tools:

```bash
npx @bengabay94/mrzero uninstall
```

Options:
- `--keep-agents` - Keep agent files in platform configs
- `--keep-docker` - Keep the Docker image

## Tools Reference

### Docker-Wrapped CLI Tools

These tools run in a Docker container but are accessible via transparent shell wrappers:

| Tool | Description |
|------|-------------|
| `opengrep` | Pattern-based code analysis (Semgrep fork) |
| `gitleaks` | Secrets and credential scanning |
| `codeql` | Semantic code analysis and taint tracking |
| `joern` | Code property graph analysis |
| `infer` | Memory safety static analysis (Facebook) |
| `bearer` | Security and privacy scanning |
| `slither` | Solidity smart contract analysis |
| `trivy` | Dependency and container CVE scanning |
| `linguist` | Language detection |

### Native Python Tools (via uv)

| Tool | Description |
|------|-------------|
| `pwntools` | CTF framework and exploit development library |
| `ropper` | ROP gadget finder |
| `ropgadget` | ROP gadget finder (bundled with pwntools) |

### Native Ruby Tools

| Tool | Description |
|------|-------------|
| `one_gadget` | Find one-shot RCE gadgets in libc |

### MCP Servers

| Server | Tool | Description |
|--------|------|-------------|
| `pwndbg-mcp` | GDB + pwndbg | Binary debugging and exploitation |
| `ghidra-mcp` | Ghidra | Reverse engineering |
| `metasploit-mcp` | Metasploit | Exploitation framework |
| `ida-pro-mcp` | IDA Pro | Disassembly (if IDA Pro detected) |
| `burpsuite-mcp` | Burp Suite | Web security testing (user-managed, see [setup](#burp-suite-mcp-for-web-application-testing)) |

## Directory Structure

MrZero stores its files in `~/.mrzero/`:

```
~/.mrzero/
├── mcp-servers/           # Cloned MCP server repositories
│   ├── pwndbg-mcp/
│   ├── GhidraMCP/
│   └── MetasploitMCP/
```

CLI wrappers are installed to `~/.local/bin/` (ensure this is in your PATH).

Agent files are copied to:
- Claude Code: `~/.claude/agents/`
- OpenCode: `~/.config/opencode/agents/`

## Troubleshooting

### Docker wrapper commands not found

Ensure `~/.local/bin` is in your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Add this line to your `~/.bashrc` or `~/.zshrc`.

### MCP servers not connecting

Restart your AI platform (Claude Code / OpenCode) after installation.

### pwndbg not detected

If you installed pwndbg via `.gdbinit`, the installer should detect it. Ensure your `.gdbinit` contains:

```
source /path/to/pwndbg/gdbinit.py
```

### Docker image build fails

Some tools require significant memory to build. Ensure Docker has at least 4GB of memory allocated.

Alternatively, wait for the pre-built image to be available:

```bash
docker pull ghcr.io/bengabay1994/mrzero-tools:latest
```

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgements

- [pwndbg](https://github.com/pwndbg/pwndbg) - GDB plugin for exploit development
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) - MCP server for Ghidra
- [MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP) - MCP server for Metasploit
- [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) - MCP server for IDA Pro
- [Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server) - MCP server for Burp Suite by PortSwigger
- All the security tools integrated in this project
