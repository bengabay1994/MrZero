# MrZero

**Autonomous AI Bug Bounty CLI** - A local, command-line tool that autonomously analyzes codebases for security vulnerabilities, sets up reproduction environments, and generates weaponized exploits.

```
 __  __       ____               
|  \/  | _ _ |_  / ___  _ _  ___ 
| |\/| || '_| / / / -_)| '_|/ _ \
|_|  |_||_|  /___|\___||_|  \___/

Autonomous AI Bug Bounty CLI
```

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Supported Tools](#supported-tools)
- [CLI Commands](#cli-commands)
- [Examples](#examples)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Safety & Ethics](#safety--ethics)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Multi-Agent Architecture**: Six specialized AI agents working in concert:
  - **MrZeroMapper**: Attack surface analysis and technology fingerprinting
  - **MrZeroVulnHunter**: Static analysis vulnerability detection (SAST)
  - **MrZeroVerifier**: False positive filtering with taint analysis
  - **MrZeroEnvBuilder**: Automated environment setup (Docker/native)
  - **MrZeroExploitBuilder**: Exploit and PoC generation
  - **MrZeroConclusion**: Professional security report generation

- **Dual Execution Modes**:
  - **HITL Mode**: Human-in-the-loop with confirmation prompts (recommended)
  - **YOLO Mode**: Fully autonomous operation

- **Smart Caching**: SQLite-based tool output caching to avoid redundant scans
- **Semantic Code Search**: Vector database (ChromaDB) for RAG-powered code understanding
- **Session Management**: Pause and resume long-running scans
- **MCP Integration**: Connect to external tools via Model Context Protocol

---

## Prerequisites

### Required

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.11+ | 3.12 recommended |
| **UV** | Latest | Package manager (recommended over pip) |
| **LLM Provider** | - | AWS Bedrock or Google Gemini |

### LLM Provider Setup

MrZero requires an LLM provider. Choose one:

#### Option 1: AWS Bedrock (Recommended)

1. Configure AWS credentials:
   ```bash
   # Using AWS CLI
   aws configure
   
   # Or using AWS SSO
   aws configure sso
   aws sso login --profile your-profile
   ```

2. Enable Claude models in [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/)

3. Set environment variables (if not using AWS CLI):
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_REGION="us-east-1"
   ```

#### Option 2: Google Gemini

1. Run MrZero auth command:
   ```bash
   mrzero auth login
   ```
2. Follow the OAuth flow in your browser

---

## Installation

### Using UV (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/MrZero.git
cd MrZero

# Create virtual environment and install
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install with your preferred LLM provider
uv pip install -e ".[aws]"           # For AWS Bedrock
uv pip install -e ".[google]"        # For Google Gemini
uv pip install -e ".[all-providers]" # For all providers

# Verify installation
mrzero --version
```

### Using pip

```bash
git clone https://github.com/yourusername/MrZero.git
cd MrZero
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all-providers]"
```

---

## Getting Started

### 1. First Run - Onboarding

On first run, MrZero will guide you through setup:

```bash
mrzero scan ./your-project --mode hitl
```

This will:
- Check for installed security tools
- Configure your LLM provider
- Save your preferences

### 2. Basic Scan

```bash
# Scan with human confirmation at each step (recommended for first use)
mrzero scan ./target-codebase --mode hitl

# Scan in autonomous mode
mrzero scan ./target-codebase --mode yolo

# Specify output directory
mrzero scan ./target-codebase --output ./reports
```

### 3. Check Tool Status

```bash
# See all available tools
mrzero tools list

# Get detailed status
mrzero tools status
```

### 4. View Results

After a scan completes, find your report at:
- `~/.mrzero/output/security_report_TIMESTAMP.md` (Markdown report)
- `~/.mrzero/output/security_report_TIMESTAMP.json` (JSON data)

---

## Supported Tools

MrZero integrates with various security tools. **None are strictly required**, but having them improves scan quality.

### SAST & Code Analysis

| Tool | Purpose | Install |
|------|---------|---------|
| **Opengrep** | SAST scanner (Semgrep-compatible) | Via Docker (automatic) or [opengrep.dev](https://opengrep.dev) |
| **Gitleaks** | Secret/credential detection | `brew install gitleaks` or [GitHub](https://github.com/gitleaks/gitleaks) |
| **Trivy** | Vulnerability scanner | `brew install trivy` or [aquasecurity.github.io](https://aquasecurity.github.io/trivy) |

### Smart Contract Analysis

| Tool | Purpose | Install |
|------|---------|---------|
| **Slither** | Solidity static analysis | `pip install slither-analyzer` |
| **Mythril** | EVM bytecode analysis | `pip install mythril` |

### Binary Analysis (via MCP)

| Tool | Purpose | Notes |
|------|---------|-------|
| **Ghidra** | Reverse engineering | Requires [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) |
| **IDA Pro** | Disassembler | Requires license + MCP server |
| **Binary Ninja** | Binary analysis | Requires license + MCP server |

### Exploitation Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **pwntools** | Exploit development | `pip install pwntools` |
| **ROPgadget** | ROP chain finder | `pip install ROPgadget` |
| **Frida** | Dynamic instrumentation | `pip install frida-tools` |

### Debugging (via MCP)

| Tool | Purpose | Notes |
|------|---------|-------|
| **pwndbg** | GDB with exploit dev features | Requires [pwndbg-mcp](https://github.com/bengabay1994/pwndbg-mcp) |
| **Metasploit** | Exploitation framework | Requires [MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP) |

### Docker Toolbox

MrZero includes a Docker-based toolbox that provides Opengrep and Linguist without local installation:

```bash
# Check Docker toolbox status
mrzero docker status

# Build the toolbox (first time)
mrzero docker build

# Run Opengrep via Docker
mrzero docker opengrep ./target
```

### MCP Server Installation

Install MCP servers for advanced tooling:

```bash
# List available MCP servers
mrzero mcp list

# Install a server
mrzero mcp install pwndbg
mrzero mcp install metasploit

# Check installation status
mrzero mcp status
```

---

## CLI Commands

### Main Commands

```bash
mrzero scan <target> [OPTIONS]    # Start vulnerability scan
mrzero sessions                   # Manage scan sessions
mrzero config                     # Configuration management
mrzero tools                      # Tool management
mrzero mcp                        # MCP server management
mrzero docker                     # Docker toolbox management
mrzero auth                       # Authentication management
```

### Scan Options

```bash
mrzero scan ./target-repo \
  --mode hitl                    # hitl or yolo
  --output ./reports             # Output directory
  --resume SESSION_ID            # Resume previous session
  --checkpoint-interval 1        # Save checkpoint frequency
```

### Session Management

```bash
mrzero sessions                  # List all sessions
mrzero sessions --delete ID      # Delete a session
mrzero scan ./repo --resume ID   # Resume a session
```

### Tool Commands

```bash
mrzero tools list               # List all known tools
mrzero tools status             # Show unified status
mrzero tools check              # Check tool availability
mrzero tools info <tool>        # Get tool details
```

### MCP Commands

```bash
mrzero mcp list                 # List available MCP servers
mrzero mcp info <server>        # Server details
mrzero mcp install <server>     # Install a server
mrzero mcp uninstall <server>   # Remove a server
mrzero mcp status               # All server statuses
mrzero mcp test <server>        # Test server connection
```

---

## Examples

### Example 1: Scan a Python Web Application

```bash
# Clone a vulnerable test app
git clone https://github.com/example/vulnerable-flask-app
cd vulnerable-flask-app

# Run MrZero scan
mrzero scan . --mode hitl --output ./security-report
```

**Expected Output:**
```
MrZero - Autonomous AI Bug Bounty CLI

[1/6] MrZeroMapper - Analyzing attack surface...
  Languages: Python (95%), HTML (5%)
  Frameworks: Flask, SQLAlchemy
  Endpoints: 12 found (4 unauthenticated)

[2/6] MrZeroVulnHunter - Hunting vulnerabilities...
  Running Opengrep... 8 findings
  Running Gitleaks... 2 secrets found
  LLM Analysis: 6 candidates identified

[3/6] MrZeroVerifier - Filtering false positives...
  Confirmed: 4 vulnerabilities
  False Positives: 2

[4/6] MrZeroEnvBuilder - Setting up environment...
  Docker build: SUCCESS
  Container running on port 5000

[5/6] MrZeroExploitBuilder - Generating exploits...
  SQL Injection (VULN-001): Exploit generated
  Command Injection (VULN-002): Exploit generated

[6/6] MrZeroConclusion - Generating report...

Report saved to: ./security-report/security_report_20260118_143022.md
```

### Example 2: Scan a Smart Contract

```bash
# Scan Solidity contracts
mrzero scan ./contracts --mode hitl

# MrZero will automatically use Slither if available
```

### Example 3: Resume a Long-Running Scan

```bash
# Start a scan (it auto-saves checkpoints)
mrzero scan ./large-codebase --mode yolo

# If interrupted, resume later
mrzero sessions  # Find your session ID
mrzero scan ./large-codebase --resume abc123-session-id
```

### Example 4: Use with MCP Tools

```bash
# Install pwndbg MCP server
mrzero mcp install pwndbg

# Run scan - ExploitBuilder will use pwndbg for binary analysis
mrzero scan ./vulnerable-binary --mode hitl
```

---

## Configuration

### Configuration File

Located at `~/.mrzero/config.json`:

```json
{
  "llm": {
    "provider": "aws_bedrock",
    "model": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    "temperature": 0.1
  },
  "scan": {
    "default_mode": "hitl",
    "checkpoint_interval": 1
  },
  "tools": {
    "prefer_docker": true,
    "sast_tools": ["opengrep", "gitleaks", "trivy"]
  }
}
```

### Interactive Configuration

```bash
mrzero config         # Interactive configuration wizard
mrzero config show    # Display current configuration
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MRZERO_DATA_DIR` | Data directory | `~/.mrzero` |
| `AWS_REGION` | AWS region for Bedrock | `us-east-1` |
| `AWS_PROFILE` | AWS profile name | Default profile |

---

## Architecture

```
                           MrZero Workflow
    
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  Mapper  │───>│  Hunter  │<──>│ Verifier │
    └──────────┘    └──────────┘    └──────────┘
          │              │                │
          │         Feedback Loop (max 3 iterations)
          │              │                │
          │              v                │
          │       ≥3 confirmed vulns?     │
          │              │                │
          │              v                
          │       ┌─────────────┐         
          │       │ EnvBuilder  │         
          │       └─────────────┘         
          │              │                
          │              v                
          │       ┌─────────────┐         
          │       │ExploitBuilder│        
          │       └─────────────┘         
          │              │                
          └──────────────┼────────────────
                         v
                  ┌──────────┐
                  │ Reporter │ ──> security_report.md
                  └──────────┘
```

### Agent Responsibilities

| Agent | Phase | Function |
|-------|-------|----------|
| **Mapper** | Discovery | Fingerprint languages, frameworks, endpoints |
| **Hunter** | Detection | SAST scanning, LLM-powered vulnerability identification |
| **Verifier** | Validation | Taint analysis, false positive elimination |
| **EnvBuilder** | Setup | Docker/harness environment for testing |
| **ExploitBuilder** | Exploitation | Generate PoCs and working exploits |
| **Reporter** | Reporting | Comprehensive security report |

---

## Safety & Ethics

MrZero is designed for **authorized security testing only**.

### Before Using

- Ensure you have **written permission** to test the target
- Use **proper network isolation** when generating RCE exploits
- Understand **responsible disclosure** practices

### Safety Features

- **HITL Mode**: Human confirmation at critical steps
- **Docker Sandboxing**: Targets run in containers when possible
- **No Auto-Upload**: All analysis happens locally

**Never use this tool against systems you don't own or have explicit permission to test.**

---

## Troubleshooting

### Common Issues

#### "No LLM provider configured"
```bash
# For AWS Bedrock
aws configure
# Verify: aws sts get-caller-identity

# For Google Gemini
mrzero auth login
```

#### "Tool X not found"
```bash
# Check tool status
mrzero tools list

# Use Docker toolbox (no local install needed)
mrzero docker build
mrzero docker status
```

#### "MCP server not connected"
```bash
# Install the MCP server
mrzero mcp install <server-name>

# Check its dependencies
mrzero mcp info <server-name>

# Test the connection
mrzero mcp test <server-name>
```

#### "ChromaDB error" or "VectorDB issues"
```bash
# Reinstall with all dependencies
uv pip install -e ".[all-providers]"
```

#### Session Resume Not Working
```bash
# List sessions to find ID
mrzero sessions

# Ensure target path matches original scan
mrzero scan ./same-target-path --resume SESSION_ID
```

### Debug Mode

For verbose output:
```bash
MRZERO_DEBUG=1 mrzero scan ./target --mode hitl
```

---

## Development

```bash
# Setup development environment
git clone https://github.com/yourusername/MrZero.git
cd MrZero
uv venv && source .venv/bin/activate
uv pip install -e ".[dev,all-providers]"

# Run tests
uv run pytest tests/

# Format code
uv run ruff format mrzero
uv run ruff check mrzero --fix

# Type checking
uv run mypy mrzero
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any systems.
