# MrZero

**Autonomous AI Bug Bounty CLI** - A local, command-line tool that autonomously analyzes codebases for security vulnerabilities, sets up reproduction environments, and generates weaponized exploits.

```
  __  __     _____                
 |  \/  |   |__  /__ _ _ __ ___   
 | |\/| |r    / // _ \ '__/ _ \  
 | |  | |   / /|  __/ | | (_) | 
 |_|  |_|  /____\___|_|  \___/  

Autonomous AI Bug Bounty CLI
```

## Features

- **Multi-Agent Architecture**: Six specialized AI agents working in concert
  - **MrZeroMapper**: Attack surface analysis and technology fingerprinting
  - **MrZeroVulnHunter**: Static analysis vulnerability detection (SAST)
  - **MrZeroVerifier**: False positive filtering with taint analysis
  - **MrZeroEnvBuilder**: Automated environment setup (Docker/native)
  - **MrZeroExploitBuilder**: Exploit and PoC generation
  - **MrZeroConclusion**: Professional security report generation

- **Dual Execution Modes**:
  - **YOLO Mode**: Fully autonomous operation
  - **HITL Mode**: Human-in-the-loop with confirmation prompts

- **Smart Caching**: SQLite-based tool output caching to avoid redundant scans

- **Semantic Code Search**: Vector database (ChromaDB) for RAG-powered code understanding

- **Session Management**: Pause and resume long-running scans

## Supported LLM Providers

MrZero currently supports two LLM providers:

| Provider | Authentication | Models |
|----------|----------------|--------|
| **AWS Bedrock** | AWS credentials (IAM/SSO) | Claude 3.5, Nova, Llama 3.1 |
| **Google Gemini** | OAuth (browser-based) | Gemini 2.0, 1.5 Pro/Flash |

## Prerequisites

- **Python 3.11+**
- **uv** (recommended) or pip
- One of the supported LLM providers configured

### Optional Security Tools

For enhanced scanning, install these tools:

- [Semgrep](https://semgrep.dev/) - Static analysis
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection
- [Trivy](https://trivy.dev/) - Vulnerability scanner
- [Slither](https://github.com/crytic/slither) - Solidity analyzer (for smart contracts)

## Installation

### Using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/MrZero.git
cd MrZero

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with your preferred LLM provider
uv pip install -e ".[aws]"      # For AWS Bedrock
uv pip install -e ".[google]"   # For Google Gemini
uv pip install -e ".[all-providers]"  # For all providers

# Install development dependencies (optional)
uv pip install -e ".[dev]"
```

### Using pip

```bash
# Clone the repository
git clone https://github.com/yourusername/MrZero.git
cd MrZero

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install
pip install -e ".[all-providers]"
```

## Authentication Setup

### Option 1: AWS Bedrock

AWS Bedrock requires AWS credentials. You can configure them in several ways:

#### Using AWS CLI

```bash
# Configure AWS credentials
aws configure

# Or use AWS SSO
aws configure sso
aws sso login --profile your-profile
```

#### Using Environment Variables

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"  # or your preferred region

# Optional: specify a profile
export AWS_PROFILE="your-profile"
```

#### Enable Bedrock Models

Make sure you have enabled the models you want to use in the [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/).

### Option 2: Google Gemini (OAuth)

Google Gemini uses OAuth authentication similar to [gemini-cli](https://github.com/google-gemini/gemini-cli):

```bash
# Authenticate with Google
mrzero auth login

# Select Google Gemini when prompted
# A browser window will open for OAuth consent
```

This will:
1. Open your browser for Google OAuth consent
2. Create a local token file at `~/.mrzero/.mrzero_google_token.json`
3. Automatically refresh tokens as needed

## Configuration

Create a configuration file at `~/.mrzero/config.json`:

```json
{
  "llm": {
    "provider": "aws_bedrock",
    "model": "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "temperature": 0.1
  },
  "tools": {
    "disassembly": ["ghidra", "ida", "binaryninja"],
    "sast_tools": ["semgrep", "gitleaks", "trivy"]
  }
}
```

Or configure interactively:

```bash
mrzero config
```

## Usage

### Basic Scan

```bash
# Scan a codebase in HITL (human-in-the-loop) mode
mrzero scan ./target_repo --mode hitl

# Scan in YOLO (autonomous) mode
mrzero scan ./target_repo --mode yolo

# Specify output directory
mrzero scan ./target_repo --output ./reports
```

### Check Installed Tools

```bash
mrzero tools
```

### Manage Sessions

```bash
# List saved sessions
mrzero sessions

# Resume a paused session
mrzero scan ./target_repo --resume SESSION_ID

# Delete a session
mrzero sessions --delete SESSION_ID
```

### Authentication

```bash
# Login with Google OAuth (for Gemini)
mrzero auth login

# Check authentication status
mrzero auth status

# Logout
mrzero auth logout
```

## Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                      MrZero Workflow                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  Mapper  │───▶│  Hunter  │◀──▶│ Verifier │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       │              │                │                     │
│       │         Feedback Loop (max 3 iterations)           │
│       │              │                │                     │
│       │              ▼                │                     │
│       │         ≥3 confirmed vulns?   │                     │
│       │              │                │                     │
│       │              ▼                                      │
│       │       ┌─────────────┐                              │
│       │       │ EnvBuilder  │                              │
│       │       └─────────────┘                              │
│       │              │                                      │
│       │              ▼                                      │
│       │       ┌─────────────┐                              │
│       │       │ExploitBuilder│                             │
│       │       └─────────────┘                              │
│       │              │                                      │
│       └──────────────┼──────────────────────────────────── │
│                      ▼                                      │
│               ┌──────────┐                                  │
│               │ Reporter │ ──▶ security_report.md          │
│               └──────────┘                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Vulnerability Prioritization

MrZero uses a prioritization matrix to score vulnerabilities:

| Severity | Score | Vulnerability Types |
|----------|-------|---------------------|
| **Critical** | 90-100 | RCE, Command Injection, SQLi, Auth Bypass, Reentrancy, Private Key Leaks |
| **High** | 70-89 | LPE, SSRF, XXE, Insecure Deserialization, Path Traversal, Stored XSS |
| **Medium** | 40-69 | Reflected XSS, DoS, CSRF, Race Conditions |
| **Low** | 20-39 | Open Redirect, CRLF Injection |

## Project Structure

```
mrzero/
├── cli/                    # CLI interface (Typer/Rich)
│   └── main.py
├── core/
│   ├── config.py           # Configuration management
│   ├── schemas.py          # Pydantic models
│   ├── orchestration/      # LangGraph workflow
│   │   └── graph.py
│   ├── memory/             # Data persistence
│   │   ├── sqlite.py       # Session & cache storage
│   │   ├── vectordb.py     # Semantic code search
│   │   └── state.py        # Agent state
│   ├── mcp/                # MCP client
│   │   └── client.py
│   └── llm/                # LLM providers
│       └── providers.py
├── agents/                 # AI agents
│   ├── base.py
│   ├── mapper/
│   ├── hunter/
│   ├── verifier/
│   ├── builder/
│   ├── exploiter/
│   └── reporter/
└── tools/                  # Security tool wrappers
    ├── base.py
    ├── sast.py
    ├── smart_contract.py
    └── binary.py
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MRZERO_DATA_DIR` | Data directory | `~/.mrzero` |
| `AWS_REGION` | AWS region for Bedrock | `us-east-1` |
| `AWS_PROFILE` | AWS profile name | - |
| `GOOGLE_CLOUD_PROJECT` | Google Cloud project ID | - |

## Safety & Ethics

MrZero is designed for **authorized security testing only**. Please ensure you have:

- Written permission to test the target codebase
- Proper network isolation when generating RCE exploits
- Understanding of responsible disclosure practices

**Never use this tool against systems you don't own or have explicit permission to test.**

## Development

```bash
# Clone and setup
git clone https://github.com/yourusername/MrZero.git
cd MrZero
uv venv && source .venv/bin/activate
uv pip install -e ".[dev,all-providers]"

# Run tests
pytest

# Format code
ruff format mrzero
ruff check mrzero --fix

# Type checking
mypy mrzero
```

## Troubleshooting

### Google OAuth Issues

If the local OAuth callback server fails:
1. Check if port 8085 is available
2. Try running with `--no-browser` and paste the callback URL manually
3. Ensure your browser allows popups from localhost

### AWS Bedrock Issues

1. Verify your credentials: `aws sts get-caller-identity`
2. Check model access in Bedrock console
3. Ensure your region has the models enabled

### "No module named 'chromadb'" or similar

Install the full dependencies:
```bash
uv pip install -e ".[all-providers]"
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit PRs.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any systems.
