#!/bin/bash
# MrZero Toolbox Entrypoint
# Routes tool commands to the appropriate binary

set -e

# Add Opengrep to PATH (installed via install.sh to ~/.opengrep)
export PATH="/root/.opengrep/cli/latest:$PATH"

# Mark /workspace as safe for git operations (handles permission issues in Docker)
git config --global --add safe.directory /workspace 2>/dev/null || true

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_help() {
    echo "MrZero Toolbox - Security Analysis Tools"
    echo ""
    echo "Usage: docker run mrzero-toolbox <tool> [args...]"
    echo ""
    echo "Available tools:"
    echo "  opengrep    - SAST scanner (static code analysis)"
    echo "  linguist    - Language detection (GitHub Linguist)"
    echo "  help        - Show this help message"
    echo ""
    echo "Examples:"
    echo "  docker run -v \$(pwd):/workspace mrzero-toolbox opengrep scan --config auto /workspace"
    echo "  docker run -v \$(pwd):/workspace mrzero-toolbox linguist /workspace"
    echo ""
}

# Get the tool name from first argument
TOOL="${1:-help}"
shift || true

case "$TOOL" in
    opengrep)
        exec opengrep "$@"
        ;;
    linguist|github-linguist)
        exec github-linguist "$@"
        ;;
    help|--help|-h)
        print_help
        exit 0
        ;;
    version|--version|-v)
        echo "MrZero Toolbox v1.0"
        echo ""
        echo "Tool versions:"
        echo -n "  opengrep: "
        opengrep --version 2>/dev/null | head -1 || echo "unknown"
        echo -n "  linguist: "
        github-linguist --version 2>/dev/null || echo "unknown"
        exit 0
        ;;
    *)
        echo -e "${RED}Error: Unknown tool '$TOOL'${NC}" >&2
        echo "" >&2
        print_help >&2
        exit 1
        ;;
esac
