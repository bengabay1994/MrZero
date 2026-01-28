package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Version is set during build via ldflags
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "opencode":
		launch("opencode", os.Args[2:])
	case "claude", "claude-code":
		launch("claude", os.Args[2:])
	case "--help", "-h":
		showHelp()
	case "--version", "-v":
		fmt.Printf("mrzero launcher %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown platform '%s'\n\n", os.Args[1])
		showHelp()
		os.Exit(1)
	}
}

func launch(command string, args []string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	toolsDir := filepath.Join(home, ".local", "bin", "mrzero-tools")

	// Check if tools directory exists
	if _, err := os.Stat(toolsDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: MrZero tools not found at %s\n", toolsDir)
		fmt.Fprintf(os.Stderr, "Run: npx @bengabay94/mrzero@alpha install\n")
		os.Exit(1)
	}

	// Prepend MrZero tools to PATH
	currentPath := os.Getenv("PATH")
	newPath := toolsDir + string(os.PathListSeparator) + currentPath
	os.Setenv("PATH", newPath)

	// Find the command in PATH
	cmdPath, err := exec.LookPath(command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: '%s' not found in PATH\n", command)
		fmt.Fprintf(os.Stderr, "Please install %s first.\n", command)
		os.Exit(1)
	}

	// Execute the command (replace current process)
	argv := append([]string{command}, args...)
	err = syscall.Exec(cmdPath, argv, os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to execute %s: %v\n", command, err)
		os.Exit(1)
	}
}

func showHelp() {
	help := `MrZero - AI-Powered Security Research Agents

Usage: mrzero <platform> [args...]

Platforms:
  opencode      Launch OpenCode with MrZero security tools
  claude        Launch Claude Code with MrZero security tools

Options:
  --help, -h       Show this help message
  --version, -v    Show version

Examples:
  mrzero opencode
  mrzero claude

For installation and management:
  npx @bengabay94/mrzero@alpha install     Install MrZero
  npx @bengabay94/mrzero@alpha check       Verify installation
  npx @bengabay94/mrzero@alpha uninstall   Remove MrZero

Documentation: https://github.com/bengabay1994/MrZero
`
	fmt.Print(help)
}
