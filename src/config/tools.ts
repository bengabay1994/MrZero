export interface ToolConfig {
  name: string;
  displayName: string;
  description: string;
  installMethod: 'docker' | 'uv' | 'gem' | 'apt' | 'manual';
  checkCommand?: string;
  installCommand?: string;
  wrapperName?: string;
}

export const DOCKER_TOOLS: Record<string, ToolConfig> = {
  // Static Analysis Tools
  opengrep: {
    name: 'opengrep',
    displayName: 'Opengrep',
    description: 'Pattern-based code analysis for vulnerability detection',
    installMethod: 'docker',
    wrapperName: 'opengrep',
  },
  gitleaks: {
    name: 'gitleaks',
    displayName: 'Gitleaks',
    description: 'Scanning for hardcoded secrets and sensitive data',
    installMethod: 'docker',
    wrapperName: 'gitleaks',
  },
  codeql: {
    name: 'codeql',
    displayName: 'CodeQL',
    description: 'Deep semantic code analysis and taint tracking',
    installMethod: 'docker',
    wrapperName: 'codeql',
  },
  joern: {
    name: 'joern',
    displayName: 'Joern',
    description: 'Code property graph analysis for security flaws',
    installMethod: 'docker',
    wrapperName: 'joern',
  },
  bearer: {
    name: 'bearer',
    displayName: 'Bearer',
    description: 'Security and privacy scanning for sensitive data flows',
    installMethod: 'docker',
    wrapperName: 'bearer',
  },
  slither: {
    name: 'slither',
    displayName: 'Slither',
    description: 'Solidity smart contract analysis',
    installMethod: 'docker',
    wrapperName: 'slither',
  },
  trivy: {
    name: 'trivy',
    displayName: 'Trivy',
    description: 'Dependency and container vulnerability scanning',
    installMethod: 'docker',
    wrapperName: 'trivy',
  },
  linguist: {
    name: 'linguist',
    displayName: 'Linguist',
    description: 'Language detection and codebase composition analysis',
    installMethod: 'docker',
    wrapperName: 'linguist',
  },
  // Exploitation Tools
  pwntools: {
    name: 'pwntools',
    displayName: 'pwntools',
    description: 'CTF framework and exploit development library',
    installMethod: 'docker',
    wrapperName: 'pwn',
  },
  ropper: {
    name: 'ropper',
    displayName: 'Ropper',
    description: 'ROP gadget finder and binary analysis',
    installMethod: 'docker',
    wrapperName: 'ropper',
  },
  one_gadget: {
    name: 'one_gadget',
    displayName: 'one_gadget',
    description: 'Find one-shot RCE gadgets in libc',
    installMethod: 'docker',
    wrapperName: 'one_gadget',
  },
};

// Keep these for backward compatibility but they're now empty
// All tools are Docker-based except for MCP-connected tools
export const PYTHON_TOOLS: Record<string, ToolConfig> = {};

export const RUBY_TOOLS: Record<string, ToolConfig> = {};

export const SYSTEM_TOOLS: Record<string, ToolConfig> = {
  docker: {
    name: 'docker',
    displayName: 'Docker',
    description: 'Container runtime for isolated tools',
    installMethod: 'manual',
    checkCommand: 'docker --version',
  },
  gdb: {
    name: 'gdb',
    displayName: 'GDB',
    description: 'GNU Debugger (required for pwndbg MCP)',
    installMethod: 'apt',
    checkCommand: 'gdb --version',
    installCommand: 'sudo apt-get install -y gdb',
  },
  checksec: {
    name: 'checksec',
    displayName: 'checksec',
    description: 'Check binary security features',
    installMethod: 'apt',
    checkCommand: 'checksec --version',
    installCommand: 'sudo apt-get install -y checksec',
  },
};

export const DOCKER_IMAGE = 'ghcr.io/bengabay1994/mrzero-tools:latest';
