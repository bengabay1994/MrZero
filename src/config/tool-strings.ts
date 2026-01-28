/**
 * Tool strings for agent template rendering.
 * 
 * Each agent has a set of tools, and each tool has multiple placeholder strings
 * that get inserted into the agent's system prompt template based on what
 * tools the user chose to install.
 * 
 * Placeholder naming convention:
 * - TOOL_LIST_{TOOLNAME}: Tool description in the "available tools" list
 * - TOOL_USAGE_{TOOLNAME}: How to use the tool in methodology sections
 * - TOOL_RESULTS_{TOOLNAME}: Tool results section in report templates
 * - TOOL_DESC_{TOOLNAME}: Additional tool description paragraphs
 */

export interface ToolStringSet {
  [placeholderName: string]: string;
}

export interface AgentToolStrings {
  [toolName: string]: ToolStringSet;
}

export const TOOL_STRINGS: Record<string, AgentToolStrings> = {
  // ============================================================================
  // MrZeroMapperOS - Attack Surface Mapping Agent
  // ============================================================================
  MrZeroMapperOS: {
    opengrep: {
      TOOL_LIST_OPENGREP: '   - **opengrep**: Pattern-based code analysis for vulnerability detection',
      TOOL_USAGE_OPENGREP: '- Execute opengrep with security rulesets for the detected languages',
      TOOL_RESULTS_OPENGREP: `### opengrep
[Summary of pattern-based findings]`,
    },
    gitleaks: {
      TOOL_LIST_GITLEAKS: '   - **Gitleaks**: Scanning for hardcoded secrets and sensitive data',
      TOOL_RESULTS_GITLEAKS: `### Gitleaks
[Summary of secrets scanning results]`,
    },
    codeql: {
      TOOL_LIST_CODEQL: '   - **CodeQL**: Deep semantic code analysis and taint tracking',
      TOOL_USAGE_CODEQL: '- Run CodeQL queries focused on taint analysis and injection vulnerabilities',
      TOOL_RESULTS_CODEQL: `### CodeQL
[Summary of semantic analysis results]`,
    },
    joern: {
      TOOL_LIST_JOERN: '   - **Joern**: Code property graph analysis for security flaws',
      TOOL_USAGE_JOERN: '- Use Joern for control flow and data flow analysis',
      TOOL_RESULTS_JOERN: `### Joern
[Summary of code property graph analysis]`,
    },
    bearer: {
      TOOL_LIST_BEARER: '   - **Bearer**: Security and privacy scanning for sensitive data flows',
      TOOL_USAGE_BEARER: '- Execute Bearer to identify sensitive data handling',
      TOOL_RESULTS_BEARER: `### Bearer
[Summary of sensitive data flow findings]`,
    },
    linguist: {
      TOOL_LIST_LINGUIST: '   - **Linguist**: Language detection and codebase composition analysis',
      TOOL_USAGE_LINGUIST: '- Run Linguist to understand language composition',
    },
  },

  // ============================================================================
  // MrZeroVulnHunterOS - Vulnerability Hunting Agent
  // ============================================================================
  MrZeroVulnHunterOS: {
    opengrep: {
      TOOL_DESC_OPENGREP: `**Opengrep**: Use for pattern-based detection of common vulnerability patterns across multiple languages. Excellent for finding injection flaws, authentication issues, and cryptographic mistakes.`,
    },
    codeql: {
      TOOL_DESC_CODEQL: `**CodeQL**: Deploy for deep semantic analysis and data flow tracking. Use to trace attacker-controlled input through the codebase to sensitive sinks.`,
    },
    joern: {
      TOOL_DESC_JOERN: `**Joern**: Utilize for code property graph analysis, especially effective for discovering complex control-flow and data-flow vulnerabilities in C/C++ code.`,
    },
    gitleaks: {
      TOOL_DESC_GITLEAKS: `**Gitleaks**: Scan for accidentally committed secrets, private keys, API tokens, and sensitive credentials in git history.`,
    },
    slither: {
      TOOL_DESC_SLITHER: `**Slither**: Use exclusively for Solidity smart contract analysis. Essential for detecting reentrancy, oracle manipulation, and other DeFi-specific vulnerabilities.`,
    },
    trivy: {
      TOOL_DESC_TRIVY: `**Trivy**: Employ for dependency and container vulnerability scanning to identify known CVEs in third-party libraries.`,
    },
  },

  // ============================================================================
  // MrZeroExploitDeveloper - Exploit Development Agent
  // ============================================================================
  MrZeroExploitDeveloper: {
    // CLI Tools
    pwntools: {
      TOOL_LIST_PWNTOOLS: '- **pwntools**: Python exploitation framework for CTF and exploit development',
      TOOL_USAGE_PWNTOOLS: '- Use pwntools as the primary framework for binary exploitation',
    },
    ropper: {
      TOOL_LIST_ROPPER: '- **ROPgadget/Ropper**: ROP chain gadget finder and builder',
      TOOL_USAGE_ROPPER: '- Build ROP chains using ROPgadget and one_gadget findings or ropper via pwntools framework',
    },
    one_gadget: {
      TOOL_LIST_ONEGADGET: '- **one_gadget**: Find one-shot RCE gadgets in libc',
    },
    // System tools (detected, not installed by us)
    checksec: {
      TOOL_LIST_CHECKSEC: '- **Standard Linux utilities**: objdump, readelf, checksec, strings, nm, ldd',
    },
    // MCP Servers
    'pwndbg-mcp': {
      TOOL_LIST_PWNDBG: '- **GDB with pwndbg plugin**: Dynamic analysis, debugging, memory inspection (Linux)',
      TOOL_USAGE_PWNDBG: '- Debug failures using GDB/pwndbg',
      TOOL_DEBUG_PWNDBG: `### Debugging Integration
\`\`\`python
# Attach GDB for debugging
p = gdb.debug('./vulnerable', '''
    break *main+100
    continue
''')
\`\`\``,
    },
    'ghidra-mcp': {
      TOOL_LIST_GHIDRA: '- **Ghidra**: Static analysis and reverse engineering disassembler',
    },
    'metasploit-mcp': {
      TOOL_LIST_METASPLOIT: '- **Metasploit Framework**: Exploit modules, payloads, encoders, and post-exploitation',
    },
    'ida-pro-mcp': {
      TOOL_LIST_IDA: '- **IDA Pro**: Advanced disassembler for static analysis and reverse engineering',
    },
  },
};

/**
 * Get all tool strings for a specific agent
 */
export function getAgentToolStrings(agentName: string): AgentToolStrings | undefined {
  return TOOL_STRINGS[agentName];
}

/**
 * Get tool strings for a specific tool within an agent
 */
export function getToolStrings(agentName: string, toolName: string): ToolStringSet | undefined {
  return TOOL_STRINGS[agentName]?.[toolName];
}

/**
 * Get all tools that have strings defined for a specific agent
 */
export function getAgentTools(agentName: string): string[] {
  const agentStrings = TOOL_STRINGS[agentName];
  return agentStrings ? Object.keys(agentStrings) : [];
}
