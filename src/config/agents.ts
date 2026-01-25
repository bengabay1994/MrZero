export interface AgentConfig {
  name: string;
  displayName: string;
  description: string;
  filename: string;
  dockerTools: string[];
  pythonTools: string[];
  rubyTools: string[];
  systemTools: string[];
  mcpServers: string[];
}

export const AGENTS: Record<string, AgentConfig> = {
  MrZeroMapperOS: {
    name: 'MrZeroMapperOS',
    displayName: 'MrZero Mapper',
    description: 'Attack surface mapping and analysis',
    filename: 'MrZeroMapperOS.md',
    dockerTools: ['opengrep', 'gitleaks', 'codeql', 'joern', 'bearer', 'linguist', 'tree-sitter'],
    pythonTools: [],
    rubyTools: [],
    systemTools: [],
    mcpServers: [],
  },
  MrZeroVulnHunterOS: {
    name: 'MrZeroVulnHunterOS',
    displayName: 'MrZero VulnHunter',
    description: 'Vulnerability hunting and detection',
    filename: 'MrZeroVulnHunterOS.md',
    dockerTools: ['opengrep', 'codeql', 'joern', 'infer', 'gitleaks', 'slither', 'trivy'],
    pythonTools: [],
    rubyTools: [],
    systemTools: [],
    mcpServers: [],
  },
  MrZeroExploitDeveloper: {
    name: 'MrZeroExploitDeveloper',
    displayName: 'MrZero Exploit Developer',
    description: 'Exploit development and testing',
    filename: 'MrZeroExploitDeveloper.md',
    dockerTools: [],
    pythonTools: ['pwntools', 'ropper'],
    rubyTools: ['one_gadget'],
    systemTools: ['gdb', 'checksec'],
    mcpServers: ['pwndbg-mcp', 'ghidra-mcp', 'metasploit-mcp', 'ida-pro-mcp'],
  },
  MrZeroEnvBuilder: {
    name: 'MrZeroEnvBuilder',
    displayName: 'MrZero Environment Builder',
    description: 'Test environment setup and configuration',
    filename: 'MrZeroEnvBuilder.md',
    dockerTools: [],
    pythonTools: [],
    rubyTools: [],
    systemTools: ['docker'],
    mcpServers: [],
  },
};

export function getAgentByName(name: string): AgentConfig | undefined {
  return AGENTS[name];
}

export function getAllAgents(): AgentConfig[] {
  return Object.values(AGENTS);
}

export function getUniqueDockerTools(agents: AgentConfig[]): string[] {
  const tools = new Set<string>();
  agents.forEach((agent) => agent.dockerTools.forEach((tool) => tools.add(tool)));
  return Array.from(tools);
}

export function getUniquePythonTools(agents: AgentConfig[]): string[] {
  const tools = new Set<string>();
  agents.forEach((agent) => agent.pythonTools.forEach((tool) => tools.add(tool)));
  return Array.from(tools);
}

export function getUniqueRubyTools(agents: AgentConfig[]): string[] {
  const tools = new Set<string>();
  agents.forEach((agent) => agent.rubyTools.forEach((tool) => tools.add(tool)));
  return Array.from(tools);
}

export function getUniqueSystemTools(agents: AgentConfig[]): string[] {
  const tools = new Set<string>();
  agents.forEach((agent) => agent.systemTools.forEach((tool) => tools.add(tool)));
  return Array.from(tools);
}

export function getUniqueMcpServers(agents: AgentConfig[]): string[] {
  const servers = new Set<string>();
  agents.forEach((agent) => agent.mcpServers.forEach((server) => servers.add(server)));
  return Array.from(servers);
}
