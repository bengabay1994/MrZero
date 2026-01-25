export interface McpServerConfig {
  name: string;
  displayName: string;
  description: string;
  repo: string;
  installMethod: 'uv-tool' | 'uv-pip' | 'clone';
  requiresPrerequisite?: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
  postInstallNotes?: string[];
}

export const MCP_SERVERS: Record<string, McpServerConfig> = {
  'pwndbg-mcp': {
    name: 'pwndbg-mcp',
    displayName: 'pwndbg MCP',
    description: 'GDB + pwndbg integration for binary exploitation',
    repo: 'https://github.com/bengabay1994/pwndbg-mcp.git',
    installMethod: 'uv-tool',
    requiresPrerequisite: 'pwndbg',
    command: 'pwndbg-mcp',
  },
  'ghidra-mcp': {
    name: 'ghidra-mcp',
    displayName: 'Ghidra MCP',
    description: 'Ghidra integration for reverse engineering',
    repo: 'https://github.com/LaurieWired/GhidraMCP.git',
    installMethod: 'clone',
    requiresPrerequisite: 'ghidra',
    command: 'python',
    args: ['${MRZERO_DIR}/mcp-servers/GhidraMCP/bridge_mcp_ghidra.py', '--ghidra-server', 'http://127.0.0.1:8080/'],
    postInstallNotes: [
      'GhidraMCP requires manual Ghidra extension installation:',
      '1. Open Ghidra',
      '2. Go to File → Install Extensions',
      '3. Click the + button',
      '4. Select ~/.mrzero/mcp-servers/GhidraMCP/GhidraMCP*.zip',
      '5. Restart Ghidra and enable the plugin in File → Configure → Developer',
    ],
  },
  'metasploit-mcp': {
    name: 'metasploit-mcp',
    displayName: 'Metasploit MCP',
    description: 'Metasploit Framework integration',
    repo: 'https://github.com/GH05TCREW/MetasploitMCP.git',
    installMethod: 'clone',
    requiresPrerequisite: 'metasploit',
    command: 'uv',
    args: ['--directory', '${MRZERO_DIR}/mcp-servers/MetasploitMCP', 'run', 'MetasploitMCP.py', '--transport', 'stdio'],
    env: {
      MSF_PASSWORD: 'mrzero',
    },
    postInstallNotes: [
      'MetasploitMCP requires msfrpcd to be running:',
      'Start it with: msfrpcd -P mrzero -S -a 127.0.0.1 -p 55553',
      'The default password is "mrzero" - change MSF_PASSWORD in your config if you use a different one.',
    ],
  },
  'ida-pro-mcp': {
    name: 'ida-pro-mcp',
    displayName: 'IDA Pro MCP',
    description: 'IDA Pro integration for reverse engineering',
    repo: 'https://github.com/mrexodia/ida-pro-mcp',
    installMethod: 'uv-pip',
    requiresPrerequisite: 'ida-pro',
    command: 'ida-pro-mcp',
    postInstallNotes: [
      'After installation, run: ida-pro-mcp --install',
      'This will configure the IDA Pro plugin automatically.',
    ],
  },
};

export function getMcpServerByName(name: string): McpServerConfig | undefined {
  return MCP_SERVERS[name];
}

export function getAllMcpServers(): McpServerConfig[] {
  return Object.values(MCP_SERVERS);
}
