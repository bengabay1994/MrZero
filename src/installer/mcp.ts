import * as fs from 'fs';
import * as path from 'path';
import { exec, runWithOutput } from '../utils/shell.js';
import { logger } from '../utils/logger.js';
import { getMcpServersDir, getMrZeroDir, getHomeDir } from '../utils/platform.js';
import { MCP_SERVERS, McpServerConfig } from '../config/mcp-servers.js';

export interface McpInstallResult {
  name: string;
  installed: boolean;
  skipped: boolean;
  reason?: string;
  postInstallNotes?: string[];
}

async function installPwndbgMcp(): Promise<McpInstallResult> {
  const server = MCP_SERVERS['pwndbg-mcp'];
  const mcpDir = getMcpServersDir();
  const repoPath = path.join(mcpDir, 'pwndbg-mcp');

  logger.step(`Installing ${server.displayName}...`);

  // Clone the repo
  fs.mkdirSync(mcpDir, { recursive: true });

  if (fs.existsSync(repoPath)) {
    logger.info('Repository already exists, pulling latest...');
    const pullResult = await exec('git pull', { cwd: repoPath });
    if (pullResult.code !== 0) {
      logger.warning('Failed to pull updates, using existing version');
    }
  } else {
    const cloneResult = await exec(`git clone ${server.repo} ${repoPath}`);
    if (cloneResult.code !== 0) {
      return {
        name: server.name,
        installed: false,
        skipped: false,
        reason: `Failed to clone repository: ${cloneResult.stderr}`,
      };
    }
  }

  // Install using uv tool install
  const installResult = await exec(`uv tool install .`, { cwd: repoPath });
  if (installResult.code !== 0) {
    return {
      name: server.name,
      installed: false,
      skipped: false,
      reason: `Failed to install: ${installResult.stderr}`,
    };
  }

  logger.success(`Installed ${server.displayName}`);
  return {
    name: server.name,
    installed: true,
    skipped: false,
  };
}

async function installGhidraMcp(): Promise<McpInstallResult> {
  const server = MCP_SERVERS['ghidra-mcp'];
  const mcpDir = getMcpServersDir();
  const repoPath = path.join(mcpDir, 'GhidraMCP');

  logger.step(`Installing ${server.displayName}...`);

  fs.mkdirSync(mcpDir, { recursive: true });

  if (fs.existsSync(repoPath)) {
    logger.info('Repository already exists, pulling latest...');
    await exec('git pull', { cwd: repoPath });
  } else {
    const cloneResult = await exec(`git clone ${server.repo} ${repoPath}`);
    if (cloneResult.code !== 0) {
      return {
        name: server.name,
        installed: false,
        skipped: false,
        reason: `Failed to clone repository: ${cloneResult.stderr}`,
      };
    }
  }

  // Install Python dependencies in a virtual environment
  const reqFile = path.join(repoPath, 'requirements.txt');
  if (fs.existsSync(reqFile)) {
    // Create venv if it doesn't exist
    const venvPath = path.join(repoPath, '.venv');
    if (!fs.existsSync(venvPath)) {
      await exec(`uv venv`, { cwd: repoPath });
    }
    const pipResult = await exec(`uv pip install -r requirements.txt`, { cwd: repoPath });
    if (pipResult.code !== 0) {
      logger.warning(`Failed to install Python dependencies: ${pipResult.stderr}`);
    }
  }

  // Download latest release for Ghidra extension
  logger.info('Downloading Ghidra extension...');
  const releaseResult = await exec(
    `curl -s https://api.github.com/repos/LaurieWired/GhidraMCP/releases/latest`
  );
  
  if (releaseResult.code === 0 && releaseResult.stdout.trim()) {
    try {
      const releaseData = JSON.parse(releaseResult.stdout);
      const zipAsset = releaseData.assets?.find((a: any) => a.name?.endsWith('.zip'));
      if (zipAsset?.browser_download_url) {
        const downloadUrl = zipAsset.browser_download_url;
        const zipPath = path.join(repoPath, 'GhidraMCP-extension.zip');
        await exec(`curl -sSL "${downloadUrl}" -o "${zipPath}"`);
      }
    } catch {
      logger.warning('Failed to parse Ghidra release info, skipping extension download');
    }
  }

  logger.success(`Installed ${server.displayName}`);
  return {
    name: server.name,
    installed: true,
    skipped: false,
    postInstallNotes: server.postInstallNotes,
  };
}

async function installMetasploitMcp(): Promise<McpInstallResult> {
  const server = MCP_SERVERS['metasploit-mcp'];
  const mcpDir = getMcpServersDir();
  const repoPath = path.join(mcpDir, 'MetasploitMCP');

  logger.step(`Installing ${server.displayName}...`);

  fs.mkdirSync(mcpDir, { recursive: true });

  if (fs.existsSync(repoPath)) {
    logger.info('Repository already exists, pulling latest...');
    await exec('git pull', { cwd: repoPath });
  } else {
    const cloneResult = await exec(`git clone ${server.repo} ${repoPath}`);
    if (cloneResult.code !== 0) {
      return {
        name: server.name,
        installed: false,
        skipped: false,
        reason: `Failed to clone repository: ${cloneResult.stderr}`,
      };
    }
  }

  // Install Python dependencies in a virtual environment
  const reqFile = path.join(repoPath, 'requirements.txt');
  if (fs.existsSync(reqFile)) {
    // Create venv if it doesn't exist
    const venvPath = path.join(repoPath, '.venv');
    if (!fs.existsSync(venvPath)) {
      await exec(`uv venv`, { cwd: repoPath });
    }
    const pipResult = await exec(`uv pip install -r requirements.txt`, { cwd: repoPath });
    if (pipResult.code !== 0) {
      logger.warning(`Failed to install Python dependencies: ${pipResult.stderr}`);
    }
  }

  logger.success(`Installed ${server.displayName}`);
  return {
    name: server.name,
    installed: true,
    skipped: false,
    postInstallNotes: server.postInstallNotes,
  };
}

async function installIdaProMcp(): Promise<McpInstallResult> {
  const server = MCP_SERVERS['ida-pro-mcp'];

  logger.step(`Installing ${server.displayName}...`);

  // Install via uv tool from GitHub
  const installResult = await exec(
    `uv tool install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip`
  );

  if (installResult.code !== 0) {
    return {
      name: server.name,
      installed: false,
      skipped: false,
      reason: `Failed to install: ${installResult.stderr}`,
    };
  }

  // Run the install command to set up the IDA plugin
  logger.info('Configuring IDA Pro plugin...');
  const configResult = await exec('ida-pro-mcp --install');
  if (configResult.code !== 0) {
    logger.warning('Failed to auto-configure IDA plugin. You may need to run: ida-pro-mcp --install');
  }

  logger.success(`Installed ${server.displayName}`);
  return {
    name: server.name,
    installed: true,
    skipped: false,
    postInstallNotes: server.postInstallNotes,
  };
}

export async function installMcpServer(serverName: string): Promise<McpInstallResult> {
  const server = MCP_SERVERS[serverName];
  if (!server) {
    return {
      name: serverName,
      installed: false,
      skipped: true,
      reason: `Unknown MCP server: ${serverName}`,
    };
  }

  // External servers are not installed by us - just configure the MCP client
  if (server.installMethod === 'external') {
    logger.success(`Configured ${server.displayName} (user-managed, not installed by MrZero)`);
    return {
      name: server.name,
      installed: true,
      skipped: false,
      postInstallNotes: server.postInstallNotes,
    };
  }

  // Note: We no longer check prerequisites here since user explicitly chose to install
  // The warning about prerequisites is shown during MCP server selection

  switch (serverName) {
    case 'pwndbg-mcp':
      return installPwndbgMcp();
    case 'ghidra-mcp':
      return installGhidraMcp();
    case 'metasploit-mcp':
      return installMetasploitMcp();
    case 'ida-pro-mcp':
      return installIdaProMcp();
    default:
      return {
        name: serverName,
        installed: false,
        skipped: true,
        reason: `No installer implemented for: ${serverName}`,
      };
  }
}

export async function installAllMcpServers(servers: string[]): Promise<McpInstallResult[]> {
  if (servers.length === 0) return [];

  logger.header('Installing MCP servers');

  const results: McpInstallResult[] = [];
  for (const server of servers) {
    const result = await installMcpServer(server);
    results.push(result);
  }

  return results;
}

export async function uninstallMcpServer(serverName: string): Promise<boolean> {
  const mcpDir = getMcpServersDir();
  
  const serverDirs: Record<string, string> = {
    'pwndbg-mcp': 'pwndbg-mcp',
    'ghidra-mcp': 'GhidraMCP',
    'metasploit-mcp': 'MetasploitMCP',
  };

  const dirName = serverDirs[serverName];
  if (dirName) {
    const serverPath = path.join(mcpDir, dirName);
    if (fs.existsSync(serverPath)) {
      fs.rmSync(serverPath, { recursive: true, force: true });
      logger.success(`Removed ${serverName}`);
      return true;
    }
  }

  // For pip-installed servers
  if (serverName === 'ida-pro-mcp') {
    await exec('uv pip uninstall -y ida-pro-mcp');
    logger.success(`Removed ${serverName}`);
    return true;
  }

  if (serverName === 'pwndbg-mcp') {
    await exec('uv tool uninstall pwndbg-mcp');
    return true;
  }

  return false;
}
