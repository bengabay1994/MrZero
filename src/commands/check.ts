import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { logger, formatStatus, formatOptional } from '../utils/logger.js';
import { isLinuxArm64 } from '../utils/platform.js';
import {
  detectSystemInfo,
  detectGdb,
  detectPwndbg,
  detectGhidra,
  detectMetasploit,
  detectIdaPro,
  detectIdaFree,
  detectDockerImage,
  detectDockerTool,
  detectPythonPackage,
  detectRubyGem,
} from '../installer/detector.js';
import {
  getClaudeAgentsDir,
  getOpenCodeAgentsDir,
  getMcpServersDir,
} from '../utils/platform.js';
import { DOCKER_IMAGE, DOCKER_TOOLS, PYTHON_TOOLS, RUBY_TOOLS } from '../config/tools.js';
import { AGENTS } from '../config/agents.js';
import { MCP_SERVERS } from '../config/mcp-servers.js';
import { createRubyWrapper } from '../installer/ruby.js';

interface CheckOptions {
  verbose?: boolean;
}

function formatToolStatus(wrapperInstalled: boolean, nativeInstalled: boolean, nativePath?: string): string {
  if (nativeInstalled && wrapperInstalled) {
    return chalk.green('✓ native') + chalk.dim(' + wrapper');
  } else if (nativeInstalled) {
    return chalk.green('✓ native') + (nativePath ? chalk.dim(` (${nativePath})`) : '');
  } else if (wrapperInstalled) {
    return chalk.green('✓ wrapper');
  } else {
    return chalk.red('✗ not found');
  }
}

export async function checkCommand(options: CheckOptions): Promise<void> {
  logger.header('MrZero Installation Status');

  // System dependencies
  logger.blank();
  logger.subheader('System Dependencies:');
  const systemInfo = await detectSystemInfo();
  logger.table([
    ['Docker', formatStatus(systemInfo.docker.installed)],
    ['Python', formatStatus(systemInfo.python.installed)],
    ['uv', formatStatus(systemInfo.uv.installed)],
    ['Ruby', formatOptional(systemInfo.ruby.installed)],
    ['Git', formatStatus(systemInfo.git.installed)],
  ]);

  // Docker image
  logger.blank();
  logger.subheader('Docker Image:');
  const dockerImageExists = await detectDockerImage(DOCKER_IMAGE);
  logger.table([
    [DOCKER_IMAGE, formatStatus(dockerImageExists)],
  ]);

  // Docker CLI tools (wrappers AND native)
  logger.blank();
  logger.subheader('Security Scanning Tools:');
  const toolStatus: [string, string][] = [];
  const isArm64Linux = isLinuxArm64();
  
  for (const toolName of Object.keys(DOCKER_TOOLS)) {
    const tool = DOCKER_TOOLS[toolName];
    
    // Check if tool is unsupported on this platform
    if (isArm64Linux && tool.unsupportedOnLinuxArm64) {
      toolStatus.push([
        toolName,
        chalk.dim('○ not supported on Linux ARM64'),
      ]);
      continue;
    }
    
    const status = await detectDockerTool(toolName);
    toolStatus.push([
      toolName,
      formatToolStatus(status.wrapperInstalled, status.nativeInstalled, status.nativePath),
    ]);
  }
  logger.table(toolStatus);

  // Python tools
  const pythonToolNames = Object.keys(PYTHON_TOOLS);
  if (pythonToolNames.length > 0) {
    logger.blank();
    logger.subheader('Python Tools:');
    const pythonStatus: [string, string][] = [];
    for (const toolName of pythonToolNames) {
      const status = await detectPythonPackage(toolName === 'pwntools' ? 'pwn' : toolName);
      pythonStatus.push([toolName, formatStatus(status.installed)]);
    }
    logger.table(pythonStatus);
  }

  // Ruby tools
  const rubyToolNames = Object.keys(RUBY_TOOLS);
  if (rubyToolNames.length > 0) {
    logger.blank();
    logger.subheader('Ruby Tools:');
    const rubyStatus: [string, string][] = [];
    for (const toolName of rubyToolNames) {
      const status = await detectRubyGem(toolName);
      if (status.installed && !status.callable) {
        // Auto-fix: create wrapper for installed but not callable gems
        logger.info(`Creating wrapper for ${toolName}...`);
        const wrapperCreated = await createRubyWrapper(toolName);
        if (wrapperCreated) {
          rubyStatus.push([toolName, chalk.green('✓ installed') + chalk.dim(' (wrapper created)')]);
        } else {
          rubyStatus.push([toolName, chalk.yellow('⚠ installed but not in PATH')]);
        }
      } else if (status.installed) {
        rubyStatus.push([toolName, formatStatus(status.installed)]);
      } else {
        rubyStatus.push([toolName, formatStatus(status.installed)]);
      }
    }
    logger.table(rubyStatus);
  }

  // Optional tools (for exploit development)
  logger.blank();
  logger.subheader('Optional Tools (for MrZeroExploitDeveloper):');
  const [gdb, pwndbg, ghidra, metasploit, idaPro, idaFree] = await Promise.all([
    detectGdb(),
    detectPwndbg(),
    detectGhidra(),
    detectMetasploit(),
    detectIdaPro(),
    detectIdaFree(),
  ]);
  
  // Format IDA status - show Pro, Free, or not installed
  let idaStatus: string;
  if (idaPro.installed) {
    idaStatus = chalk.green('✓ IDA Pro') + (idaPro.path ? chalk.dim(` (${idaPro.path})`) : '');
  } else if (idaFree.installed) {
    idaStatus = chalk.yellow('○ IDA Free only') + chalk.dim(' (Pro required for MCP)');
  } else {
    idaStatus = chalk.dim('○ not installed (optional)');
  }
  
  logger.table([
    ['GDB', formatOptional(gdb.installed) + (gdb.version ? chalk.dim(` v${gdb.version}`) : '')],
    ['pwndbg', formatOptional(pwndbg.installed) + (pwndbg.method ? chalk.dim(` (${pwndbg.method})`) : '')],
    ['Ghidra', formatOptional(ghidra.installed) + (ghidra.path ? chalk.dim(` (${ghidra.path})`) : '')],
    ['Metasploit', formatOptional(metasploit.installed)],
    ['IDA', idaStatus],
  ]);

  // MCP servers
  logger.blank();
  logger.subheader('MCP Servers:');
  const mcpDir = getMcpServersDir();
  const mcpStatus: [string, string][] = [];
  for (const [name, server] of Object.entries(MCP_SERVERS)) {
    let installed = false;
    
    if (server.installMethod === 'uv-tool') {
      // Check if command exists
      const { exec } = await import('../utils/shell.js');
      const result = await exec(`which ${server.command}`);
      installed = result.code === 0;
    } else if (server.installMethod === 'clone') {
      // Check if directory exists
      const dirMap: Record<string, string> = {
        'ghidra-mcp': 'GhidraMCP',
        'metasploit-mcp': 'MetasploitMCP',
        'pwndbg-mcp': 'pwndbg-mcp',
      };
      const dirName = dirMap[name];
      if (dirName) {
        installed = fs.existsSync(path.join(mcpDir, dirName));
      }
    } else if (server.installMethod === 'uv-pip') {
      // Check if command exists
      const { exec } = await import('../utils/shell.js');
      const result = await exec(`which ${server.command}`);
      installed = result.code === 0;
    } else if (server.installMethod === 'external') {
      // External servers are user-managed, show as "configured" if in platform config
      // We can't check if Burp Suite is running, so just show it as user-managed
      mcpStatus.push([server.displayName, chalk.dim('○ user-managed (install in Burp Suite)')]);
      continue;
    }
    
    mcpStatus.push([server.displayName, formatOptional(installed)]);
  }
  logger.table(mcpStatus);

  // Agent files
  logger.blank();
  logger.subheader('Agent Files (Claude Code):');
  const claudeAgentsDir = getClaudeAgentsDir();
  const claudeAgentStatus: [string, string][] = [];
  for (const agent of Object.values(AGENTS)) {
    const agentPath = path.join(claudeAgentsDir, agent.filename);
    const exists = fs.existsSync(agentPath);
    claudeAgentStatus.push([agent.displayName, formatStatus(exists)]);
  }
  logger.table(claudeAgentStatus);

  logger.blank();
  logger.subheader('Agent Files (OpenCode):');
  const openCodeAgentsDir = getOpenCodeAgentsDir();
  const openCodeAgentStatus: [string, string][] = [];
  for (const agent of Object.values(AGENTS)) {
    const agentPath = path.join(openCodeAgentsDir, agent.filename);
    const exists = fs.existsSync(agentPath);
    openCodeAgentStatus.push([agent.displayName, formatStatus(exists)]);
  }
  logger.table(openCodeAgentStatus);

  logger.blank();
}
