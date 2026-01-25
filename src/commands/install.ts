import * as fs from 'fs';
import enquirer from 'enquirer';
import ora from 'ora';
import { logger, formatStatus, formatOptional } from '../utils/logger.js';
import { isLinux } from '../utils/platform.js';
import {
  detectSystemInfo,
  detectGdb,
  detectPwndbg,
  detectGhidra,
  detectMetasploit,
  detectIdaPro,
  SystemInfo,
} from '../installer/detector.js';
import {
  AGENTS,
  getAllAgents,
  getUniqueDockerTools,
  getUniquePythonTools,
  getUniqueRubyTools,
  getUniqueMcpServers,
  AgentConfig,
} from '../config/agents.js';
import { ensureDockerImage, createAllWrappers } from '../installer/docker.js';
import { installAllPythonTools } from '../installer/python.js';
import { installAllRubyTools } from '../installer/ruby.js';
import { installAllMcpServers, McpInstallResult } from '../installer/mcp.js';
import { configurePlatform, Platform } from '../installer/platforms.js';

const { MultiSelect, Confirm } = enquirer as any;

interface InstallOptions {
  agent?: string[];
  platform?: string[];
  skipDocker?: boolean;
  skipMcp?: boolean;
  yes?: boolean;
}

async function showSystemInfo(): Promise<SystemInfo> {
  const spinner = ora('Detecting system configuration...').start();
  
  const [systemInfo, gdb, pwndbg, ghidra, metasploit, idaPro] = await Promise.all([
    detectSystemInfo(),
    detectGdb(),
    detectPwndbg(),
    detectGhidra(),
    detectMetasploit(),
    detectIdaPro(),
  ]);

  spinner.stop();

  logger.header('System Information');
  logger.table([
    ['OS', systemInfo.osVersion || systemInfo.os],
    ['Architecture', systemInfo.arch],
    ['Docker', formatStatus(systemInfo.docker.installed) + (systemInfo.docker.version ? ` (v${systemInfo.docker.version})` : '')],
    ['Python', formatStatus(systemInfo.python.installed) + (systemInfo.python.version ? ` (v${systemInfo.python.version})` : '')],
    ['uv', formatStatus(systemInfo.uv.installed) + (systemInfo.uv.version ? ` (v${systemInfo.uv.version})` : '')],
    ['Ruby', formatOptional(systemInfo.ruby.installed) + (systemInfo.ruby.version ? ` (v${systemInfo.ruby.version})` : '')],
    ['Git', formatStatus(systemInfo.git.installed)],
  ]);

  logger.blank();
  logger.subheader('Optional Tools (for MrZeroExploitDeveloper):');
  logger.table([
    ['GDB', formatOptional(gdb.installed) + (gdb.version ? ` (v${gdb.version})` : '')],
    ['pwndbg', formatOptional(pwndbg.installed) + (pwndbg.method ? ` (${pwndbg.method})` : '')],
    ['Ghidra', formatOptional(ghidra.installed) + (ghidra.path ? ` (${ghidra.path})` : '')],
    ['Metasploit', formatOptional(metasploit.installed)],
    ['IDA Pro', formatOptional(idaPro.installed)],
  ]);

  // Check for critical missing dependencies
  if (!systemInfo.docker.installed) {
    logger.blank();
    logger.error('Docker is required but not installed.');
    logger.info('Install Docker: https://docs.docker.com/engine/install/');
    process.exit(1);
  }

  if (!systemInfo.python.installed) {
    logger.blank();
    logger.error('Python 3 is required but not installed.');
    logger.info('Install Python: sudo apt-get install python3 python3-pip');
    process.exit(1);
  }

  if (!systemInfo.uv.installed) {
    logger.blank();
    logger.error('uv is required but not installed.');
    logger.info('Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh');
    process.exit(1);
  }

  return systemInfo;
}

async function selectAgents(preselected?: string[]): Promise<string[]> {
  if (preselected && preselected.length > 0) {
    // Validate preselected agents
    const valid = preselected.filter((a) => AGENTS[a]);
    if (valid.length !== preselected.length) {
      const invalid = preselected.filter((a) => !AGENTS[a]);
      logger.warning(`Unknown agents: ${invalid.join(', ')}`);
    }
    return valid;
  }

  logger.blank();
  const prompt = new MultiSelect({
    name: 'agents',
    message: 'Select agents to install tools for:',
    choices: getAllAgents().map((agent) => ({
      name: agent.name,
      message: `${agent.displayName} - ${agent.description}`,
      value: agent.name,
    })),
    initial: getAllAgents().map((a) => a.name), // All selected by default
  });

  const selected = await prompt.run();
  return selected;
}

async function selectPlatforms(preselected?: string[]): Promise<Platform[]> {
  if (preselected && preselected.length > 0) {
    const valid = preselected.filter((p) => p === 'claude-code' || p === 'opencode');
    return valid as Platform[];
  }

  logger.blank();
  const prompt = new MultiSelect({
    name: 'platforms',
    message: 'Select AI platforms to configure:',
    choices: [
      { name: 'claude-code', message: 'Claude Code', value: 'claude-code' },
      { name: 'opencode', message: 'OpenCode', value: 'opencode' },
    ],
    initial: ['claude-code', 'opencode'],
  });

  const selected = await prompt.run();
  return selected as Platform[];
}

async function confirmInstallation(
  agents: AgentConfig[],
  dockerTools: string[],
  pythonTools: string[],
  rubyTools: string[],
  mcpServers: string[],
  platforms: Platform[],
  skipConfirm: boolean
): Promise<boolean> {
  logger.blank();
  logger.header('Installation Plan');

  logger.subheader('Agents:');
  logger.list(agents.map((a) => a.displayName));

  if (dockerTools.length > 0) {
    logger.blank();
    logger.subheader('Docker-wrapped CLI tools:');
    logger.list(dockerTools);
  }

  if (pythonTools.length > 0) {
    logger.blank();
    logger.subheader('Python tools (via uv):');
    logger.list(pythonTools);
  }

  if (rubyTools.length > 0) {
    logger.blank();
    logger.subheader('Ruby tools (via gem):');
    logger.list(rubyTools);
  }

  if (mcpServers.length > 0) {
    logger.blank();
    logger.subheader('MCP servers:');
    logger.list(mcpServers);
  }

  logger.blank();
  logger.subheader('Target platforms:');
  logger.list(platforms);

  if (skipConfirm) {
    return true;
  }

  logger.blank();
  const prompt = new Confirm({
    name: 'confirm',
    message: 'Proceed with installation?',
    initial: true,
  });

  return await prompt.run();
}

function showPostInstallNotes(mcpResults: McpInstallResult[]): void {
  const notes: string[] = [];

  for (const result of mcpResults) {
    if (result.postInstallNotes && result.postInstallNotes.length > 0) {
      notes.push(...result.postInstallNotes);
      notes.push(''); // blank line between sections
    }
  }

  if (notes.length > 0) {
    logger.box('Post-Installation Notes', notes);
  }
}

export async function installCommand(options: InstallOptions): Promise<void> {
  console.log('');
  console.log('  __  __      _____                ');
  console.log(' |  \\/  |_ __|__  /___ _ __ ___   ');
  console.log(' | |\\/| | \'__| / // _ \\ \'__/ _ \\  ');
  console.log(' | |  | | |   / /|  __/ | | (_) | ');
  console.log(' |_|  |_|_|  /____\\___|_|  \\___/  ');
  console.log('');
  console.log(' AI-Powered Security Research Agents');
  console.log('');

  // Check platform
  if (!isLinux()) {
    logger.warning('MrZero currently only supports Linux.');
    logger.info('macOS and Windows support coming soon!');
    process.exit(1);
  }

  // Show system info and check dependencies
  await showSystemInfo();

  // Select agents
  const selectedAgentNames = await selectAgents(options.agent);
  if (selectedAgentNames.length === 0) {
    logger.error('No agents selected. Exiting.');
    process.exit(1);
  }

  const selectedAgents = selectedAgentNames.map((name) => AGENTS[name]);

  // Select platforms
  const selectedPlatforms = await selectPlatforms(options.platform);
  if (selectedPlatforms.length === 0) {
    logger.error('No platforms selected. Exiting.');
    process.exit(1);
  }

  // Calculate what needs to be installed
  const dockerTools = options.skipDocker ? [] : getUniqueDockerTools(selectedAgents);
  const pythonTools = getUniquePythonTools(selectedAgents);
  const rubyTools = getUniqueRubyTools(selectedAgents);
  const mcpServers = options.skipMcp ? [] : getUniqueMcpServers(selectedAgents);

  // Confirm installation
  const confirmed = await confirmInstallation(
    selectedAgents,
    dockerTools,
    pythonTools,
    rubyTools,
    mcpServers,
    selectedPlatforms,
    options.yes || false
  );

  if (!confirmed) {
    logger.info('Installation cancelled.');
    process.exit(0);
  }

  logger.blank();

  // Install Docker tools
  if (dockerTools.length > 0) {
    logger.header('Installing Docker tools');
    const imageReady = await ensureDockerImage();
    if (imageReady) {
      await createAllWrappers(dockerTools);
    } else {
      logger.error('Failed to setup Docker image. Docker tools will not be available.');
    }
  }

  // Install Python tools
  if (pythonTools.length > 0) {
    await installAllPythonTools(pythonTools);
  }

  // Install Ruby tools
  if (rubyTools.length > 0) {
    await installAllRubyTools(rubyTools);
  }

  // Install MCP servers
  let mcpResults: McpInstallResult[] = [];
  if (mcpServers.length > 0) {
    mcpResults = await installAllMcpServers(mcpServers);
  }

  // Configure platforms
  const installedMcpServers = mcpResults
    .filter((r) => r.installed)
    .map((r) => r.name);

  for (const platform of selectedPlatforms) {
    await configurePlatform(platform, installedMcpServers, selectedAgentNames);
  }

  // Show completion message
  logger.blank();
  logger.header('Installation Complete!');

  // Show post-install notes
  showPostInstallNotes(mcpResults);

  // Show quick start
  logger.blank();
  logger.info('Quick start:');
  logger.info('  npx mrzero check    # Verify installation');
  logger.info('  npx mrzero --help   # See all commands');

  if (selectedPlatforms.includes('claude-code')) {
    logger.blank();
    logger.info('Restart Claude Code to load the new agents and MCP servers.');
  }

  if (selectedPlatforms.includes('opencode')) {
    logger.blank();
    logger.info('Restart OpenCode to load the new agents and MCP servers.');
  }
}
