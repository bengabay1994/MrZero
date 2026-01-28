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
import { MCP_SERVERS, getAllMcpServers } from '../config/mcp-servers.js';
import { DOCKER_TOOLS, PYTHON_TOOLS, RUBY_TOOLS } from '../config/tools.js';
import chalk from 'chalk';
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

async function selectMcpServers(agentMcpServers: string[], skipMcp: boolean): Promise<string[]> {
  if (skipMcp) {
    return [];
  }

  // If no MCP servers are needed by selected agents, skip
  if (agentMcpServers.length === 0) {
    return [];
  }

  logger.blank();
  logger.header('MCP Server Selection');
  
  // Show warning box
  console.log('');
  console.log(chalk.yellow('  ┌─────────────────────────────────────────────────────────────────────┐'));
  console.log(chalk.yellow('  │') + chalk.bold.yellow('                           ⚠  WARNING  ⚠                            ') + chalk.yellow('│'));
  console.log(chalk.yellow('  ├─────────────────────────────────────────────────────────────────────┤'));
  console.log(chalk.yellow('  │') + '  MCP servers provide AI agents with access to external tools.      ' + chalk.yellow('│'));
  console.log(chalk.yellow('  │') + '                                                                     ' + chalk.yellow('│'));
  console.log(chalk.yellow('  │') + '  Only install MCP servers for tools you have already installed     ' + chalk.yellow('│'));
  console.log(chalk.yellow('  │') + '  or plan to install before using the MrZero agents.                ' + chalk.yellow('│'));
  console.log(chalk.yellow('  │') + '                                                                     ' + chalk.yellow('│'));
  console.log(chalk.yellow('  │') + chalk.dim('  Installing an MCP server without its prerequisite tool will      ') + chalk.yellow('│'));
  console.log(chalk.yellow('  │') + chalk.dim('  cause errors when agents try to use it.                          ') + chalk.yellow('│'));
  console.log(chalk.yellow('  └─────────────────────────────────────────────────────────────────────┘'));
  console.log('');

  // Get all available MCP servers with their prerequisite info
  const allServers = getAllMcpServers();
  const choices = allServers.map((server) => {
    const isRecommended = agentMcpServers.includes(server.name);
    const prereq = server.requiresPrerequisite 
      ? chalk.dim(` (requires ${server.requiresPrerequisite})`)
      : '';
    
    return {
      name: server.name,
      message: `${server.displayName}${prereq}${isRecommended ? chalk.green(' [recommended for selected agents]') : ''}`,
      value: server.name,
      hint: server.description,
    };
  });

  const prompt = new MultiSelect({
    name: 'mcpServers',
    message: 'Select MCP servers to install:',
    choices,
    initial: [], // No servers selected by default - user must opt-in
  });

  const selected = await prompt.run();
  return selected;
}

interface ToolSelection {
  dockerTools: string[];
  pythonTools: string[];
  rubyTools: string[];
}

async function selectTools(
  recommendedDockerTools: string[],
  recommendedPythonTools: string[],
  recommendedRubyTools: string[],
  skipDocker: boolean
): Promise<ToolSelection> {
  // Collect all available tools
  const allDockerTools = Object.values(DOCKER_TOOLS);
  const allPythonTools = Object.values(PYTHON_TOOLS);
  const allRubyTools = Object.values(RUBY_TOOLS);

  // If skipping docker, only show Python and Ruby tools
  if (skipDocker && allPythonTools.length === 0 && allRubyTools.length === 0) {
    return { dockerTools: [], pythonTools: [], rubyTools: [] };
  }

  logger.blank();
  logger.header('Tool Selection');
  
  // Show info box
  console.log('');
  console.log(chalk.cyan('  ┌─────────────────────────────────────────────────────────────────────┐'));
  console.log(chalk.cyan('  │') + chalk.bold.cyan('                         Tool Selection                              ') + chalk.cyan('│'));
  console.log(chalk.cyan('  ├─────────────────────────────────────────────────────────────────────┤'));
  console.log(chalk.cyan('  │') + '  Select which security tools you want to install.                   ' + chalk.cyan('│'));
  console.log(chalk.cyan('  │') + '                                                                     ' + chalk.cyan('│'));
  console.log(chalk.cyan('  │') + '  Only selected tools will be:                                       ' + chalk.cyan('│'));
  console.log(chalk.cyan('  │') + '    • Available as CLI commands on your system                       ' + chalk.cyan('│'));
  console.log(chalk.cyan('  │') + '    • Mentioned in the AI agent system prompts                       ' + chalk.cyan('│'));
  console.log(chalk.cyan('  │') + '                                                                     ' + chalk.cyan('│'));
  console.log(chalk.cyan('  │') + chalk.dim('  Tools marked [recommended] are used by your selected agents.       ') + chalk.cyan('│'));
  console.log(chalk.cyan('  └─────────────────────────────────────────────────────────────────────┘'));
  console.log('');

  const selectedDockerTools: string[] = [];
  const selectedPythonTools: string[] = [];
  const selectedRubyTools: string[] = [];

  // Docker tools selection
  if (!skipDocker && allDockerTools.length > 0) {
    const dockerChoices = allDockerTools.map((tool) => {
      const isRecommended = recommendedDockerTools.includes(tool.name);
      return {
        name: tool.name,
        message: `${tool.displayName} - ${tool.description}${isRecommended ? chalk.green(' [recommended]') : ''}`,
        value: tool.name,
      };
    });

    const dockerPrompt = new MultiSelect({
      name: 'dockerTools',
      message: 'Select Docker-wrapped security tools:',
      choices: dockerChoices,
      initial: recommendedDockerTools, // Pre-select recommended tools
    });

    const selected = await dockerPrompt.run();
    selectedDockerTools.push(...selected);
  }

  // Python tools selection
  if (allPythonTools.length > 0) {
    const pythonChoices = allPythonTools.map((tool) => {
      const isRecommended = recommendedPythonTools.includes(tool.name);
      return {
        name: tool.name,
        message: `${tool.displayName} - ${tool.description}${isRecommended ? chalk.green(' [recommended]') : ''}`,
        value: tool.name,
      };
    });

    logger.blank();
    const pythonPrompt = new MultiSelect({
      name: 'pythonTools',
      message: 'Select Python tools (via uv):',
      choices: pythonChoices,
      initial: recommendedPythonTools,
    });

    const selected = await pythonPrompt.run();
    selectedPythonTools.push(...selected);
  }

  // Ruby tools selection
  if (allRubyTools.length > 0) {
    const rubyChoices = allRubyTools.map((tool) => {
      const isRecommended = recommendedRubyTools.includes(tool.name);
      return {
        name: tool.name,
        message: `${tool.displayName} - ${tool.description}${isRecommended ? chalk.green(' [recommended]') : ''}`,
        value: tool.name,
      };
    });

    logger.blank();
    const rubyPrompt = new MultiSelect({
      name: 'rubyTools',
      message: 'Select Ruby tools (via gem):',
      choices: rubyChoices,
      initial: recommendedRubyTools,
    });

    const selected = await rubyPrompt.run();
    selectedRubyTools.push(...selected);
  }

  return {
    dockerTools: selectedDockerTools,
    pythonTools: selectedPythonTools,
    rubyTools: selectedRubyTools,
  };
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

  // Get recommended tools based on selected agents
  const recommendedDockerTools = getUniqueDockerTools(selectedAgents);
  const recommendedPythonTools = getUniquePythonTools(selectedAgents);
  const recommendedRubyTools = getUniqueRubyTools(selectedAgents);
  
  // Let user select which tools to install
  const toolSelection = await selectTools(
    recommendedDockerTools,
    recommendedPythonTools,
    recommendedRubyTools,
    options.skipDocker || false
  );
  
  const dockerTools = toolSelection.dockerTools;
  const pythonTools = toolSelection.pythonTools;
  const rubyTools = toolSelection.rubyTools;
  
  // Get MCP servers recommended for selected agents
  const agentMcpServers = getUniqueMcpServers(selectedAgents);
  
  // Let user select which MCP servers to install
  const mcpServers = await selectMcpServers(agentMcpServers, options.skipMcp || false);

  // Combine all selected tools for template rendering
  const allSelectedTools = [
    ...dockerTools,
    ...pythonTools,
    ...rubyTools,
  ];

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
    await configurePlatform(platform, installedMcpServers, selectedAgentNames, allSelectedTools);
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
