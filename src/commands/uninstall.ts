import * as fs from 'fs';
import enquirer from 'enquirer';
import { logger } from '../utils/logger.js';
import {
  getMrZeroDir,
  getMcpServersDir,
  getClaudeAgentsDir,
  getOpenCodeAgentsDir,
  getWrappersDir,
} from '../utils/platform.js';
import { removeWrappers, removeDockerImage } from '../installer/docker.js';
import { uninstallMcpServer } from '../installer/mcp.js';
import {
  removeAgentsFromPlatform,
  removeMcpServersFromPlatform,
} from '../installer/platforms.js';
import { DOCKER_TOOLS } from '../config/tools.js';
import { AGENTS } from '../config/agents.js';
import { MCP_SERVERS } from '../config/mcp-servers.js';
import { removeLauncher } from '../installer/launcher.js';

const { Confirm } = enquirer as any;

interface UninstallOptions {
  keepAgents?: boolean;
  keepDocker?: boolean;
  yes?: boolean;
}

export async function uninstallCommand(options: UninstallOptions): Promise<void> {
  logger.header('MrZero Uninstaller');

  if (!options.yes) {
    logger.blank();
    logger.warning('This will remove MrZero tools, MCP servers, and configurations.');
    
    const prompt = new Confirm({
      name: 'confirm',
      message: 'Are you sure you want to uninstall MrZero?',
      initial: false,
    });

    const confirmed = await prompt.run();
    if (!confirmed) {
      logger.info('Uninstall cancelled.');
      process.exit(0);
    }
  }

  logger.blank();

  // Remove launcher binary
  logger.step('Removing MrZero launcher...');
  await removeLauncher();

  // Remove CLI wrappers
  logger.step('Removing CLI wrappers...');
  const dockerTools = Object.keys(DOCKER_TOOLS);
  await removeWrappers(dockerTools);

  // Remove wrappers directory if empty
  const wrappersDir = getWrappersDir();
  if (fs.existsSync(wrappersDir)) {
    const files = fs.readdirSync(wrappersDir);
    if (files.length === 0) {
      fs.rmdirSync(wrappersDir);
      logger.success(`Removed empty directory ${wrappersDir}`);
    }
  }

  // Remove MCP servers
  logger.step('Removing MCP servers...');
  for (const serverName of Object.keys(MCP_SERVERS)) {
    await uninstallMcpServer(serverName);
  }

  // Remove agent files (unless --keep-agents)
  if (!options.keepAgents) {
    logger.step('Removing agent files...');
    const agentNames = Object.keys(AGENTS);
    await removeAgentsFromPlatform('claude-code', agentNames);
    await removeAgentsFromPlatform('opencode', agentNames);
  }

  // Remove MCP server configs from platforms
  logger.step('Removing MCP configurations from platforms...');
  const mcpServerNames = Object.keys(MCP_SERVERS);
  await removeMcpServersFromPlatform('claude-code', mcpServerNames);
  await removeMcpServersFromPlatform('opencode', mcpServerNames);

  // Remove Docker image (unless --keep-docker)
  if (!options.keepDocker) {
    logger.step('Removing Docker image...');
    await removeDockerImage();
  }

  // Remove MrZero directory
  const mrZeroDir = getMrZeroDir();
  if (fs.existsSync(mrZeroDir)) {
    logger.step('Removing MrZero directory...');
    fs.rmSync(mrZeroDir, { recursive: true, force: true });
    logger.success(`Removed ${mrZeroDir}`);
  }

  logger.blank();
  logger.header('Uninstall Complete');
  logger.info('MrZero has been removed from your system.');

  if (options.keepAgents) {
    logger.info('Agent files were kept in Claude Code and OpenCode configurations.');
  }

  if (options.keepDocker) {
    logger.info('Docker image was kept.');
  }
}
