import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger.js';
import {
  getClaudeConfigDir,
  getClaudeAgentsDir,
  getOpenCodeConfigDir,
  getOpenCodeAgentsDir,
  getMrZeroDir,
  getHomeDir,
} from '../utils/platform.js';
import { MCP_SERVERS } from '../config/mcp-servers.js';
import { AGENTS } from '../config/agents.js';
import { renderAgentTemplate, agentHasTemplate, RenderContext } from './template-renderer.js';

export type Platform = 'claude-code' | 'opencode';

// Claude Code MCP config format
interface ClaudeMcpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

// OpenCode MCP config format
interface OpenCodeMcpServerConfig {
  type: 'local';
  command: string[];
  enabled: boolean;
  environment?: Record<string, string>;
}

// Get the path to the agents directory in the package
function getPackageAgentsDir(): string {
  // When running from dist, agents are at ../agents relative to dist
  const distAgents = path.join(__dirname, '..', '..', 'agents');
  if (fs.existsSync(distAgents)) {
    return distAgents;
  }
  // When running from source
  const srcAgents = path.join(__dirname, '..', '..', '..', 'agents');
  if (fs.existsSync(srcAgents)) {
    return srcAgents;
  }
  throw new Error('Could not find agents directory');
}

// Get the path to the templates directory in the package
function getPackageTemplatesDir(): string {
  // When running from dist, templates are at ../agents/templates relative to dist
  const distTemplates = path.join(__dirname, '..', '..', 'agents', 'templates');
  if (fs.existsSync(distTemplates)) {
    return distTemplates;
  }
  // When running from source
  const srcTemplates = path.join(__dirname, '..', '..', '..', 'agents', 'templates');
  if (fs.existsSync(srcTemplates)) {
    return srcTemplates;
  }
  throw new Error('Could not find templates directory');
}

function expandMrZeroDir(str: string): string {
  return str.replace(/\$\{MRZERO_DIR\}/g, getMrZeroDir());
}

function buildClaudeMcpConfig(serverName: string): ClaudeMcpServerConfig | null {
  const server = MCP_SERVERS[serverName];
  if (!server) return null;

  const config: ClaudeMcpServerConfig = {
    command: server.command,
  };

  if (server.args) {
    config.args = server.args.map(expandMrZeroDir);
  }

  if (server.env) {
    config.env = server.env;
  }

  return config;
}

function buildOpenCodeMcpConfig(serverName: string): OpenCodeMcpServerConfig | null {
  const server = MCP_SERVERS[serverName];
  if (!server) return null;

  // Build the command array
  const commandArray: string[] = [server.command];
  if (server.args) {
    commandArray.push(...server.args.map(expandMrZeroDir));
  }

  const config: OpenCodeMcpServerConfig = {
    type: 'local',
    command: commandArray,
    enabled: true,
  };

  if (server.env) {
    config.environment = server.env;
  }

  return config;
}

export async function configureClaudeCode(
  mcpServers: string[],
  agents: string[],
  installedTools: string[]
): Promise<void> {
  logger.header('Configuring Claude Code');

  const claudeDir = getClaudeConfigDir();
  const agentsDir = getClaudeAgentsDir();

  // Ensure directories exist
  fs.mkdirSync(claudeDir, { recursive: true });
  fs.mkdirSync(agentsDir, { recursive: true });

  // Install agent files (either from template or static)
  const packageAgentsDir = getPackageAgentsDir();
  const templatesDir = getPackageTemplatesDir();
  
  const renderContext: RenderContext = {
    installedTools,
    installedMcpServers: mcpServers,
  };

  for (const agentName of agents) {
    const agent = AGENTS[agentName];
    if (!agent) continue;

    const destPath = path.join(agentsDir, agent.filename);
    
    // Check if this agent has a template
    if (agentHasTemplate(agentName)) {
      const templatePath = path.join(templatesDir, `${agentName}.template.md`);
      
      if (fs.existsSync(templatePath)) {
        // Read template and render with installed tools
        const templateContent = fs.readFileSync(templatePath, 'utf-8');
        const renderedContent = renderAgentTemplate(agentName, templateContent, renderContext);
        fs.writeFileSync(destPath, renderedContent);
        logger.success(`Installed agent: ${agent.displayName} (customized for installed tools)`);
      } else {
        // Fallback to static file if template not found
        const srcPath = path.join(packageAgentsDir, agent.filename);
        if (fs.existsSync(srcPath)) {
          fs.copyFileSync(srcPath, destPath);
          logger.success(`Installed agent: ${agent.displayName}`);
        } else {
          logger.warning(`Agent file not found: ${agent.filename}`);
        }
      }
    } else {
      // Static agent (no template needed, like MrZeroEnvBuilder)
      const srcPath = path.join(packageAgentsDir, agent.filename);
      if (fs.existsSync(srcPath)) {
        fs.copyFileSync(srcPath, destPath);
        logger.success(`Installed agent: ${agent.displayName}`);
      } else {
        logger.warning(`Agent file not found: ${agent.filename}`);
      }
    }
  }

  // Configure MCP servers in settings.json
  const settingsPath = path.join(claudeDir, 'settings.json');
  let settings: Record<string, any> = {};

  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    } catch {
      logger.warning('Could not parse existing settings.json, creating new one');
    }
  }

  // Initialize mcpServers if not present
  if (!settings.mcpServers) {
    settings.mcpServers = {};
  }

  // Add MCP server configurations
  for (const serverName of mcpServers) {
    const config = buildClaudeMcpConfig(serverName);
    if (config) {
      // Use a clean name for the key
      const keyName = serverName.replace('-mcp', '').replace('mcp-', '');
      settings.mcpServers[keyName] = config;
      logger.success(`Configured MCP server: ${serverName}`);
    }
  }

  // Write settings
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
  logger.success(`Updated ${settingsPath}`);
}

export async function configureOpenCode(
  mcpServers: string[],
  agents: string[],
  installedTools: string[]
): Promise<void> {
  logger.header('Configuring OpenCode');

  const openCodeDir = getOpenCodeConfigDir();
  const agentsDir = getOpenCodeAgentsDir();

  // Ensure directories exist
  fs.mkdirSync(openCodeDir, { recursive: true });
  fs.mkdirSync(agentsDir, { recursive: true });

  // Install agent files (either from template or static)
  const packageAgentsDir = getPackageAgentsDir();
  const templatesDir = getPackageTemplatesDir();
  
  const renderContext: RenderContext = {
    installedTools,
    installedMcpServers: mcpServers,
  };

  for (const agentName of agents) {
    const agent = AGENTS[agentName];
    if (!agent) continue;

    const destPath = path.join(agentsDir, agent.filename);
    
    // Check if this agent has a template
    if (agentHasTemplate(agentName)) {
      const templatePath = path.join(templatesDir, `${agentName}.template.md`);
      
      if (fs.existsSync(templatePath)) {
        // Read template and render with installed tools
        const templateContent = fs.readFileSync(templatePath, 'utf-8');
        const renderedContent = renderAgentTemplate(agentName, templateContent, renderContext);
        fs.writeFileSync(destPath, renderedContent);
        logger.success(`Installed agent: ${agent.displayName} (customized for installed tools)`);
      } else {
        // Fallback to static file if template not found
        const srcPath = path.join(packageAgentsDir, agent.filename);
        if (fs.existsSync(srcPath)) {
          fs.copyFileSync(srcPath, destPath);
          logger.success(`Installed agent: ${agent.displayName}`);
        } else {
          logger.warning(`Agent file not found: ${agent.filename}`);
        }
      }
    } else {
      // Static agent (no template needed, like MrZeroEnvBuilder)
      const srcPath = path.join(packageAgentsDir, agent.filename);
      if (fs.existsSync(srcPath)) {
        fs.copyFileSync(srcPath, destPath);
        logger.success(`Installed agent: ${agent.displayName}`);
      } else {
        logger.warning(`Agent file not found: ${agent.filename}`);
      }
    }
  }

  // Configure MCP servers in opencode.json
  const configPath = path.join(openCodeDir, 'config.json');
  let config: Record<string, any> = {};

  if (fs.existsSync(configPath)) {
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    } catch {
      logger.warning('Could not parse existing config.json, creating new one');
    }
  }

  // Initialize mcp if not present
  if (!config.mcp) {
    config.mcp = {};
  }

  // Add MCP server configurations
  for (const serverName of mcpServers) {
    const serverConfig = buildOpenCodeMcpConfig(serverName);
    if (serverConfig) {
      const keyName = serverName.replace('-mcp', '').replace('mcp-', '');
      config.mcp[keyName] = serverConfig;
      logger.success(`Configured MCP server: ${serverName}`);
    }
  }

  // Write config
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  logger.success(`Updated ${configPath}`);
}

export async function configurePlatform(
  platform: Platform,
  mcpServers: string[],
  agents: string[],
  installedTools: string[]
): Promise<void> {
  switch (platform) {
    case 'claude-code':
      await configureClaudeCode(mcpServers, agents, installedTools);
      break;
    case 'opencode':
      await configureOpenCode(mcpServers, agents, installedTools);
      break;
  }
}

export async function removeAgentsFromPlatform(
  platform: Platform,
  agents: string[]
): Promise<void> {
  const agentsDir =
    platform === 'claude-code' ? getClaudeAgentsDir() : getOpenCodeAgentsDir();

  for (const agentName of agents) {
    const agent = AGENTS[agentName];
    if (!agent) continue;

    const agentPath = path.join(agentsDir, agent.filename);
    if (fs.existsSync(agentPath)) {
      fs.unlinkSync(agentPath);
      logger.success(`Removed agent: ${agent.displayName}`);
    }
  }
}

export async function removeMcpServersFromPlatform(
  platform: Platform,
  mcpServers: string[]
): Promise<void> {
  if (platform === 'claude-code') {
    const settingsPath = path.join(getClaudeConfigDir(), 'settings.json');
    if (fs.existsSync(settingsPath)) {
      try {
        const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
        if (settings.mcpServers) {
          for (const serverName of mcpServers) {
            const keyName = serverName.replace('-mcp', '').replace('mcp-', '');
            delete settings.mcpServers[keyName];
          }
          fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
        }
      } catch {}
    }
  } else if (platform === 'opencode') {
    const configPath = path.join(getOpenCodeConfigDir(), 'config.json');
    if (fs.existsSync(configPath)) {
      try {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        if (config.mcp) {
          for (const serverName of mcpServers) {
            const keyName = serverName.replace('-mcp', '').replace('mcp-', '');
            delete config.mcp[keyName];
          }
          fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        }
      } catch {}
    }
  }
}
