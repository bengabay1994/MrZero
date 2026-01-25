import { exec, runWithOutput } from '../utils/shell.js';
import { logger } from '../utils/logger.js';
import { RUBY_TOOLS } from '../config/tools.js';

export async function installRubyTool(toolName: string): Promise<boolean> {
  const tool = RUBY_TOOLS[toolName];
  if (!tool) {
    logger.error(`Unknown Ruby tool: ${toolName}`);
    return false;
  }

  logger.step(`Installing ${tool.displayName}...`);

  // Check if Ruby is available
  const rubyCheck = await exec('ruby --version');
  if (rubyCheck.code !== 0) {
    logger.error('Ruby is not installed. Please install Ruby first:');
    logger.info('  sudo apt-get install ruby ruby-dev');
    return false;
  }

  // Check if gem is available
  const gemCheck = await exec('gem --version');
  if (gemCheck.code !== 0) {
    logger.error('gem is not installed. Please install RubyGems first.');
    return false;
  }

  // Install using gem
  const installCmd = tool.installCommand || `gem install ${toolName}`;
  const result = await exec(installCmd);

  if (result.code === 0) {
    logger.success(`Installed ${tool.displayName}`);
    return true;
  } else {
    // Try with sudo if permission denied
    if (result.stderr.includes('Permission denied') || result.stderr.includes('permission')) {
      logger.warning('Permission denied, trying with --user-install...');
      const userResult = await exec(`gem install --user-install ${toolName}`);
      if (userResult.code === 0) {
        logger.success(`Installed ${tool.displayName}`);
        return true;
      }
    }
    logger.error(`Failed to install ${tool.displayName}: ${result.stderr}`);
    return false;
  }
}

export async function installAllRubyTools(tools: string[]): Promise<void> {
  if (tools.length === 0) return;

  logger.header('Installing Ruby tools via gem');

  for (const tool of tools) {
    await installRubyTool(tool);
  }
}

export async function checkRubyTool(toolName: string): Promise<boolean> {
  const tool = RUBY_TOOLS[toolName];
  if (!tool || !tool.checkCommand) {
    return false;
  }

  const result = await exec(tool.checkCommand);
  return result.code === 0;
}

export async function uninstallRubyTool(toolName: string): Promise<boolean> {
  const tool = RUBY_TOOLS[toolName];
  if (!tool) {
    return false;
  }

  logger.step(`Uninstalling ${tool.displayName}...`);

  const result = await exec(`gem uninstall -x ${toolName}`);
  if (result.code === 0) {
    logger.success(`Uninstalled ${tool.displayName}`);
    return true;
  }
  return false;
}
