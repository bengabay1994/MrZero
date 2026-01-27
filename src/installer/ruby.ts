import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { exec, runWithOutput } from '../utils/shell.js';
import { logger } from '../utils/logger.js';
import { RUBY_TOOLS } from '../config/tools.js';

/**
 * Get the gem user bin directory dynamically based on the user's Ruby version
 */
async function getGemBinDir(): Promise<string | null> {
  const result = await exec("ruby -e 'puts Gem.user_dir'");
  if (result.code !== 0) {
    return null;
  }
  return path.join(result.stdout.trim(), 'bin');
}

/**
 * Create a wrapper script in ~/.local/bin for a Ruby gem
 * This makes the gem callable from PATH without modifying shell configs
 */
export async function createRubyWrapper(toolName: string): Promise<boolean> {
  const gemBinDir = await getGemBinDir();
  if (!gemBinDir) {
    logger.warning(`Could not determine gem directory, ${toolName} may not be in PATH`);
    return false;
  }

  const gemBinPath = path.join(gemBinDir, toolName);

  // Verify the gem binary exists
  if (!fs.existsSync(gemBinPath)) {
    // Try system gem dir as fallback
    const sysGemResult = await exec('gem environment gemdir');
    if (sysGemResult.code === 0) {
      const sysGemBinPath = path.join(sysGemResult.stdout.trim(), 'bin', toolName);
      if (fs.existsSync(sysGemBinPath)) {
        return createWrapperFile(toolName, sysGemBinPath);
      }
    }
    logger.warning(`Gem binary not found at ${gemBinPath}`);
    return false;
  }

  return createWrapperFile(toolName, gemBinPath);
}

/**
 * Create the actual wrapper file
 */
async function createWrapperFile(toolName: string, gemBinPath: string): Promise<boolean> {
  const wrapperDir = path.join(os.homedir(), '.local', 'bin');
  const wrapperPath = path.join(wrapperDir, toolName);

  // Ensure directory exists
  fs.mkdirSync(wrapperDir, { recursive: true });

  // Write wrapper script
  const wrapperContent = `#!/bin/bash
exec "${gemBinPath}" "$@"
`;

  fs.writeFileSync(wrapperPath, wrapperContent, { mode: 0o755 });

  // Check if ~/.local/bin is in PATH
  const localBin = path.join(os.homedir(), '.local', 'bin');
  const pathDirs = (process.env.PATH || '').split(':');

  if (!pathDirs.includes(localBin)) {
    logger.warning(`~/.local/bin is not in your PATH`);
    logger.info(`Add this to your shell config (~/.bashrc or ~/.zshrc):`);
    logger.info(`  export PATH="$HOME/.local/bin:$PATH"`);
  }

  return true;
}

/**
 * Remove the wrapper script for a Ruby gem
 */
export function removeRubyWrapper(toolName: string): boolean {
  const wrapperPath = path.join(os.homedir(), '.local', 'bin', toolName);
  if (fs.existsSync(wrapperPath)) {
    fs.unlinkSync(wrapperPath);
    return true;
  }
  return false;
}

/**
 * Check if a wrapper exists for a Ruby gem
 */
export function hasRubyWrapper(toolName: string): boolean {
  const wrapperPath = path.join(os.homedir(), '.local', 'bin', toolName);
  return fs.existsSync(wrapperPath);
}

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

  let installed = false;

  if (result.code === 0) {
    installed = true;
  } else {
    // Try with --user-install if permission denied
    if (result.stderr.includes('Permission denied') || result.stderr.includes('permission')) {
      logger.warning('Permission denied, trying with --user-install...');
      const userResult = await exec(`gem install --user-install ${toolName}`);
      if (userResult.code === 0) {
        installed = true;
      }
    }
  }

  if (installed) {
    // Create wrapper script so the tool is callable from PATH
    const wrapperCreated = await createRubyWrapper(toolName);
    if (wrapperCreated) {
      logger.success(`Installed ${tool.displayName}`);
    } else {
      logger.success(`Installed ${tool.displayName} (wrapper not created, may not be in PATH)`);
    }
    return true;
  } else {
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

  // Remove wrapper first
  if (removeRubyWrapper(toolName)) {
    logger.info(`Removed wrapper for ${toolName}`);
  }

  // Uninstall gem
  const result = await exec(`gem uninstall -x ${toolName}`);
  if (result.code === 0) {
    logger.success(`Uninstalled ${tool.displayName}`);
    return true;
  }
  return false;
}
