import { exec, runWithOutput } from '../utils/shell.js';
import { logger } from '../utils/logger.js';
import { PYTHON_TOOLS } from '../config/tools.js';

export async function installPythonTool(toolName: string): Promise<boolean> {
  const tool = PYTHON_TOOLS[toolName];
  if (!tool) {
    logger.error(`Unknown Python tool: ${toolName}`);
    return false;
  }

  logger.step(`Installing ${tool.displayName}...`);

  // First check if uv is available
  const uvCheck = await exec('uv --version');
  if (uvCheck.code !== 0) {
    logger.error('uv is not installed. Please install uv first:');
    logger.info('  curl -LsSf https://astral.sh/uv/install.sh | sh');
    return false;
  }

  // Install using uv
  const installCmd = tool.installCommand || `uv pip install --system ${toolName}`;
  const result = await exec(installCmd);

  if (result.code === 0) {
    logger.success(`Installed ${tool.displayName}`);
    return true;
  } else {
    logger.error(`Failed to install ${tool.displayName}: ${result.stderr}`);
    return false;
  }
}

export async function installAllPythonTools(tools: string[]): Promise<void> {
  if (tools.length === 0) return;

  logger.header('Installing Python tools via uv');

  for (const tool of tools) {
    await installPythonTool(tool);
  }
}

export async function checkPythonTool(toolName: string): Promise<boolean> {
  const tool = PYTHON_TOOLS[toolName];
  if (!tool || !tool.checkCommand) {
    return false;
  }

  const result = await exec(tool.checkCommand);
  return result.code === 0;
}

export async function uninstallPythonTool(toolName: string): Promise<boolean> {
  const tool = PYTHON_TOOLS[toolName];
  if (!tool) {
    return false;
  }

  logger.step(`Uninstalling ${tool.displayName}...`);

  const result = await exec(`uv pip uninstall -y ${toolName}`);
  if (result.code === 0) {
    logger.success(`Uninstalled ${tool.displayName}`);
    return true;
  }
  return false;
}
