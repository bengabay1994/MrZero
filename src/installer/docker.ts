import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { exec, runWithOutput } from '../utils/shell.js';
import { logger } from '../utils/logger.js';
import { getHomeDir, getMrZeroDir, getWrappersDir } from '../utils/platform.js';
import { DOCKER_IMAGE, DOCKER_TOOLS } from '../config/tools.js';

// ESM doesn't have __dirname, so we create it
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WRAPPER_TEMPLATE = `#!/bin/bash
# MrZero wrapper for {{TOOL_NAME}}
# Transparently runs {{TOOL_NAME}} in Docker container

MRZERO_IMAGE="${DOCKER_IMAGE}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker first." >&2
    exit 1
fi

# Run the tool in container with current directory mounted
# Note: We don't use -t (TTY) as these tools are run non-interactively by AI agents
# Note: --entrypoint "" overrides any ENTRYPOINT in the image for direct command execution
# Note: --network host uses host networking for proper DNS resolution and internet access
# Note: PYTHONIOENCODING=utf-8 fixes encoding issues with some Python-based tools
docker run --rm \\
    --network host \\
    --entrypoint "" \\
    -e PYTHONIOENCODING=utf-8 \\
    -v "$(pwd)":/workspace \\
    -w /workspace \\
    "$MRZERO_IMAGE" \\
    {{TOOL_COMMAND}} "$@"
`;

// Special wrapper for linguist which needs git safe.directory config
const LINGUIST_WRAPPER_TEMPLATE = `#!/bin/bash
# MrZero wrapper for linguist
# Transparently runs github-linguist in Docker container

MRZERO_IMAGE="${DOCKER_IMAGE}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker first." >&2
    exit 1
fi

# Run linguist in container with current directory mounted
# Note: We configure git safe.directory to allow linguist to analyze mounted repos
# Note: --network host uses host networking for proper DNS resolution
docker run --rm \\
    --network host \\
    --entrypoint "" \\
    -e PYTHONIOENCODING=utf-8 \\
    -v "$(pwd)":/workspace \\
    -w /workspace \\
    "$MRZERO_IMAGE" \\
    bash -c 'git config --global --add safe.directory /workspace 2>/dev/null; github-linguist "$@"' _ "$@"
`;

/**
 * Check if Docker daemon is running
 */
export async function isDockerRunning(): Promise<boolean> {
  const result = await exec('docker info');
  return result.code === 0;
}

export async function pullDockerImage(): Promise<boolean> {
  // First check if Docker daemon is running
  if (!await isDockerRunning()) {
    logger.error('Docker daemon is not running.');
    return false;
  }

  logger.step(`Pulling Docker image: ${DOCKER_IMAGE}`);
  
  const code = await runWithOutput('docker', ['pull', DOCKER_IMAGE]);
  
  if (code === 0) {
    logger.success(`Docker image pulled successfully`);
    return true;
  } else {
    logger.warning(`Failed to pull image, will try to build locally`);
    return false;
  }
}

export async function buildDockerImage(): Promise<boolean> {
  const dockerfilePath = path.join(__dirname, '..', '..', 'docker', 'Dockerfile');
  
  // Check if Dockerfile exists (when running from source)
  if (!fs.existsSync(dockerfilePath)) {
    // Try to find it in the npm package location
    const npmDockerfile = path.join(__dirname, '..', '..', '..', 'docker', 'Dockerfile');
    if (!fs.existsSync(npmDockerfile)) {
      logger.error('Dockerfile not found. Cannot build image.');
      return false;
    }
  }
  
  logger.step(`Building Docker image: ${DOCKER_IMAGE}`);
  
  const buildContext = path.dirname(dockerfilePath);
  const code = await runWithOutput('docker', [
    'build',
    '-t', DOCKER_IMAGE,
    '-f', dockerfilePath,
    buildContext,
  ]);
  
  if (code === 0) {
    logger.success(`Docker image built successfully`);
    return true;
  } else {
    logger.error(`Failed to build Docker image`);
    return false;
  }
}

export async function ensureDockerImage(): Promise<boolean> {
  // First try to pull the image
  const pulled = await pullDockerImage();
  if (pulled) return true;
  
  // If pull fails, try to build locally
  return await buildDockerImage();
}

export async function createWrapperScript(toolName: string): Promise<boolean> {
  const tool = DOCKER_TOOLS[toolName];
  if (!tool) {
    logger.error(`Unknown tool: ${toolName}`);
    return false;
  }
  
  const wrappersDir = getWrappersDir();
  const wrapperName = tool.wrapperName || toolName;
  const wrapperPath = path.join(wrappersDir, wrapperName);
  
  // Ensure wrappers directory exists
  fs.mkdirSync(wrappersDir, { recursive: true });
  
  let wrapperContent: string;
  
  // Linguist needs special handling for git safe.directory
  if (toolName === 'linguist') {
    wrapperContent = LINGUIST_WRAPPER_TEMPLATE;
  } else {
    // Generate wrapper content for other tools
    let toolCommand = wrapperName;
    
    // Some tools need special command names
    switch (toolName) {
      case 'joern':
        toolCommand = 'joern';
        break;
      case 'codeql':
        toolCommand = 'codeql';
        break;
      default:
        toolCommand = wrapperName;
    }
    
    wrapperContent = WRAPPER_TEMPLATE
      .replace(/{{TOOL_NAME}}/g, wrapperName)
      .replace(/{{TOOL_COMMAND}}/g, toolCommand);
  }
  
  try {
    fs.writeFileSync(wrapperPath, wrapperContent, { mode: 0o755 });
    logger.success(`Created wrapper: ${wrapperPath}`);
    return true;
  } catch (error) {
    logger.error(`Failed to create wrapper for ${wrapperName}: ${error}`);
    return false;
  }
}

export async function createAllWrappers(tools: string[]): Promise<void> {
  logger.header('Installing CLI wrappers');
  
  const wrappersDir = getWrappersDir();
  logger.info(`Wrappers directory: ${wrappersDir}`);
  
  for (const toolName of tools) {
    await createWrapperScript(toolName);
  }
  
  // Check if wrappers dir is in PATH
  const pathEnv = process.env.PATH || '';
  if (!pathEnv.includes(wrappersDir)) {
    logger.blank();
    logger.info(`Note: Tools installed to ${wrappersDir}`);
    logger.info(`Use the MrZero launcher to ensure correct PATH:`);
    logger.info(`  mrzero opencode`);
    logger.info(`  mrzero claude`);
  }
}

export async function removeWrappers(tools: string[]): Promise<void> {
  const wrappersDir = getWrappersDir();
  
  for (const tool of tools) {
    const wrapperPath = path.join(wrappersDir, tool);
    if (fs.existsSync(wrapperPath)) {
      try {
        fs.unlinkSync(wrapperPath);
        logger.success(`Removed wrapper: ${tool}`);
      } catch (error) {
        logger.warning(`Failed to remove wrapper: ${tool}`);
      }
    }
  }
}

export async function removeDockerImage(): Promise<boolean> {
  const result = await exec(`docker rmi ${DOCKER_IMAGE}`);
  if (result.code === 0) {
    logger.success(`Removed Docker image: ${DOCKER_IMAGE}`);
    return true;
  }
  return false;
}
