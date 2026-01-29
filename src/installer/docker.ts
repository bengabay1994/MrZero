import * as fs from 'fs';
import * as path from 'path';
import { exec, runWithOutput } from '../utils/shell.js';
import { logger } from '../utils/logger.js';
import { getHomeDir, getMrZeroDir, getWrappersDir } from '../utils/platform.js';
import { DOCKER_IMAGE, DOCKER_TOOLS } from '../config/tools.js';

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
docker run --rm -it \\
    -v "$(pwd)":/workspace \\
    -w /workspace \\
    "$MRZERO_IMAGE" \\
    "{{TOOL_COMMAND}} $*"
`;

export async function pullDockerImage(): Promise<boolean> {
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
  
  // Generate wrapper content
  let toolCommand = wrapperName;
  
  // Some tools need special handling
  switch (toolName) {
    case 'joern':
      toolCommand = 'joern';
      break;
    case 'codeql':
      toolCommand = 'codeql';
      break;
    case 'linguist':
      toolCommand = 'github-linguist';
      break;
    default:
      toolCommand = wrapperName;
  }
  
  const wrapperContent = WRAPPER_TEMPLATE
    .replace(/{{TOOL_NAME}}/g, wrapperName)
    .replace(/{{TOOL_COMMAND}}/g, toolCommand);
  
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
