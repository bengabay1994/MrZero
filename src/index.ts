#!/usr/bin/env node

import { Command } from 'commander';
import { installCommand } from './commands/install.js';
import { checkCommand } from './commands/check.js';
import { uninstallCommand } from './commands/uninstall.js';

const program = new Command();

program
  .name('mrzero')
  .description('AI-powered security research agents for vulnerability hunting and exploit development')
  .version('1.0.0');

program
  .command('install')
  .description('Install MrZero agents and tools')
  .option('-a, --agent <agents...>', 'Specific agents to install tools for')
  .option('-p, --platform <platforms...>', 'Target platforms (claude-code, opencode)')
  .option('--skip-docker', 'Skip Docker image pull/build')
  .option('--skip-mcp', 'Skip MCP server installation')
  .option('-y, --yes', 'Skip confirmation prompts')
  .action(installCommand);

program
  .command('check')
  .description('Check installation status of MrZero tools')
  .option('-v, --verbose', 'Show detailed information')
  .action(checkCommand);

program
  .command('uninstall')
  .description('Uninstall MrZero tools and configurations')
  .option('--keep-agents', 'Keep agent files in platform configs')
  .option('--keep-docker', 'Keep Docker image')
  .option('-y, --yes', 'Skip confirmation prompts')
  .action(uninstallCommand);

program.parse();
