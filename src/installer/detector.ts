import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { exec, commandExists } from '../utils/shell.js';
import { getHomeDir, getWrappersDir, isWindows } from '../utils/platform.js';

export interface SystemInfo {
  os: string;
  osVersion: string;
  arch: string;
  docker: { installed: boolean; version?: string };
  python: { installed: boolean; version?: string };
  uv: { installed: boolean; version?: string };
  ruby: { installed: boolean; version?: string };
  git: { installed: boolean; version?: string };
}

export interface ToolStatus {
  name: string;
  installed: boolean;
  version?: string;
  path?: string;
  method?: string;
}

export async function detectSystemInfo(): Promise<SystemInfo> {
  const [docker, python, uv, ruby, git] = await Promise.all([
    detectDocker(),
    detectPython(),
    detectUv(),
    detectRuby(),
    detectGit(),
  ]);

  const distro = await detectLinuxDistro();

  return {
    os: os.platform(),
    osVersion: distro || os.release(),
    arch: os.arch(),
    docker,
    python,
    uv,
    ruby,
    git,
  };
}

async function detectDocker(): Promise<{ installed: boolean; version?: string }> {
  const result = await exec('docker --version');
  if (result.code === 0) {
    const match = result.stdout.match(/Docker version ([\d.]+)/);
    return { installed: true, version: match?.[1] };
  }
  return { installed: false };
}

async function detectPython(): Promise<{ installed: boolean; version?: string }> {
  // On Windows, Python is typically just 'python', not 'python3'
  const pythonCmd = isWindows() ? 'python --version' : 'python3 --version';
  const result = await exec(pythonCmd);
  if (result.code === 0) {
    const match = result.stdout.match(/Python ([\d.]+)/);
    return { installed: true, version: match?.[1] };
  }
  // Fallback: try the other variant
  const fallbackCmd = isWindows() ? 'python3 --version' : 'python --version';
  const fallbackResult = await exec(fallbackCmd);
  if (fallbackResult.code === 0) {
    const match = fallbackResult.stdout.match(/Python ([\d.]+)/);
    return { installed: true, version: match?.[1] };
  }
  return { installed: false };
}

async function detectUv(): Promise<{ installed: boolean; version?: string }> {
  const result = await exec('uv --version');
  if (result.code === 0) {
    const match = result.stdout.match(/uv ([\d.]+)/);
    return { installed: true, version: match?.[1] };
  }
  return { installed: false };
}

async function detectRuby(): Promise<{ installed: boolean; version?: string }> {
  const result = await exec('ruby --version');
  if (result.code === 0) {
    const match = result.stdout.match(/ruby ([\d.]+)/);
    return { installed: true, version: match?.[1] };
  }
  return { installed: false };
}

async function detectGit(): Promise<{ installed: boolean; version?: string }> {
  const result = await exec('git --version');
  if (result.code === 0) {
    const match = result.stdout.match(/git version ([\d.]+)/);
    return { installed: true, version: match?.[1] };
  }
  return { installed: false };
}

async function detectLinuxDistro(): Promise<string | null> {
  if (isWindows()) {
    // Return Windows version info
    return `Windows ${os.release()}`;
  }
  
  try {
    const releaseFile = '/etc/os-release';
    if (fs.existsSync(releaseFile)) {
      const content = fs.readFileSync(releaseFile, 'utf-8');
      const nameMatch = content.match(/^PRETTY_NAME="?([^"\n]+)"?/m);
      return nameMatch?.[1] || null;
    }
  } catch {}
  return null;
}

// GDB detection
export async function detectGdb(): Promise<ToolStatus> {
  const result = await exec('gdb --version');
  if (result.code === 0) {
    const match = result.stdout.match(/GNU gdb[^\d]*([\d.]+)/);
    return { name: 'gdb', installed: true, version: match?.[1] };
  }
  return { name: 'gdb', installed: false };
}

// pwndbg detection - multiple methods
export async function detectPwndbg(): Promise<ToolStatus> {
  // Method 1: Check for standalone pwndbg binary
  if (await commandExists('pwndbg')) {
    const whichCmd = isWindows() ? 'where pwndbg' : 'which pwndbg';
    const result = await exec(whichCmd);
    return { name: 'pwndbg', installed: true, method: 'binary', path: result.stdout.trim().split('\n')[0] };
  }

  // Method 2: Check .gdbinit for pwndbg source line (not applicable on Windows typically)
  if (!isWindows()) {
    const gdbinit = path.join(getHomeDir(), '.gdbinit');
    if (fs.existsSync(gdbinit)) {
      const content = fs.readFileSync(gdbinit, 'utf-8');
      const match = content.match(/source\s+(.+pwndbg[^\s]*gdbinit\.py)/i);
      if (match) {
        return { name: 'pwndbg', installed: true, method: 'gdbinit-source', path: match[1] };
      }
      if (content.toLowerCase().includes('pwndbg')) {
        return { name: 'pwndbg', installed: true, method: 'gdbinit-reference' };
      }
    }
  }

  // Method 3: Run gdb and check if pwndbg banner appears (Unix only)
  if (!isWindows()) {
    try {
      const result = await exec('echo "quit" | gdb -q 2>&1', { timeout: 5000 });
      const output = result.stdout + result.stderr;
      if (output.toLowerCase().includes('pwndbg')) {
        return { name: 'pwndbg', installed: true, method: 'gdb-plugin' };
      }
    } catch {}
  }

  // Method 4: Check common installation paths
  const commonPaths = [
    path.join(getHomeDir(), '.pwndbg', 'gdbinit.py'),
    path.join(getHomeDir(), 'pwndbg', 'gdbinit.py'),
    ...(isWindows() ? [] : [
      '/opt/pwndbg/gdbinit.py',
      path.join(getHomeDir(), 'Desktop', 'repos', 'pwndbg', 'gdbinit.py'),
    ]),
    path.join(getHomeDir(), 'tools', 'pwndbg', 'gdbinit.py'),
  ];

  for (const p of commonPaths) {
    if (fs.existsSync(p)) {
      return { name: 'pwndbg', installed: true, method: 'common-path', path: p };
    }
  }

  return { name: 'pwndbg', installed: false };
}

// Ghidra detection
export async function detectGhidra(): Promise<ToolStatus> {
  // Check for ghidraRun in PATH
  if (await commandExists('ghidraRun')) {
    const whichCmd = isWindows() ? 'where ghidraRun' : 'which ghidraRun';
    const result = await exec(whichCmd);
    return { name: 'ghidra', installed: true, path: result.stdout.trim().split('\n')[0] };
  }

  // Check common installation paths
  const commonPaths = [
    ...(isWindows() ? [
      // Windows common paths
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Ghidra'),
      path.join(getHomeDir(), 'ghidra'),
      path.join(getHomeDir(), 'ghidra_*'),
    ] : [
      // Unix common paths
      '/opt/ghidra',
      '/opt/ghidra_*',
      path.join(getHomeDir(), 'ghidra'),
      path.join(getHomeDir(), 'ghidra_*'),
      '/usr/local/ghidra',
      '/usr/share/ghidra',
    ]),
  ];

  for (const pattern of commonPaths) {
    if (pattern.includes('*')) {
      // Glob pattern
      const dir = path.dirname(pattern);
      const base = path.basename(pattern).replace('*', '');
      if (fs.existsSync(dir)) {
        const entries = fs.readdirSync(dir);
        const match = entries.find((e) => e.startsWith(base));
        if (match) {
          return { name: 'ghidra', installed: true, path: path.join(dir, match) };
        }
      }
    } else if (fs.existsSync(pattern)) {
      return { name: 'ghidra', installed: true, path: pattern };
    }
  }

  return { name: 'ghidra', installed: false };
}

// Metasploit detection
export async function detectMetasploit(): Promise<ToolStatus> {
  if (await commandExists('msfconsole')) {
    const versionCmd = isWindows()
      ? 'msfconsole --version 2>nul'
      : 'msfconsole --version 2>/dev/null || echo ""';
    const result = await exec(versionCmd);
    const match = result.stdout.match(/Framework Version: ([\d.]+)/);
    return { name: 'metasploit', installed: true, version: match?.[1] };
  }

  // Check common paths
  const commonPaths = isWindows() ? [
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Metasploit'),
    path.join(getHomeDir(), 'metasploit-framework'),
  ] : [
    '/opt/metasploit-framework',
    '/usr/share/metasploit-framework',
    path.join(getHomeDir(), 'metasploit-framework'),
  ];

  for (const p of commonPaths) {
    if (fs.existsSync(p)) {
      return { name: 'metasploit', installed: true, path: p };
    }
  }

  return { name: 'metasploit', installed: false };
}

// IDA Pro detection - distinguishes between Pro and Free versions
export async function detectIdaPro(): Promise<ToolStatus> {
  // IDA Pro has idat64 (text mode batch processing) which IDA Free does NOT have
  // This is the key differentiator between Pro and Free
  const idatBin = isWindows() ? 'idat64.exe' : 'idat64';
  if (await commandExists(isWindows() ? 'idat64.exe' : 'idat64')) {
    const whichCmd = isWindows() ? `where ${idatBin}` : `which ${idatBin}`;
    const result = await exec(whichCmd);
    return { name: 'ida-pro', installed: true, method: 'pro', path: result.stdout.trim().split('\n')[0] };
  }

  // Check common installation paths for IDA Pro specific indicators
  const proPaths = isWindows() ? [
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'IDA Pro'),
    path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'IDA Pro'),
    path.join(getHomeDir(), 'idapro'),
    path.join(getHomeDir(), 'ida-pro'),
  ] : [
    '/opt/idapro',
    '/opt/ida-pro',
    path.join(getHomeDir(), 'idapro'),
    path.join(getHomeDir(), 'ida-pro'),
  ];

  for (const p of proPaths) {
    if (fs.existsSync(p)) {
      // Check if idat64 exists in this directory (Pro indicator)
      const idat64Bin = isWindows() ? 'idat64.exe' : 'idat64';
      const idat64Path = path.join(p, idat64Bin);
      if (fs.existsSync(idat64Path)) {
        return { name: 'ida-pro', installed: true, method: 'pro', path: p };
      }
    }
  }

  // Check for generic IDA paths but verify it's Pro version
  const genericPaths = isWindows() ? [
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'IDA*'),
    path.join(getHomeDir(), 'ida*'),
  ] : [
    '/opt/ida*',
    path.join(getHomeDir(), 'ida*'),
  ];

  for (const pattern of genericPaths) {
    const dir = path.dirname(pattern);
    const base = path.basename(pattern).replace('*', '');
    if (fs.existsSync(dir)) {
      try {
        const entries = fs.readdirSync(dir);
        for (const entry of entries) {
          if (entry.toLowerCase().startsWith(base.toLowerCase())) {
            const fullPath = path.join(dir, entry);
            // Check if idat64 exists (Pro indicator)
            const idat64Bin = isWindows() ? 'idat64.exe' : 'idat64';
            const idat64Path = path.join(fullPath, idat64Bin);
            if (fs.existsSync(idat64Path)) {
              return { name: 'ida-pro', installed: true, method: 'pro', path: fullPath };
            }
          }
        }
      } catch {}
    }
  }

  // IDA Pro not found (IDA Free may be installed but we don't detect that here)
  return { name: 'ida-pro', installed: false };
}

// IDA Free detection (separate from Pro)
export async function detectIdaFree(): Promise<ToolStatus> {
  // Check for ida64 binary (present in both Free and Pro, but we check this after Pro detection fails)
  const ida64Bin = isWindows() ? 'ida64.exe' : 'ida64';
  if (await commandExists(ida64Bin)) {
    const whichCmd = isWindows() ? `where ${ida64Bin}` : `which ${ida64Bin}`;
    const result = await exec(whichCmd);
    return { name: 'ida-free', installed: true, path: result.stdout.trim().split('\n')[0] };
  }

  // Check common installation paths for IDA Free
  const freePaths = isWindows() ? [
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'IDA Free*'),
    path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'IDA Free*'),
    path.join(getHomeDir(), 'idafree*'),
    path.join(getHomeDir(), 'ida-free*'),
  ] : [
    '/opt/idafree*',
    '/opt/ida-free*',
    path.join(getHomeDir(), 'idafree*'),
    path.join(getHomeDir(), 'ida-free*'),
  ];

  for (const pattern of freePaths) {
    const dir = path.dirname(pattern);
    const base = path.basename(pattern).replace('*', '');
    if (fs.existsSync(dir)) {
      try {
        const entries = fs.readdirSync(dir);
        const match = entries.find((e) => e.toLowerCase().startsWith(base.toLowerCase()));
        if (match) {
          return { name: 'ida-free', installed: true, path: path.join(dir, match) };
        }
      } catch {}
    }
  }

  return { name: 'ida-free', installed: false };
}

// Check if a Python package is installed (via uv tool or system)
export async function detectPythonPackage(packageName: string): Promise<ToolStatus> {
  // First check if the CLI tool exists (for uv tool installs)
  const cliCommands: Record<string, string> = {
    'pwn': 'pwn version',
    'pwntools': 'pwn version',
    'ropper': 'ropper --version',
  };
  
  const cliCheck = cliCommands[packageName];
  if (cliCheck) {
    const cliResult = await exec(`${cliCheck} 2>&1`);
    if (cliResult.code === 0) {
      return { name: packageName, installed: true };
    }
  }
  
  // Fallback to Python import check
  const pythonCmd = isWindows() ? 'python' : 'python3';
  const result = await exec(`${pythonCmd} -c "import ${packageName.replace('-', '_')}" 2>&1`);
  if (result.code === 0) {
    return { name: packageName, installed: true };
  }
  return { name: packageName, installed: false };
}

// Check if a Ruby gem is installed and callable
export async function detectRubyGem(gemName: string): Promise<ToolStatus & { callable: boolean }> {
  // Check if gem is installed
  const result = await exec(`gem list -i ${gemName}`);
  const isInstalled = result.code === 0 && result.stdout.includes('true');

  if (!isInstalled) {
    return { name: gemName, installed: false, callable: false };
  }

  // Check if callable via PATH (wrapper exists and works)
  const callableCmd = isWindows() ? `where ${gemName}` : `command -v ${gemName}`;
  const callableResult = await exec(callableCmd);
  const isCallable = callableResult.code === 0;

  return {
    name: gemName,
    installed: true,
    callable: isCallable,
    path: isCallable ? callableResult.stdout.trim().split('\n')[0] : undefined,
  };
}

// Check if Docker image exists
export async function detectDockerImage(imageName: string): Promise<boolean> {
  const nullDev = isWindows() ? '2>nul' : '2>/dev/null';
  const result = await exec(`docker image inspect ${imageName} ${nullDev}`);
  return result.code === 0;
}

// Check if CLI wrapper exists in the wrappers directory
export async function detectWrapper(wrapperName: string): Promise<boolean> {
  const wrappersDir = getWrappersDir();
  // On Windows, wrappers are .cmd files
  const wrapperExt = isWindows() ? '.cmd' : '';
  const wrapperPath = path.join(wrappersDir, `${wrapperName}${wrapperExt}`);
  if (!fs.existsSync(wrapperPath)) {
    return false;
  }
  
  // Check if it's actually our MrZero wrapper (contains our Docker image reference)
  try {
    const stats = fs.lstatSync(wrapperPath);
    
    // If it's a symlink, it's not our wrapper
    if (stats.isSymbolicLink()) {
      return false;
    }
    
    // Read the file and check if it contains our Docker image marker
    const content = fs.readFileSync(wrapperPath, 'utf-8');
    return content.includes('mrzero') || content.includes('MRZERO') || content.includes('MrZero');
  } catch {
    return false;
  }
}

// Check if a native CLI tool is installed (not wrapper, actual tool in PATH)
export async function detectNativeTool(toolName: string): Promise<ToolStatus> {
  const whichCmd = isWindows() ? `where ${toolName} 2>nul` : `which ${toolName} 2>/dev/null`;
  const result = await exec(whichCmd);
  if (result.code === 0) {
    const toolPath = result.stdout.trim().split('\n')[0];
    return { 
      name: toolName, 
      installed: true, 
      path: toolPath,
      method: 'native'
    };
  }
  return { name: toolName, installed: false };
}

// Comprehensive tool detection - checks both wrapper and native
export interface DockerToolStatus {
  name: string;
  wrapperInstalled: boolean;
  nativeInstalled: boolean;
  nativePath?: string;
}

export async function detectDockerTool(toolName: string): Promise<DockerToolStatus> {
  // Import tool config to get the correct wrapper name
  const { DOCKER_TOOLS } = await import('../config/tools.js');
  const tool = DOCKER_TOOLS[toolName];
  const wrapperName = tool?.wrapperName || toolName;
  
  const wrapperInstalled = await detectWrapper(wrapperName);
  const nativeStatus = await detectNativeTool(wrapperName);
  
  return {
    name: toolName,
    wrapperInstalled,
    nativeInstalled: nativeStatus.installed,
    nativePath: nativeStatus.installed ? nativeStatus.path : undefined,
  };
}
