import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { exec, commandExists } from '../utils/shell.js';
import { getHomeDir } from '../utils/platform.js';

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
  const result = await exec('python3 --version');
  if (result.code === 0) {
    const match = result.stdout.match(/Python ([\d.]+)/);
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
    const result = await exec('which pwndbg');
    return { name: 'pwndbg', installed: true, method: 'binary', path: result.stdout.trim() };
  }

  // Method 2: Check .gdbinit for pwndbg source line
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

  // Method 3: Run gdb and check if pwndbg banner appears
  try {
    const result = await exec('echo "quit" | gdb -q 2>&1', { timeout: 5000 });
    const output = result.stdout + result.stderr;
    if (output.toLowerCase().includes('pwndbg')) {
      return { name: 'pwndbg', installed: true, method: 'gdb-plugin' };
    }
  } catch {}

  // Method 4: Check common installation paths
  const commonPaths = [
    path.join(getHomeDir(), '.pwndbg', 'gdbinit.py'),
    path.join(getHomeDir(), 'pwndbg', 'gdbinit.py'),
    '/opt/pwndbg/gdbinit.py',
    path.join(getHomeDir(), 'Desktop', 'repos', 'pwndbg', 'gdbinit.py'),
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
    const result = await exec('which ghidraRun');
    return { name: 'ghidra', installed: true, path: result.stdout.trim() };
  }

  // Check common installation paths
  const commonPaths = [
    '/opt/ghidra',
    '/opt/ghidra_*',
    path.join(getHomeDir(), 'ghidra'),
    path.join(getHomeDir(), 'ghidra_*'),
    '/usr/local/ghidra',
    '/usr/share/ghidra',
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
    const result = await exec('msfconsole --version 2>/dev/null || echo ""');
    const match = result.stdout.match(/Framework Version: ([\d.]+)/);
    return { name: 'metasploit', installed: true, version: match?.[1] };
  }

  // Check common paths
  const commonPaths = [
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
  if (await commandExists('idat64')) {
    const result = await exec('which idat64');
    return { name: 'ida-pro', installed: true, method: 'pro', path: result.stdout.trim() };
  }

  // Check common installation paths for IDA Pro specific indicators
  const proPaths = [
    '/opt/idapro',
    '/opt/ida-pro',
    path.join(getHomeDir(), 'idapro'),
    path.join(getHomeDir(), 'ida-pro'),
  ];

  for (const p of proPaths) {
    if (fs.existsSync(p)) {
      // Check if idat64 exists in this directory (Pro indicator)
      const idat64Path = path.join(p, 'idat64');
      if (fs.existsSync(idat64Path)) {
        return { name: 'ida-pro', installed: true, method: 'pro', path: p };
      }
    }
  }

  // Check for generic IDA paths but verify it's Pro version
  const genericPaths = [
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
            const idat64Path = path.join(fullPath, 'idat64');
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
  if (await commandExists('ida64')) {
    const result = await exec('which ida64');
    return { name: 'ida-free', installed: true, path: result.stdout.trim() };
  }

  // Check common installation paths for IDA Free
  const freePaths = [
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

// Check if a Python package is installed
export async function detectPythonPackage(packageName: string): Promise<ToolStatus> {
  const result = await exec(`python3 -c "import ${packageName.replace('-', '_')}" 2>&1`);
  if (result.code === 0) {
    return { name: packageName, installed: true };
  }
  return { name: packageName, installed: false };
}

// Check if a Ruby gem is installed
export async function detectRubyGem(gemName: string): Promise<ToolStatus> {
  const result = await exec(`gem list -i ${gemName}`);
  if (result.code === 0 && result.stdout.includes('true')) {
    return { name: gemName, installed: true };
  }
  return { name: gemName, installed: false };
}

// Check if Docker image exists
export async function detectDockerImage(imageName: string): Promise<boolean> {
  const result = await exec(`docker image inspect ${imageName} 2>/dev/null`);
  return result.code === 0;
}

// Check if CLI wrapper exists in ~/.local/bin
export async function detectWrapper(wrapperName: string): Promise<boolean> {
  const wrapperPath = path.join(getHomeDir(), '.local', 'bin', wrapperName);
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
    return content.includes('mrzero') || content.includes('MRZERO');
  } catch {
    return false;
  }
}

// Check if a native CLI tool is installed (not wrapper, actual tool in PATH)
export async function detectNativeTool(toolName: string): Promise<ToolStatus> {
  const result = await exec(`which ${toolName} 2>/dev/null`);
  if (result.code === 0) {
    const toolPath = result.stdout.trim();
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
  const wrapperInstalled = await detectWrapper(toolName);
  const nativeStatus = await detectNativeTool(toolName);
  
  return {
    name: toolName,
    wrapperInstalled,
    nativeInstalled: nativeStatus.installed,
    nativePath: nativeStatus.installed ? nativeStatus.path : undefined,
  };
}
