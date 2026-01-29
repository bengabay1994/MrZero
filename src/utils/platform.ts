import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

export type Platform = 'linux' | 'darwin' | 'win32' | 'unsupported';

export function getPlatform(): Platform {
  const platform = os.platform();
  if (platform === 'linux' || platform === 'darwin' || platform === 'win32') {
    return platform;
  }
  return 'unsupported';
}

export function isLinux(): boolean {
  return os.platform() === 'linux';
}

export function isMac(): boolean {
  return os.platform() === 'darwin';
}

export function isWindows(): boolean {
  return os.platform() === 'win32';
}

export function getHomeDir(): string {
  return os.homedir();
}

export function getMrZeroDir(): string {
  return path.join(getHomeDir(), '.mrzero');
}

export function getMcpServersDir(): string {
  return path.join(getMrZeroDir(), 'mcp-servers');
}

export function getWrappersDir(): string {
  return path.join(getHomeDir(), '.local', 'bin', 'mrzero-tools');
}

export function getLauncherPath(): string {
  return path.join(getHomeDir(), '.local', 'bin', 'mrzero');
}

export function getLauncherBinaryName(): string {
  const platform = os.platform();  // 'linux', 'darwin', 'win32'
  const arch = os.arch();          // 'x64', 'arm64'

  const osMap: Record<string, string> = {
    'linux': 'linux',
    'darwin': 'darwin',
    'win32': 'windows',
  };

  const archMap: Record<string, string> = {
    'x64': 'amd64',
    'arm64': 'arm64',
  };

  const goos = osMap[platform];
  const goarch = archMap[arch];

  if (!goos || !goarch) {
    throw new Error(`Unsupported platform: ${platform}-${arch}`);
  }

  const ext = platform === 'win32' ? '.exe' : '';
  return `mrzero-${goos}-${goarch}${ext}`;
}

export function getClaudeConfigDir(): string {
  return path.join(getHomeDir(), '.claude');
}

export function getClaudeAgentsDir(): string {
  return path.join(getClaudeConfigDir(), 'agents');
}

export function getOpenCodeConfigDir(): string {
  return path.join(getHomeDir(), '.config', 'opencode');
}

export function getOpenCodeAgentsDir(): string {
  return path.join(getOpenCodeConfigDir(), 'agents');
}

export function getDistroInfo(): { name: string; version: string } | null {
  if (!isLinux()) return null;
  
  try {
    const fs = require('fs');
    const releaseFile = '/etc/os-release';
    if (fs.existsSync(releaseFile)) {
      const content = fs.readFileSync(releaseFile, 'utf-8');
      const nameMatch = content.match(/^NAME="?([^"\n]+)"?/m);
      const versionMatch = content.match(/^VERSION_ID="?([^"\n]+)"?/m);
      return {
        name: nameMatch?.[1] || 'Unknown',
        version: versionMatch?.[1] || 'Unknown',
      };
    }
  } catch {}
  return null;
}

export function getArch(): string {
  return os.arch();
}

export function isArm64(): boolean {
  return os.arch() === 'arm64';
}

export function isX64(): boolean {
  return os.arch() === 'x64';
}

export function isLinuxArm64(): boolean {
  return isLinux() && isArm64();
}

/**
 * Get the current package version from package.json
 */
export function getPackageVersion(): string {
  try {
    // Try to find package.json relative to this file
    const packagePaths = [
      path.join(__dirname, '..', '..', 'package.json'),
      path.join(__dirname, '..', '..', '..', 'package.json'),
    ];
    
    for (const packagePath of packagePaths) {
      if (fs.existsSync(packagePath)) {
        const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
        return pkg.version;
      }
    }
  } catch {}
  
  return 'latest';
}
