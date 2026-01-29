import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import { logger } from '../utils/logger.js';
import { getLauncherPath, getLauncherBinaryName, getPackageVersion } from '../utils/platform.js';

const LAUNCHER_REPO = 'bengabay1994/MrZero';

/**
 * Download a file from URL, following redirects
 */
function downloadFile(url: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);

    const request = (currentUrl: string, redirectCount: number = 0) => {
      if (redirectCount > 5) {
        reject(new Error('Too many redirects'));
        return;
      }

      const protocol = currentUrl.startsWith('https') ? https : require('http');
      
      protocol.get(currentUrl, (response: any) => {
        // Handle redirects
        if (response.statusCode === 302 || response.statusCode === 301) {
          const redirectUrl = response.headers.location;
          if (redirectUrl) {
            request(redirectUrl, redirectCount + 1);
            return;
          }
        }

        if (response.statusCode !== 200) {
          fs.unlink(dest, () => {});
          reject(new Error(`HTTP ${response.statusCode}: Failed to download`));
          return;
        }

        response.pipe(file);
        file.on('finish', () => {
          file.close();
          resolve();
        });
        file.on('error', (err: Error) => {
          fs.unlink(dest, () => {});
          reject(err);
        });
      }).on('error', (err: Error) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
    };

    request(url);
  });
}

/**
 * Download and install the MrZero launcher binary
 */
export async function downloadLauncher(): Promise<boolean> {
  const binaryName = getLauncherBinaryName();
  const launcherPath = getLauncherPath();
  const launcherDir = path.dirname(launcherPath);
  const version = getPackageVersion();

  logger.step(`Downloading MrZero launcher (${binaryName}, v${version})`);

  // Ensure directory exists
  fs.mkdirSync(launcherDir, { recursive: true });

  // Build download URL for specific version
  const versionTag = version === 'latest' ? 'latest' : `v${version}`;
  const url = `https://github.com/${LAUNCHER_REPO}/releases/download/${versionTag}/${binaryName}`;

  try {
    await downloadFile(url, launcherPath);

    // Make executable (Linux/macOS)
    if (process.platform !== 'win32') {
      fs.chmodSync(launcherPath, 0o755);
    }

    logger.success(`Installed launcher to ${launcherPath}`);
    return true;
  } catch (error) {
    logger.error(`Failed to download launcher: ${error}`);
    logger.blank();
    logger.warning('The launcher could not be installed.');
    logger.warning('Without the launcher, tools installed on your system may take');
    logger.warning('precedence over MrZero\'s containerized tools, which could cause');
    logger.warning('unexpected behavior.');
    logger.blank();
    logger.info('You can still use MrZero tools by manually setting your PATH:');
    logger.info('  export PATH="$HOME/.local/bin/mrzero-tools:$PATH"');
    logger.info('Then run opencode or claude directly.');
    return false;
  }
}

/**
 * Remove the MrZero launcher binary
 */
export async function removeLauncher(): Promise<void> {
  const launcherPath = getLauncherPath();

  if (fs.existsSync(launcherPath)) {
    fs.unlinkSync(launcherPath);
    logger.success('Removed MrZero launcher');
  }
}

/**
 * Check if the launcher is installed
 */
export function isLauncherInstalled(): boolean {
  const launcherPath = getLauncherPath();
  return fs.existsSync(launcherPath);
}
