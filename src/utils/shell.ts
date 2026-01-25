import { exec as execCallback, spawn } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(execCallback);

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

export async function exec(
  command: string,
  options: { timeout?: number; cwd?: string } = {}
): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execPromise(command, {
      timeout: options.timeout || 60000,
      cwd: options.cwd,
      maxBuffer: 10 * 1024 * 1024, // 10MB
    });
    return { stdout, stderr, code: 0 };
  } catch (error: any) {
    return {
      stdout: error.stdout || '',
      stderr: error.stderr || error.message,
      code: error.code || 1,
    };
  }
}

export async function commandExists(command: string): Promise<boolean> {
  const result = await exec(`which ${command}`);
  return result.code === 0 && result.stdout.trim().length > 0;
}

export async function runWithOutput(
  command: string,
  args: string[],
  options: { cwd?: string } = {}
): Promise<number> {
  return new Promise((resolve) => {
    const proc = spawn(command, args, {
      stdio: 'inherit',
      cwd: options.cwd,
      shell: true,
    });

    proc.on('close', (code) => {
      resolve(code || 0);
    });

    proc.on('error', () => {
      resolve(1);
    });
  });
}
