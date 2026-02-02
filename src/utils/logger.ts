import chalk from 'chalk';

export const logger = {
  info: (message: string) => console.log(chalk.blue('i') + ' ' + message),
  success: (message: string) => console.log(chalk.green('✓') + ' ' + message),
  warning: (message: string) => console.log(chalk.yellow('!') + ' ' + message),
  error: (message: string) => console.log(chalk.red('✗') + ' ' + message),
  step: (message: string) => console.log(chalk.cyan('→') + ' ' + message),
  
  header: (message: string) => {
    console.log('');
    console.log(chalk.bold.cyan(message));
  },
  
  subheader: (message: string) => {
    console.log(chalk.dim(message));
  },
  
  list: (items: string[]) => {
    items.forEach((item) => console.log('  ' + chalk.dim('•') + ' ' + item));
  },
  
  table: (rows: [string, string][]) => {
    const maxKeyLen = Math.max(...rows.map(([key]) => key.length));
    rows.forEach(([key, value]) => {
      console.log('  ' + chalk.dim(key.padEnd(maxKeyLen)) + '  ' + value);
    });
  },
  
  blank: () => console.log(''),
  
  box: (title: string, content: string[]) => {
    console.log('');
    console.log(chalk.bold.yellow('┌─ ' + title + ' ─'));
    content.forEach((line) => console.log(chalk.yellow('│ ') + line));
    console.log(chalk.yellow('└' + '─'.repeat(title.length + 4)));
  },
};

export function formatStatus(installed: boolean): string {
  return installed ? chalk.green('✓ installed') : chalk.red('✗ not found');
}

export function formatOptional(installed: boolean): string {
  return installed ? chalk.green('✓ installed') : chalk.dim('○ not installed (optional)');
}
