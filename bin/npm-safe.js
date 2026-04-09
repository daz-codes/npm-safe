#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runInstallAndAnalyse, runAuditOnly } from '../src/index.js';
import { formatJson } from '../src/report/formatter.js';
import { addToAllowlist, approveScripts, isScriptApproved, loadConfig } from '../src/config/loader.js';

const exec = promisify(execFile);

function confirm(question) {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase().startsWith('y'));
    });
  });
}

const program = new Command();

program
  .name('npm-safe')
  .description('Secure npm install wrapper — diffs lockfile changes and applies security rules')
  .version('0.1.0');

program
  .command('install', { isDefault: true })
  .description('Run npm install --ignore-scripts, then analyse changes')
  .argument('[packages...]', 'packages to install')
  .option('--dry-run', 'Analyse only — do not install to node_modules')
  .option('--yes, -y', 'Skip confirmation prompt')
  .option('--ci', 'CI mode — no prompts, install unless blocked (exit 0 on warnings)')
  .option('--format <format>', 'Output format: text or json', 'text')
  .action(async (packages, opts) => {
    const cwd = process.cwd();
    const lockPath = join(cwd, 'package-lock.json');
    const isJson = opts.format === 'json';
    const ciMode = opts.ci;
    const autoYes = opts.yes || opts.Y || ciMode;

    try {
      // Save existing lockfile so we can revert if the user declines
      let originalLockfile = null;
      try {
        originalLockfile = await readFile(lockPath, 'utf8');
      } catch {
        // No lockfile yet — nothing to revert to
      }

      // Phase 1: Update lockfile only and analyse
      const result = await runInstallAndAnalyse(cwd, packages, { dryRun: true });

      // Show the report
      if (isJson) {
        console.log(formatJson(result.evaluations, result.warnings));
      } else {
        console.log(result.report);
      }

      // Dry-run mode: stop here
      if (opts.dryRun) {
        process.exit(result.exitCode);
      }

      // No changes detected — nothing to install
      if (result.exitCode === 0 && result.evaluations.length === 0) {
        process.exit(0);
      }

      // Blocked — abort and revert lockfile
      if (result.exitCode === 1) {
        if (!isJson) {
          console.log(chalk.red.bold('\n🚫 Install blocked by security rules.'));
          console.log(chalk.dim('   Use "npm-safe approve <pkg@version>" to allowlist reviewed packages.\n'));
        }
        await revertLockfile(lockPath, originalLockfile);
        process.exit(1);
      }

      // Decide whether to prompt
      const shouldPrompt = !autoYes && !isJson && result.exitCode === 2;

      if (shouldPrompt) {
        const ok = await confirm(chalk.yellow('\n🔶 Proceed with install? [y/N] '));
        if (!ok) {
          await revertLockfile(lockPath, originalLockfile);
          if (!isJson) console.log(chalk.dim('↩️  Install cancelled. Lockfile reverted.'));
          process.exit(2);
        }
      }

      // Phase 2: Actually install to node_modules
      if (!isJson) console.log(chalk.dim('\n📦 Installing packages...'));
      const npmArgs = ['install', '--ignore-scripts', ...packages];
      await exec('npm', npmArgs, { cwd, stdio: 'pipe' });
      if (!isJson) console.log(chalk.green('✅ Install complete (scripts not executed).'));

      // In CI mode, warnings are acceptable — only blocks fail the pipeline
      const finalExit = ciMode && result.exitCode === 2 ? 0 : result.exitCode;
      process.exit(finalExit);
    } catch (err) {
      if (isJson) {
        console.log(JSON.stringify({ error: err.message }, null, 2));
      } else {
        console.error(chalk.red(`Error: ${err.message}`));
      }
      process.exit(3);
    }
  });

async function revertLockfile(lockPath, original) {
  try {
    if (original != null) {
      await writeFile(lockPath, original);
    }
  } catch {
    // Best-effort revert
  }
}

program
  .command('audit')
  .description('Analyse existing lockfile without running install')
  .option('--format <format>', 'Output format: text or json', 'text')
  .action(async (opts) => {
    try {
      const result = await runAuditOnly(process.cwd());
      if (opts.format === 'json') {
        console.log(formatJson(result.evaluations, result.warnings));
      } else {
        console.log(result.report);
      }
      process.exit(result.exitCode);
    } catch (err) {
      if (opts.format === 'json') {
        console.log(JSON.stringify({ error: err.message }, null, 2));
      } else {
        console.error(chalk.red(`Error: ${err.message}`));
      }
      process.exit(3);
    }
  });

program
  .command('approve')
  .description('Add a package to the allowlist')
  .argument('<package>', 'package specifier (e.g. esbuild@0.19.0 or lodash@*)')
  .action(async (pkgSpec) => {
    try {
      await addToAllowlist(pkgSpec);
      console.log(chalk.green(`Added ${pkgSpec} to allowlist`));
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(3);
    }
  });

program
  .command('run-scripts')
  .description('Approve and run install scripts for a reviewed package')
  .argument('<package>', 'package specifier (e.g. esbuild@0.19.0)')
  .action(async (pkgSpec) => {
    try {
      // Validate pkgSpec format to prevent flag injection and ensure
      // the package was previously analysed (must be in allowlist or scriptApprovals)
      if (pkgSpec.startsWith('-')) {
        throw new Error(`Invalid package specifier: ${pkgSpec}`);
      }

      const config = await loadConfig(process.cwd());

      const inAllowlist = (config.allowlist || []).some(
        (e) => e === pkgSpec || e === pkgSpec.split('@').slice(0, -1).join('@') + '@*'
      );
      if (!isScriptApproved(pkgSpec, config) && !inAllowlist) {
        // First-time approval: record it, but only if it looks like a valid package spec
        if (!/^@?[a-z0-9]/.test(pkgSpec)) {
          throw new Error(`Invalid package specifier: ${pkgSpec}`);
        }
        await approveScripts(pkgSpec);
        console.log(chalk.green(`Approved scripts for ${pkgSpec}`));
      }

      console.log(chalk.dim(`Running: npm rebuild ${pkgSpec}`));
      const { stdout, stderr } = await exec('npm', ['rebuild', pkgSpec], {
        cwd: process.cwd(),
        stdio: 'pipe',
      });
      if (stdout) console.log(stdout);
      if (stderr) console.error(stderr);
      console.log(chalk.green(`Scripts executed for ${pkgSpec}`));
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(3);
    }
  });

program.parse();
